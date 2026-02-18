/*
 * Sentinel DDoS Proxy - Userspace Loader & Manager
 * 
 * This program:
 * 1. Loads the kernel module
 * 2. Manages communication with the kernel proxy
 * 3. Handles decisions from the decision engine
 * 4. Monitors and reports statistics
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <time.h>
#include <stdint.h>
#include <getopt.h>

#include "kernel_api.h"

/* ============================================================================
 * CONFIGURATION & CONSTANTS
 * ============================================================================ */

#define SENTINEL_MODULE_NAME "sentinel_proxy"
#define SENTINEL_INSMOD_PATH "/sbin/insmod"
#define SENTINEL_RMMOD_PATH "/sbin/rmmod"

#define MAX_PENDING_DECISIONS 10000
#define STATS_UPDATE_INTERVAL 5  /* seconds */
#define DECISION_QUEUE_SIZE 1024

/* Program state */
static volatile int running = 1;
static volatile int verbose = 0;
static volatile int daemonize = 0;
static int device_fd = -1;

/* ============================================================================
 * LOGGING
 * ============================================================================ */

static void log_message(int level, const char *format, ...)
{
	va_list args;
	va_start(args, format);

	if (daemonize) {
		vsyslog(level, format, args);
	} else {
		const char *level_str;
		switch (level) {
		case LOG_ERR:
			level_str = "ERROR";
			break;
		case LOG_WARNING:
			level_str = "WARN";
			break;
		case LOG_INFO:
			level_str = "INFO";
			break;
		case LOG_DEBUG:
			level_str = "DEBUG";
			break;
		default:
			level_str = "LOG";
		}
		fprintf(stderr, "[%s] ", level_str);
		vfprintf(stderr, format, args);
		fprintf(stderr, "\n");
	}

	va_end(args);
}

/* ============================================================================
 * SIGNAL HANDLING
 * ============================================================================ */

static void signal_handler(int sig)
{
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		log_message(LOG_INFO, "Received signal %d, shutting down...", sig);
		running = 0;
		break;
	case SIGHUP:
		log_message(LOG_INFO, "Received SIGHUP, reloading configuration...");
		/* TODO: Implement configuration reload */
		break;
	}
}

static void setup_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	/* Ignore SIGPIPE */
	signal(SIGPIPE, SIG_IGN);
}

/* ============================================================================
 * KERNEL MODULE MANAGEMENT
 * ============================================================================ */

/*
 * Check if kernel module is loaded
 */
static int is_module_loaded(const char *module_name)
{
	FILE *fp;
	char line[256];
	int found = 0;

	fp = fopen("/proc/modules", "r");
	if (!fp) {
		log_message(LOG_ERR, "Failed to open /proc/modules: %s", strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, module_name, strlen(module_name)) == 0) {
			found = 1;
			break;
		}
	}

	fclose(fp);
	return found;
}

/*
 * Load kernel module with insmod
 */
static int load_module(const char *module_path)
{
	pid_t pid;
	int status;

	log_message(LOG_INFO, "Loading kernel module from: %s", module_path);

	if (access(module_path, F_OK) != 0) {
		log_message(LOG_ERR, "Module file not found: %s", module_path);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		log_message(LOG_ERR, "Failed to fork for insmod: %s", strerror(errno));
		return -1;
	}

	if (pid == 0) {
		/* Child process - execute insmod */
		execlp(SENTINEL_INSMOD_PATH, SENTINEL_INSMOD_PATH, module_path, NULL);
		perror("execlp insmod failed");
		exit(1);
	}

	/* Parent process - wait for child */
	if (waitpid(pid, &status, 0) < 0) {
		log_message(LOG_ERR, "waitpid failed: %s", strerror(errno));
		return -1;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		log_message(LOG_INFO, "Module loaded successfully");
		return 0;
	}

	log_message(LOG_ERR, "Failed to load module (exit code: %d)", WEXITSTATUS(status));
	return -1;
}

/*
 * Unload kernel module
 */
static int unload_module(void)
{
	pid_t pid;
	int status;

	log_message(LOG_INFO, "Unloading kernel module...");

	pid = fork();
	if (pid < 0) {
		log_message(LOG_ERR, "Failed to fork for rmmod: %s", strerror(errno));
		return -1;
	}

	if (pid == 0) {
		/* Child process - execute rmmod */
		execlp(SENTINEL_RMMOD_PATH, SENTINEL_RMMOD_PATH, SENTINEL_MODULE_NAME, NULL);
		perror("execlp rmmod failed");
		exit(1);
	}

	/* Parent process - wait for child */
	if (waitpid(pid, &status, 0) < 0) {
		log_message(LOG_ERR, "waitpid failed: %s", strerror(errno));
		return -1;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		log_message(LOG_INFO, "Module unloaded successfully");
		return 0;
	}

	log_message(LOG_ERR, "Failed to unload module (exit code: %d)", WEXITSTATUS(status));
	return -1;
}

/* ============================================================================
 * DEVICE FILE OPERATIONS
 * ============================================================================ */

/*
 * Open device file for communication with kernel module
 */
static int open_device(void)
{
	device_fd = open(SENTINEL_DEVICE_PATH, O_RDWR);
	if (device_fd < 0) {
		log_message(LOG_ERR, "Failed to open %s: %s", SENTINEL_DEVICE_PATH, strerror(errno));
		return -1;
	}

	log_message(LOG_INFO, "Device file opened: %s", SENTINEL_DEVICE_PATH);
	return 0;
}

/*
 * Close device file
 */
static void close_device(void)
{
	if (device_fd >= 0) {
		close(device_fd);
		device_fd = -1;
	}
}

/*
 * Enable packet filtering in kernel module
 */
static int enable_filtering(int enable)
{
	if (device_fd < 0) {
		log_message(LOG_ERR, "Device not open");
		return -1;
	}

	if (ioctl(device_fd, SENTINEL_IOCTL_ENABLE_FILTERING, &enable) < 0) {
		log_message(LOG_ERR, "IOCTL ENABLE_FILTERING failed: %s", strerror(errno));
		return -1;
	}

	log_message(LOG_INFO, "Filtering %s via IOCTL", enable ? "enabled" : "disabled");
	return 0;
}

/*
 * Set filter mode
 */
static int set_filter_mode(int mode)
{
	if (device_fd < 0) {
		log_message(LOG_ERR, "Device not open");
		return -1;
	}

	if (ioctl(device_fd, SENTINEL_IOCTL_SET_FILTER_MODE, &mode) < 0) {
		log_message(LOG_ERR, "IOCTL SET_FILTER_MODE failed: %s", strerror(errno));
		return -1;
	}

	const char *mode_str;
	switch (mode) {
	case SENTINEL_MODE_DISABLED:
		mode_str = "DISABLED";
		break;
	case SENTINEL_MODE_LEARN:
		mode_str = "LEARN";
		break;
	case SENTINEL_MODE_DETECT:
		mode_str = "DETECT";
		break;
	case SENTINEL_MODE_PROTECT:
		mode_str = "PROTECT";
		break;
	case SENTINEL_MODE_QUARANTINE:
		mode_str = "QUARANTINE";
		break;
	default:
		mode_str = "UNKNOWN";
	}

	log_message(LOG_INFO, "Filter mode set to: %s", mode_str);
	return 0;
}

/*
 * Get module statistics
 */
static int get_statistics(struct sentinel_module_stats *stats)
{
	if (device_fd < 0) {
		log_message(LOG_ERR, "Device not open");
		return -1;
	}

	if (ioctl(device_fd, SENTINEL_IOCTL_GET_STATS, stats) < 0) {
		log_message(LOG_ERR, "IOCTL GET_STATS failed: %s", strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * Reset statistics
 */
static int reset_statistics(void)
{
	if (device_fd < 0) {
		log_message(LOG_ERR, "Device not open");
		return -1;
	}

	if (ioctl(device_fd, SENTINEL_IOCTL_RESET_STATS, NULL) < 0) {
		log_message(LOG_ERR, "IOCTL RESET_STATS failed: %s", strerror(errno));
		return -1;
	}

	log_message(LOG_INFO, "Statistics reset");
	return 0;
}

/* ============================================================================
 * STATISTICS & MONITORING
 * ============================================================================ */

static void print_statistics(const struct sentinel_module_stats *stats)
{
	time_t now = time(NULL);
	struct tm *tm_info = localtime(&now);
	char time_str[32];

	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

	printf("\n");
	printf("=== Sentinel DDoS Proxy Statistics [%s] ===\n", time_str);
	printf("Packets Processed:    %llu\n", (unsigned long long)stats->packets_processed);
	printf("  Allowed:            %llu\n", (unsigned long long)stats->packets_allowed);
	printf("  Dropped:            %llu\n", (unsigned long long)stats->packets_dropped);
	printf("  Redirected:         %llu\n", (unsigned long long)stats->packets_redirected);
	printf("  Rate Limited:       %llu\n", (unsigned long long)stats->packets_rate_limited);
	printf("  Quarantined:        %llu\n", (unsigned long long)stats->packets_quarantined);
	printf("Active Flows:         %u\n", stats->active_flows);
	printf("Active Rules:         %u\n", stats->active_rules);
	printf("Errors:               %llu\n", (unsigned long long)stats->errors);
	printf("============================================\n\n");
}

/* ============================================================================
 * MAIN PROGRAM
 * ============================================================================ */

static void print_usage(const char *prog_name)
{
	printf("Usage: %s [OPTIONS]\n\n", prog_name);
	printf("Options:\n");
	printf("  -m, --module PATH      Path to kernel module (default: ./sentinel_proxy.ko)\n");
	printf("  -d, --daemon           Run as daemon\n");
	printf("  -v, --verbose          Enable verbose logging\n");
	printf("  -c, --command CMD      Execute command: load/unload/status/enable/disable/reset-stats\n");
	printf("  -f, --filter-mode MODE Set filter mode: 0=disabled, 1=learn, 2=detect, 3=protect, 4=quarantine\n");
	printf("  -h, --help             Show this help message\n");
	printf("\n");
	printf("Examples:\n");
	printf("  Load module:           %s -c load -m ./sentinel_proxy.ko\n", prog_name);
	printf("  Enable filtering:      %s -c enable\n", prog_name);
	printf("  Set protect mode:      %s -f 3\n", prog_name);
	printf("  Get statistics:        %s -c status\n", prog_name);
	printf("  Run as daemon:         %s -d\n", prog_name);
}

int main(int argc, char *argv[])
{
	const char *module_path = "./sentinel_proxy.ko";
	const char *command = NULL;
	int filter_mode_arg = -1;
	int opt;
	struct option long_opts[] = {
		{"module", required_argument, 0, 'm'},
		{"daemon", no_argument, 0, 'd'},
		{"verbose", no_argument, 0, 'v'},
		{"command", required_argument, 0, 'c'},
		{"filter-mode", required_argument, 0, 'f'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	/* Parse command-line arguments */
	while ((opt = getopt_long(argc, argv, "m:dvc:f:h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'm':
			module_path = optarg;
			break;
		case 'd':
			daemonize = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'c':
			command = optarg;
			break;
		case 'f':
			filter_mode_arg = atoi(optarg);
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	/* Initialize logging */
	if (daemonize) {
		openlog("sentinel-proxy", LOG_PID, LOG_DAEMON);
	}

	log_message(LOG_INFO, "Sentinel DDoS Proxy Loader v1.0.0 starting");

	setup_signals();

	/* Handle specific commands */
	if (command) {
		if (strcmp(command, "load") == 0) {
			if (is_module_loaded(SENTINEL_MODULE_NAME)) {
				log_message(LOG_WARNING, "Module already loaded");
				return 0;
			}
			return load_module(module_path);
		}

		if (strcmp(command, "unload") == 0) {
			if (!is_module_loaded(SENTINEL_MODULE_NAME)) {
				log_message(LOG_WARNING, "Module not loaded");
				return 0;
			}
			return unload_module();
		}

		if (strcmp(command, "status") == 0) {
			if (open_device() < 0)
				return 1;

			struct sentinel_module_stats stats;
			if (get_statistics(&stats) == 0) {
				print_statistics(&stats);
				close_device();
				return 0;
			}
			close_device();
			return 1;
		}

		if (strcmp(command, "enable") == 0) {
			if (open_device() < 0)
				return 1;
			int ret = enable_filtering(1);
			close_device();
			return ret;
		}

		if (strcmp(command, "disable") == 0) {
			if (open_device() < 0)
				return 1;
			int ret = enable_filtering(0);
			close_device();
			return ret;
		}

		if (strcmp(command, "reset-stats") == 0) {
			if (open_device() < 0)
				return 1;
			int ret = reset_statistics();
			close_device();
			return ret;
		}

		log_message(LOG_ERR, "Unknown command: %s", command);
		return 1;
	}

	/* Set filter mode if specified */
	if (filter_mode_arg >= 0) {
		if (open_device() < 0)
			return 1;
		set_filter_mode(filter_mode_arg);
	}

	/* Load module if not already loaded */
	if (!is_module_loaded(SENTINEL_MODULE_NAME)) {
		if (load_module(module_path) < 0) {
			log_message(LOG_ERR, "Failed to load kernel module");
			return 1;
		}
	}

	/* Open device file */
	if (open_device() < 0) {
		log_message(LOG_ERR, "Failed to open device file");
		return 1;
	}

	/* Daemonize if requested */
	if (daemonize) {
		if (daemon(0, 0) < 0) {
			log_message(LOG_ERR, "Failed to daemonize: %s", strerror(errno));
			close_device();
			return 1;
		}
		log_message(LOG_INFO, "Running as daemon (PID: %d)", getpid());
	}

	log_message(LOG_INFO, "Sentinel DDoS Proxy Loader ready");

	/* Main loop */
	time_t last_stats_time = time(NULL);
	while (running) {
		time_t now = time(NULL);

		/* Print statistics periodically */
		if ((now - last_stats_time) >= STATS_UPDATE_INTERVAL) {
			struct sentinel_module_stats stats;
			if (get_statistics(&stats) == 0) {
				if (!daemonize)
					print_statistics(&stats);
				else
					log_message(LOG_INFO, 
						   "Packets: %llu (allowed: %llu, dropped: %llu, errors: %llu)",
						   (unsigned long long)stats.packets_processed,
						   (unsigned long long)stats.packets_allowed,
						   (unsigned long long)stats.packets_dropped,
						   (unsigned long long)stats.errors);
			}
			last_stats_time = now;
		}

		sleep(1);
	}

	/* Cleanup */
	close_device();
	log_message(LOG_INFO, "Sentinel DDoS Proxy Loader shutting down");

	return 0;
}
