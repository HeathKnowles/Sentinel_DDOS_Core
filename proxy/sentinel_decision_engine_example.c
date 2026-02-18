/*
 * Example: Sentinel DDoS Core - Decision Engine Integration
 * 
 * This example shows how to integrate the kernel proxy with your
 * decision engine (featureextractor, ML models, etc.)
 * 
 * Usage:
 *   gcc -o sentinel_decision_engine sentinel_decision_engine_example.c
 *   ./sentinel_decision_engine
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <time.h>

#include "kernel_api.h"

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

#define DEVICE_PATH SENTINEL_DEVICE_PATH
#define STATS_UPDATE_INTERVAL 10  /* seconds */

/* Global state */
static volatile int running = 1;
static int device_fd = -1;

/* Simple statistics */
struct {
    unsigned long packets_read;
    unsigned long decisions_made;
    unsigned long packets_dropped;
    unsigned long packets_allowed;
} app_stats = {0};

/* ============================================================================
 * SIGNAL HANDLING
 * ============================================================================ */

static void signal_handler(int sig)
{
    printf("\nShutting down...\n");
    running = 0;
}

/* ============================================================================
 * SIMPLE DECISION ENGINE
 * ============================================================================ */

/*
 * This is a simplified decision engine.
 * Replace with your actual ML models, anomaly detection, etc.
 */
static enum sentinel_verdict
analyze_packet(const struct sentinel_packet_metadata *packet)
{
    /* Example 1: Block high port ranges */
    if (packet->dst_port > 10000) {
        return SENTINEL_VERDICT_ALLOW;  /* Allow by default */
    }

    /* Example 2: Block SSH brute force (detect high frequency) */
    if (packet->dst_port == htons(22) && packet->protocol == IPPROTO_TCP) {
        /* In real implementation, track connection attempts per IP */
        return SENTINEL_VERDICT_ALLOW;  /* Allow for now */
    }

    /* Example 3: Block suspicious ICMP patterns */
    if (packet->protocol == IPPROTO_ICMP) {
        if (packet->payload_len > 512) {
            printf("[DETECTION] Large ICMP packet from %u.%u.%u.%u "
                   "(size: %u, may be ping of death)\n",
                   NIPQUAD(packet->src_ip), packet->payload_len);
            return SENTINEL_VERDICT_DROP;
        }
    }

    /* Example 4: Drop packets with malicious payloads */
    if (packet->payload_len > 0) {
        /* Check for known attack signatures */
        /* This is where you'd integrate with featureextractor */
        
        /* For demo: check for simple pattern */
        if (packet->payload[0] == 0xFF && packet->payload[1] == 0xFF) {
            printf("[DETECTION] Suspicious payload pattern detected from %u.%u.%u.%u\n",
                   NIPQUAD(packet->src_ip));
            return SENTINEL_VERDICT_DROP;
        }
    }

    /* Default: allow packet */
    return SENTINEL_VERDICT_ALLOW;
}

/* ============================================================================
 * IP ADDRESS FORMATTING
 * ============================================================================ */

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define NIPQUAD_FMT "%u.%u.%u.%u"

/* ============================================================================
 * PACKET PROCESSING LOOP
 * ============================================================================ */

static void print_packet_info(const struct sentinel_packet_metadata *pkt)
{
    const char *direction = (pkt->direction == SENTINEL_DIRECTION_INBOUND) ?
                            "INBOUND" : "OUTBOUND";
    const char *protocol = "UNKNOWN";

    switch (pkt->protocol) {
    case IPPROTO_TCP:
        protocol = "TCP";
        break;
    case IPPROTO_UDP:
        protocol = "UDP";
        break;
    case IPPROTO_ICMP:
        protocol = "ICMP";
        break;
    }

    printf("[%s] %-7s " NIPQUAD_FMT ":%u -> " NIPQUAD_FMT ":%u "
           "(ID: %u, TTL: %u, Len: %u)\n",
           direction, protocol,
           NIPQUAD(pkt->src_ip), ntohs(pkt->src_port),
           NIPQUAD(pkt->dst_ip), ntohs(pkt->dst_port),
           pkt->packet_id, pkt->ttl, pkt->payload_len);
}

static int process_packets(void)
{
    struct sentinel_packet_metadata metadata;
    struct sentinel_packet_decision decision;
    ssize_t n;
    enum sentinel_verdict verdict;
    time_t last_stats_time = time(NULL);

    printf("Opening device: %s\n", DEVICE_PATH);
    device_fd = open(DEVICE_PATH, O_RDWR);
    if (device_fd < 0) {
        perror("Failed to open device");
        return -1;
    }
    printf("Device opened successfully\n\n");

    printf("Starting packet processing loop (Ctrl+C to stop)...\n");
    printf("=====================================\n\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    while (running) {
        time_t now = time(NULL);

        /* Read packet metadata from kernel module */
        n = read(device_fd, &metadata, sizeof(metadata));

        if (n == sizeof(metadata)) {
            /* Packet received */
            app_stats.packets_read++;

            /* Print packet info */
            print_packet_info(&metadata);

            /* Analyze with decision engine */
            verdict = analyze_packet(&metadata);

            /* Create decision packet */
            memset(&decision, 0, sizeof(decision));
            decision.packet_id = metadata.packet_id;
            decision.verdict = verdict;

            /* For rate limiting demo */
            if (verdict == SENTINEL_VERDICT_RATE_LIMIT) {
                decision.rate_limit_pps = 100;  /* 100 pps limit */
            }

            /* Send decision back to kernel */
            if (write(device_fd, &decision, sizeof(decision)) != sizeof(decision)) {
                perror("Failed to write decision");
            } else {
                app_stats.decisions_made++;

                /* Track decision stats */
                switch (verdict) {
                case SENTINEL_VERDICT_ALLOW:
                    app_stats.packets_allowed++;
                    printf("  -> ALLOW\n");
                    break;
                case SENTINEL_VERDICT_DROP:
                    app_stats.packets_dropped++;
                    printf("  -> DROP\n");
                    break;
                case SENTINEL_VERDICT_REDIRECT:
                    printf("  -> REDIRECT\n");
                    break;
                case SENTINEL_VERDICT_RATE_LIMIT:
                    printf("  -> RATE_LIMIT (100 pps)\n");
                    break;
                case SENTINEL_VERDICT_QUARANTINE:
                    printf("  -> QUARANTINE\n");
                    break;
                }
            }

            printf("\n");

        } else if (n < 0) {
            /* Error reading */
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("Error reading from device");
                break;
            }
        }

        /* Print statistics periodically */
        if ((now - last_stats_time) >= STATS_UPDATE_INTERVAL) {
            printf("\n");
            printf("====== Application Statistics ======\n");
            printf("Packets read:       %lu\n", app_stats.packets_read);
            printf("Decisions made:     %lu\n", app_stats.decisions_made);
            printf("  Allowed:          %lu\n", app_stats.packets_allowed);
            printf("  Dropped:          %lu\n", app_stats.packets_dropped);
            printf("====================================\n\n");

            /* Also get kernel module statistics */
            struct sentinel_module_stats kernel_stats;
            if (ioctl(device_fd, SENTINEL_IOCTL_GET_STATS, &kernel_stats) == 0) {
                printf("===== Kernel Module Statistics =====\n");
                printf("Packets processed:  %llu\n", (unsigned long long)kernel_stats.packets_processed);
                printf("  Allowed:          %llu\n", (unsigned long long)kernel_stats.packets_allowed);
                printf("  Dropped:          %llu\n", (unsigned long long)kernel_stats.packets_dropped);
                printf("Active flows:       %u\n", kernel_stats.active_flows);
                printf("Errors:             %llu\n", (unsigned long long)kernel_stats.errors);
                printf("====================================\n\n");
            }

            last_stats_time = now;
        }

        sleep(1);  /* Small delay to prevent busy-waiting */
    }

    return 0;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

int main(int argc, char *argv[])
{
    printf("Sentinel DDoS Core - Decision Engine Example v1.0.0\n");
    printf("====================================================\n\n");

    printf("This example demonstrates integration with the kernel proxy.\n");
    printf("Make sure:\n");
    printf("  1. Kernel module is loaded: lsmod | grep sentinel_proxy\n");
    printf("  2. Device exists: ls /dev/sentinel_proxy\n");
    printf("  3. Run as root: sudo ./sentinel_decision_engine_example\n\n");

    /* Check if device exists */
    if (access(DEVICE_PATH, F_OK) != 0) {
        fprintf(stderr, "Error: %s does not exist\n", DEVICE_PATH);
        fprintf(stderr, "Load the kernel module first:\n");
        fprintf(stderr, "  sudo insmod sentinel_proxy.ko\n");
        return 1;
    }

    /* Process packets */
    if (process_packets() < 0) {
        return 1;
    }

    /* Cleanup */
    if (device_fd >= 0) {
        close(device_fd);
    }

    printf("\nShutdown complete. Final statistics:\n");
    printf("  Packets read:      %lu\n", app_stats.packets_read);
    printf("  Decisions made:    %lu\n", app_stats.decisions_made);
    printf("  Packets dropped:   %lu\n", app_stats.packets_dropped);
    printf("  Packets allowed:   %lu\n", app_stats.packets_allowed);

    return 0;
}

/* ============================================================================
 * INTEGRATION GUIDE
 * ============================================================================ 
 *
 * To integrate with your actual decision engine:
 *
 * 1. FEATURE EXTRACTION:
 *    - Call featureextractor functions with packet metadata
 *    - Extract relevant features (packet size, rate, patterns, etc.)
 *
 * 2. DECISION MAKING:
 *    - Feed features to ML models
 *    - Apply anomaly detection algorithms
 *    - Generate confidence scores
 *
 * 3. VERDICT SELECTION:
 *    - If high confidence threat -> SENTINEL_VERDICT_DROP
 *    - If suspicious behavior -> SENTINEL_VERDICT_RATE_LIMIT
 *    - If from blacklisted IP -> SENTINEL_VERDICT_QUARANTINE
 *    - Otherwise -> SENTINEL_VERDICT_ALLOW
 *
 * 4. FEEDBACK:
 *    - Send decision back to kernel module
 *    - Update feedback system with results
 *    - Retrain models with new data
 *
 * Example enhanced analyze_packet():
 *
 *   static enum sentinel_verdict
 *   analyze_packet(const struct sentinel_packet_metadata *packet)
 *   {
 *       // Extract features
 *       struct feature_vector features = featureextractor_extract(packet);
 *
 *       // Get ML predictions
 *       struct prediction pred = ml_model_predict(&features);
 *
 *       // Make decision based on prediction
 *       if (pred.threat_score > 0.9) {
 *           return SENTINEL_VERDICT_DROP;
 *       } else if (pred.threat_score > 0.7) {
 *           return SENTINEL_VERDICT_RATE_LIMIT;
 *       }
 *
 *       // Send feedback
 *       feedback_report_decision(&packet->src_ip, SENTINEL_VERDICT_ALLOW);
 *
 *       return SENTINEL_VERDICT_ALLOW;
 *   }
 *
 * ========================================================================== */
