/*
 * Sentinel DDoS Core - Pipeline Daemon
 *
 * Reads packets from /dev/sentinel_proxy, pushes them through:
 *
 *   proxy device  -->  feature extractor  -->  decision engine  -->  SDN controller
 *                                                    |
 *                                               verdict back
 *                                              to kernel module
 *
 * This is the main event loop that ties every component together.
 *
 * Build:
 *   make -C featureextractor
 *   make -C decisionengine
 *   make -C sdncontrolplane
 *   make              (builds this binary: sentinel_pipeline)
 *
 * Usage:
 *   sudo ./sentinel_pipeline [options]
 *
 * Options:
 *   -d, --daemon           Daemonise
 *   -c, --controller URL   Ryu REST URL  (default http://127.0.0.1:8080)
 *   -n, --dpid DPID        Default switch dpid (default 1)
 *   -v, --verbose          Verbose logging
 *   -h, --help             This message
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <poll.h>

/* project headers */
#include "core/sentinel_types.h"
#include "proxy/kernel_api.h"
#include "featureextractor/feature_extractor.h"
#include "decisionengine/decision_engine.h"
#include "sdncontrolplane/sdn_controller.h"
#include "feedback/feedback.h"
#include "websocket/websocket_server.h"

/* ============================================================================
 * GLOBALS
 * ============================================================================ */

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_dump_stats = 0;
static volatile sig_atomic_t g_reset_baselines = 0;
static int g_verbose = 0;
static int g_filter_mode = SENTINEL_MODE_PROTECT;

static void sig_handler(int sig)
{
    if (sig == SIGUSR1)
        g_dump_stats = 1;
    else if (sig == SIGUSR2)
        g_reset_baselines = 1;
    else
        g_running = 0;
}

/* ============================================================================
 * LOGGING
 * ============================================================================ */

static void logmsg(const char *level, const char *fmt, ...)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);

    fprintf(stderr, "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] [%s] ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec,
            ts.tv_nsec / 1000000, level);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

#define LOG_INFO(...)  logmsg("INFO",  __VA_ARGS__)
#define LOG_WARN(...)  logmsg("WARN",  __VA_ARGS__)
#define LOG_ERROR(...) logmsg("ERROR", __VA_ARGS__)
#define LOG_DEBUG(...) do { if (g_verbose) logmsg("DEBUG", __VA_ARGS__); } while (0)

/* ============================================================================
 * ATTACK TYPE -> STRING
 * ============================================================================ */

static const char *attack_str(sentinel_attack_type_t t)
{
    switch (t) {
    case SENTINEL_ATTACK_NONE:      return "NONE";
    case SENTINEL_ATTACK_SYN_FLOOD: return "SYN_FLOOD";
    case SENTINEL_ATTACK_UDP_FLOOD: return "UDP_FLOOD";
    case SENTINEL_ATTACK_ICMP_FLOOD:return "ICMP_FLOOD";
    case SENTINEL_ATTACK_DNS_AMP:   return "DNS_AMP";
    case SENTINEL_ATTACK_NTP_AMP:   return "NTP_AMP";
    case SENTINEL_ATTACK_SLOWLORIS: return "SLOWLORIS";
    case SENTINEL_ATTACK_PORT_SCAN: return "PORT_SCAN";
    case SENTINEL_ATTACK_LAND:      return "LAND";
    case SENTINEL_ATTACK_SMURF:     return "SMURF";
    default:                        return "UNKNOWN";
    }
}

static const char *verdict_str(sentinel_verdict_e v)
{
    switch (v) {
    case VERDICT_ALLOW:      return "ALLOW";
    case VERDICT_DROP:       return "DROP";
    case VERDICT_RATE_LIMIT: return "RATE_LIMIT";
    case VERDICT_REDIRECT:   return "REDIRECT";
    case VERDICT_QUARANTINE: return "QUARANTINE";
    default:                 return "???";
    }
}

/* ============================================================================
 * CONVERT KERNEL METADATA -> FE PACKET
 * ============================================================================ */

static void metadata_to_fe_packet(const struct sentinel_packet_metadata *meta,
                                  fe_packet_t *pkt)
{
    memset(pkt, 0, sizeof(*pkt));
    pkt->packet_id    = meta->packet_id;
    pkt->src_ip       = meta->src_ip;
    pkt->dst_ip       = meta->dst_ip;
    pkt->src_port     = meta->src_port;
    pkt->dst_port     = meta->dst_port;
    pkt->protocol     = meta->protocol;
    pkt->direction    = meta->direction;
    pkt->payload_len  = meta->payload_len;
    pkt->ttl          = meta->ttl;
    pkt->timestamp_ns = meta->timestamp;
    pkt->payload      = meta->payload;

    /* Extract TCP flags from payload buffer if TCP.
     * The kernel copies transport header + data into meta->payload.
     * TCP header byte 13 contains the flags (FIN,SYN,RST,PSH,ACK,URG). */
    pkt->tcp_flags = 0;
    if (meta->protocol == SENTINEL_PROTO_TCP && meta->payload_len >= 14) {
        pkt->tcp_flags = meta->payload[13];
    }
}

/* ============================================================================
 * SEND VERDICT BACK TO KERNEL
 * ============================================================================ */

static int send_verdict(int dev_fd, uint32_t packet_id,
                        const sentinel_threat_assessment_t *a)
{
    struct sentinel_packet_decision dec;
    memset(&dec, 0, sizeof(dec));
    dec.packet_id = packet_id;

    switch (a->verdict) {
    case VERDICT_ALLOW:
        dec.verdict = SENTINEL_VERDICT_ALLOW;
        break;
    case VERDICT_DROP:
    case VERDICT_QUARANTINE:
        dec.verdict = SENTINEL_VERDICT_DROP;
        break;
    case VERDICT_RATE_LIMIT:
        dec.verdict = SENTINEL_VERDICT_RATE_LIMIT;
        dec.rate_limit_pps = a->rate_limit_pps;
        break;
    case VERDICT_REDIRECT:
        dec.verdict = SENTINEL_VERDICT_REDIRECT;
        break;
    }

    if (a->verdict == VERDICT_QUARANTINE)
        dec.quarantine_duration = a->quarantine_sec;

    ssize_t n = write(dev_fd, &dec, sizeof(dec));
    if (n < 0 && errno != EAGAIN) {
        LOG_ERROR("write verdict: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* ============================================================================
 * PIPELINE STATS
 * ============================================================================ */

typedef struct {
    uint64_t packets_processed;
    uint64_t verdicts_allow;
    uint64_t verdicts_drop;
    uint64_t verdicts_rate_limit;
    uint64_t verdicts_quarantine;
    uint64_t sdn_rules_pushed;
    uint64_t sdn_rules_failed;
    time_t   start_time;
} pipeline_stats_t;

static void print_stats(const pipeline_stats_t *s, int dev_fd,
                        de_context_t *de, sdn_context_t *sdn,
                        fb_context_t *fb)
{
    time_t now = time(NULL);
    double uptime = difftime(now, s->start_time);

    LOG_INFO("=== Pipeline Statistics (uptime %.0fs) ===", uptime);
    LOG_INFO("  Packets processed : %lu", (unsigned long)s->packets_processed);
    LOG_INFO("  Verdicts: ALLOW=%lu DROP=%lu RATE_LIMIT=%lu QUARANTINE=%lu",
             (unsigned long)s->verdicts_allow, (unsigned long)s->verdicts_drop,
             (unsigned long)s->verdicts_rate_limit,
             (unsigned long)s->verdicts_quarantine);
    LOG_INFO("  Baselines tracked : %u", de_baseline_count(de));
    LOG_INFO("  SDN rules pushed  : %lu (failed: %lu)",
             (unsigned long)sdn_rules_pushed(sdn),
             (unsigned long)sdn_rules_failed(sdn));

    /* Query kernel module statistics */
    struct sentinel_module_stats kstats;
    if (ioctl(dev_fd, SENTINEL_IOCTL_GET_STATS, &kstats) == 0) {
        LOG_INFO("  Kernel: processed=%llu allowed=%llu dropped=%llu "
                 "rate_limited=%llu quarantined=%llu errors=%llu",
                 (unsigned long long)kstats.packets_processed,
                 (unsigned long long)kstats.packets_allowed,
                 (unsigned long long)kstats.packets_dropped,
                 (unsigned long long)kstats.packets_rate_limited,
                 (unsigned long long)kstats.packets_quarantined,
                 (unsigned long long)kstats.errors);
    }

    /* Feedback metrics */
    if (fb) {
        fb_metrics_t m;
        if (fb_evaluate(fb, &m) == 0 && m.total_records > 0) {
            LOG_INFO("  Feedback: records=%lu precision=%.3f recall=%.3f F1=%.3f",
                     (unsigned long)m.total_records,
                     m.precision, m.recall, m.f1_score);
        }
    }
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "  -d, --daemon           Daemonise\n"
        "  -m, --mode MODE        Filter mode: learn/detect/protect (default protect)\n"
        "  -c, --controller URL   Ryu REST URL (default http://127.0.0.1:8080)\n"
        "  -n, --dpid DPID        Default switch dpid (default 1)\n"
        "  -w, --websocket PORT   WebSocket port for frontend (default 8765, 0=disable)\n"
        "  -v, --verbose          Verbose logging\n"
        "  -h, --help             This message\n",
        prog);
}

int main(int argc, char **argv)
{
    int daemonise = 0;
    sdn_config_t sdn_cfg = SDN_CONFIG_DEFAULT;
    ws_config_t  ws_cfg = WS_CONFIG_DEFAULT;

    static struct option long_opts[] = {
        { "daemon",     no_argument,       NULL, 'd' },
        { "mode",       required_argument, NULL, 'm' },
        { "controller", required_argument, NULL, 'c' },
        { "dpid",       required_argument, NULL, 'n' },
        { "websocket",  required_argument, NULL, 'w' },
        { "verbose",    no_argument,       NULL, 'v' },
        { "help",       no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "dm:c:n:w:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'd': daemonise = 1; break;
        case 'm':
            if (strcmp(optarg, "learn") == 0)
                g_filter_mode = SENTINEL_MODE_LEARN;
            else if (strcmp(optarg, "detect") == 0)
                g_filter_mode = SENTINEL_MODE_DETECT;
            else if (strcmp(optarg, "protect") == 0)
                g_filter_mode = SENTINEL_MODE_PROTECT;
            else {
                fprintf(stderr, "Unknown mode: %s (use learn/detect/protect)\n",
                        optarg);
                return 1;
            }
            break;
        case 'c': snprintf(sdn_cfg.controller_url, sizeof(sdn_cfg.controller_url),
                           "%s", optarg); break;
        case 'n': {
            char *end = NULL;
            unsigned long long v = strtoull(optarg, &end, 0);
            if (end != optarg) sdn_cfg.default_dpid = (uint64_t)v;
            break;
        }
        case 'w': ws_cfg.port = (uint16_t)atoi(optarg); break;
        case 'v': g_verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    /* signals */
    struct sigaction sa = { .sa_handler = sig_handler };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    /* daemonise */
    if (daemonise) {
        if (daemon(0, 0) < 0) {
            perror("daemon");
            return 1;
        }
    }

    LOG_INFO("Sentinel Pipeline starting...");

    /* ---- open proxy device ---- */
    int dev_fd = open("/dev/sentinel_proxy", O_RDWR | O_NONBLOCK);
    if (dev_fd < 0) {
        LOG_ERROR("Cannot open /dev/sentinel_proxy: %s", strerror(errno));
        LOG_ERROR("Is the kernel module loaded? (sudo insmod sentinel_proxy.ko)");
        return 1;
    }
    LOG_INFO("Proxy device opened");

    /* ---- configure proxy module via IOCTL ---- */
    {
        int val = 1;
        if (ioctl(dev_fd, SENTINEL_IOCTL_ENABLE_FILTERING, &val) < 0)
            LOG_WARN("IOCTL enable filtering: %s", strerror(errno));
        else
            LOG_INFO("Kernel filtering enabled");

        val = g_filter_mode;
        if (ioctl(dev_fd, SENTINEL_IOCTL_SET_FILTER_MODE, &val) < 0)
            LOG_WARN("IOCTL set filter mode: %s", strerror(errno));
        else
            LOG_INFO("Kernel filter mode set to %s",
                     val == SENTINEL_MODE_LEARN ? "LEARN" :
                     val == SENTINEL_MODE_DETECT ? "DETECT" :
                     val == SENTINEL_MODE_PROTECT ? "PROTECT" : "UNKNOWN");
    }

    /* ---- initialise feature extractor ---- */
    fe_config_t fe_cfg = {
        .window_sec       = SENTINEL_WINDOW_SECONDS,
        .flow_table_buckets = 16384,
        .max_flows          = 100000,
        .gc_interval_sec    = 30
    };
    fe_context_t *fe = fe_init(&fe_cfg);
    if (!fe) {
        LOG_ERROR("Feature extractor init failed");
        close(dev_fd);
        return 1;
    }
    LOG_INFO("Feature extractor initialised (window=%us, buckets=%u)",
             fe_cfg.window_sec, fe_cfg.flow_table_buckets);

    /* ---- initialise decision engine ---- */
    de_thresholds_t de_cfg = DE_THRESHOLDS_DEFAULT;
    de_context_t *de = de_init(&de_cfg);
    if (!de) {
        LOG_ERROR("Decision engine init failed");
        fe_destroy(fe);
        close(dev_fd);
        return 1;
    }
    LOG_INFO("Decision engine initialised");

    /* ---- initialise SDN controller ---- */
    sdn_context_t *sdn = sdn_init(&sdn_cfg);
    if (!sdn) {
        LOG_ERROR("SDN controller init failed");
        de_destroy(de);
        fe_destroy(fe);
        close(dev_fd);
        return 1;
    }
    LOG_INFO("Ryu SDN controller at %s  dpid=%" PRIu64,
             sdn_cfg.controller_url, sdn_cfg.default_dpid);

    /* optional health check */
    if (sdn_health_check(sdn) == 0) {
        LOG_INFO("Ryu controller reachable");
    } else {
        LOG_WARN("Ryu controller unreachable (will retry on rule push)");
    }

    /* ---- initialise feedback loop ---- */
    fb_config_t fb_cfg = FB_CONFIG_DEFAULT;
    fb_context_t *fb = fb_init(&fb_cfg);
    if (!fb) {
        LOG_WARN("Feedback module init failed (continuing without it)");
    } else {
        LOG_INFO("Feedback loop initialised (history=%u, window=%us)",
                 fb_cfg.history_size, fb_cfg.evaluation_window_sec);
    }

    /* ---- initialise WebSocket server ---- */
    ws_context_t *ws = NULL;
    if (ws_cfg.port > 0) {
        ws = ws_init(&ws_cfg);
        if (ws) {
            if (ws_start(ws) == 0) {
                LOG_INFO("WebSocket server started on port %u", ws_cfg.port);
            } else {
                LOG_ERROR("Failed to start WebSocket server");
                ws_destroy(ws);
                ws = NULL;
            }
        } else {
            LOG_ERROR("WebSocket init failed");
        }
    }

    /* ---- pipeline stats ---- */
    pipeline_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    stats.start_time = time(NULL);

    /* GC timer */
    time_t last_gc = time(NULL);
    time_t last_stats = time(NULL);
    time_t last_feedback = time(NULL);
    
    /* WebSocket update timers and counters */
    time_t last_ws_1s = time(NULL);
    time_t last_ws_5s = time(NULL);
    time_t last_ws_10s = time(NULL);
    uint64_t last_ws_packets = 0;
    uint64_t last_ws_bytes = 0;

    /* poll setup */
    struct pollfd pfd = { .fd = dev_fd, .events = POLLIN };

    /* ---- main loop ---- */
    LOG_INFO("Pipeline running. Ctrl+C to stop. (SIGUSR1=stats, SIGUSR2=reset baselines)");

    while (g_running) {
        /* Handle deferred signals */
        if (g_dump_stats) {
            g_dump_stats = 0;
            print_stats(&stats, dev_fd, de, sdn, fb);
        }
        if (g_reset_baselines) {
            g_reset_baselines = 0;
            de_reset_baselines(de);
            LOG_INFO("Baselines reset via SIGUSR2");
        }

        /* poll with 100ms timeout for maintenance */
        int rc = poll(&pfd, 1, 100);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            LOG_ERROR("poll: %s", strerror(errno));
            break;
        }

        if (rc == 0) {
            /* timeout - periodic maintenance */
            time_t now = time(NULL);

            if (difftime(now, last_gc) >= fe_cfg.gc_interval_sec) {
                fe_gc(fe);
                last_gc = now;
                LOG_DEBUG("GC: %u active flows, %u active sources",
                          fe_active_flows(fe), fe_active_sources(fe));
            }

            if (difftime(now, last_stats) >= 60) {
                print_stats(&stats, dev_fd, de, sdn, fb);
                last_stats = now;
            }

            /* periodic feedback evaluation */
            if (fb && difftime(now, last_feedback) >= 120) {
                fb_adjustments_t adj;
                if (fb_suggest_adjustments(fb, &adj) == 0 && adj.should_adjust) {
                    LOG_INFO("Feedback: %s", adj.reason);
                }
                last_feedback = now;
            }
            
            /* WebSocket updates */
            if (ws) {
                /* 1 second updates */
                if (difftime(now, last_ws_1s) >= 1) {
                    double elapsed = difftime(now, last_ws_1s);
                    
                    /* Calculate actual rates since last update */
                    uint64_t packets_delta = stats.packets_processed - last_ws_packets;
                    uint64_t bytes_delta = stats.packets_processed * 1000;  /* rough estimate */
                    
                    ws_metrics_t m;
                    memset(&m, 0, sizeof(m));
                    m.packets_per_sec = (uint64_t)(packets_delta / elapsed);
                    m.bytes_per_sec = (uint64_t)(bytes_delta / elapsed);
                    m.active_flows = fe_active_flows(fe);
                    m.active_sources = fe_active_sources(fe);
                    m.ml_classifications_per_sec = m.packets_per_sec;
                    m.cpu_usage_percent = 0.0;  /* TODO: get real CPU usage */
                    m.memory_usage_mb = 0.0;  /* TODO: get real memory usage */
                    m.kernel_drops = 0;
                    m.userspace_drops = 0;
                    ws_update_metrics(ws, &m);
                    
                    ws_traffic_rate_t tr;
                    memset(&tr, 0, sizeof(tr));
                    tr.total_pps = m.packets_per_sec;
                    tr.total_bps = m.bytes_per_sec;
                    tr.tcp_pps = m.packets_per_sec * 7 / 10;  /* estimate based on typical traffic */
                    tr.udp_pps = m.packets_per_sec * 2 / 10;
                    tr.icmp_pps = m.packets_per_sec * 1 / 10;
                    ws_update_traffic_rate(ws, &tr);
                    
                    ws_protocol_dist_t pd;
                    memset(&pd, 0, sizeof(pd));
                    pd.tcp_percent = 70.0;
                    pd.udp_percent = 20.0;
                    pd.icmp_percent = 10.0;
                    pd.other_percent = 0.0;
                    pd.tcp_bytes = tr.tcp_pps * 1000;
                    pd.udp_bytes = tr.udp_pps * 500;
                    pd.icmp_bytes = tr.icmp_pps * 84;
                    ws_update_protocol_dist(ws, &pd);
                    
                    ws_connection_t conns[10];
                    int conn_count = 0;  /* TODO: get real connections from FE */
                    ws_update_connections(ws, conns, conn_count);
                    
                    ws_mitigation_status_t ms;
                    memset(&ms, 0, sizeof(ms));
                    ms.total_blocked = stats.verdicts_drop;
                    ms.total_rate_limited = stats.verdicts_rate_limit;
                    ms.total_monitored = stats.verdicts_quarantine;
                    ms.total_whitelisted = stats.verdicts_allow;
                    ms.kernel_verdict_cache_hits = 0;  /* TODO: get from kernel */
                    ms.kernel_verdict_cache_misses = 0;
                    ms.active_sdn_rules = 0;  /* TODO: track SDN rules */
                    ws_update_mitigation_status(ws, &ms);
                    
                    /* Update counters for next interval */
                    last_ws_packets = stats.packets_processed;
                    last_ws_bytes = bytes_delta;
                    last_ws_1s = now;
                }
                
                /* 5 second updates */
                if (difftime(now, last_ws_5s) >= 5) {
                    ws_top_source_t sources[10];
                    int source_count = 0;  /* TODO: get real top sources from FE */
                    ws_update_top_sources(ws, sources, source_count);
                    last_ws_5s = now;
                }
                
                /* 10 second updates */
                if (difftime(now, last_ws_10s) >= 10) {
                    ws_feature_importance_t fi;
                    memset(&fi, 0, sizeof(fi));
                    fi.volume_weight = 0.35;
                    fi.entropy_weight = 0.25;
                    fi.protocol_weight = 0.20;
                    fi.behavioral_weight = 0.20;
                    fi.avg_threat_score = 0.0;  /* TODO: calculate from DE */
                    fi.detections_last_10s = stats.verdicts_drop + stats.verdicts_rate_limit;
                    ws_update_feature_importance(ws, &fi);
                    last_ws_10s = now;
                }
            }
            
            continue;
        }

        /* ---- read packet from proxy device ---- */
        struct sentinel_packet_metadata meta;
        ssize_t n = read(dev_fd, &meta, sizeof(meta));

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            LOG_ERROR("read: %s", strerror(errno));
            break;
        }

        if ((size_t)n < sizeof(meta)) {
            LOG_WARN("Short read (%zd bytes), skipping", n);
            continue;
        }

        stats.packets_processed++;

        /* ---- step 1: ingest into feature extractor ---- */
        fe_packet_t pkt;
        metadata_to_fe_packet(&meta, &pkt);
        fe_ingest_packet(fe, &pkt);

        /* ---- step 2: extract features for this flow ---- */
        sentinel_feature_vector_t fv;
        memset(&fv, 0, sizeof(fv));
        if (fe_extract_last(fe, &fv) != 0) {
            /* flow just started, not enough data - allow */
            struct sentinel_packet_decision dec = {
                .packet_id = meta.packet_id,
                .verdict   = SENTINEL_VERDICT_ALLOW
            };
            write(dev_fd, &dec, sizeof(dec));
            continue;
        }

        /* ---- step 3: classify with decision engine ---- */
        sentinel_threat_assessment_t assessment;
        if (de_classify(de, &fv, &assessment) != 0) {
            LOG_WARN("de_classify failed for packet %u", meta.packet_id);
            struct sentinel_packet_decision dec = {
                .packet_id = meta.packet_id,
                .verdict   = SENTINEL_VERDICT_ALLOW
            };
            write(dev_fd, &dec, sizeof(dec));
            continue;
        }

        /* update stats */
        switch (assessment.verdict) {
        case VERDICT_ALLOW:      stats.verdicts_allow++;      break;
        case VERDICT_DROP:       stats.verdicts_drop++;       break;
        case VERDICT_RATE_LIMIT: stats.verdicts_rate_limit++; break;
        case VERDICT_QUARANTINE: stats.verdicts_quarantine++; break;
        default: break;
        }

        /* ---- step 4: send verdict back to kernel ---- */
        send_verdict(dev_fd, meta.packet_id, &assessment);
        
        /* ---- WebSocket: push activity log for non-allow verdicts ---- */
        if (ws && assessment.verdict != VERDICT_ALLOW) {
            ws_activity_t act;
            memset(&act, 0, sizeof(act));
            act.timestamp_ns = (uint64_t)time(NULL) * 1000000000ULL;
            act.src_ip = meta.src_ip;
            snprintf(act.action, sizeof(act.action), "%s", verdict_str(assessment.verdict));
            snprintf(act.attack_type, sizeof(act.attack_type), "%s", attack_str(assessment.attack_type));
            snprintf(act.reason, sizeof(act.reason), "Threat score %.2f", assessment.threat_score);
            act.threat_score = assessment.threat_score;
            ws_push_activity(ws, &act);
        }

        /* ---- step 5: cache verdict in kernel for fast enforcement ---- */
        if (assessment.verdict != VERDICT_ALLOW) {
            struct sentinel_verdict_update vu;
            memset(&vu, 0, sizeof(vu));
            vu.src_ip = meta.src_ip;
            vu.rate_limit_pps = assessment.rate_limit_pps;
            vu.duration_sec = assessment.quarantine_sec
                              ? assessment.quarantine_sec : 300;

            switch (assessment.verdict) {
            case VERDICT_DROP:       vu.verdict = SENTINEL_VERDICT_DROP; break;
            case VERDICT_RATE_LIMIT: vu.verdict = SENTINEL_VERDICT_RATE_LIMIT; break;
            case VERDICT_QUARANTINE: vu.verdict = SENTINEL_VERDICT_QUARANTINE; break;
            default:                 vu.verdict = SENTINEL_VERDICT_DROP; break;
            }

            ioctl(dev_fd, SENTINEL_IOCTL_CACHE_VERDICT, &vu);
        }

        /* ---- step 6: push SDN rule ---- */
        if (assessment.verdict != VERDICT_ALLOW) {
            sentinel_sdn_rule_t rule;
            if (sdn_build_rule_from_assessment(sdn, &assessment, &rule) == 0) {
                if (sdn_push_rule(sdn, &rule) == 0) {
                    stats.sdn_rules_pushed++;
                    LOG_DEBUG("SDN rule %u pushed: %s -> %s (score=%.2f)",
                              rule.rule_id,
                              attack_str(assessment.attack_type),
                              verdict_str(assessment.verdict),
                              assessment.threat_score);
                } else {
                    stats.sdn_rules_failed++;
                }
            }
        }

        /* ---- step 7: record in feedback loop ---- */
        if (fb) {
            fb_record_action(fb, meta.src_ip, assessment.verdict,
                             assessment.attack_type, assessment.threat_score);

            /* auto-detect FP/FN based on score changes */
            if (assessment.threat_score > 0.7)
                fb_auto_detect_fn(fb, meta.src_ip, assessment.threat_score);
            else if (assessment.threat_score < 0.1)
                fb_auto_detect_fp(fb, meta.src_ip, assessment.threat_score);
        }

        /* verbose per-packet log */
        if (g_verbose && stats.packets_processed % 1000 == 0) {
            char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
            struct in_addr a;
            a.s_addr = meta.src_ip;
            inet_ntop(AF_INET, &a, sip, sizeof(sip));
            a.s_addr = meta.dst_ip;
            inet_ntop(AF_INET, &a, dip, sizeof(dip));
            LOG_DEBUG("pkt#%lu %s:%u->%s:%u proto=%u verdict=%s score=%.3f [%s]",
                      (unsigned long)stats.packets_processed,
                      sip, ntohs(meta.src_port), dip, ntohs(meta.dst_port),
                      meta.protocol,
                      verdict_str(assessment.verdict),
                      assessment.threat_score,
                      attack_str(assessment.attack_type));
        }
    }

    /* ---- shutdown ---- */
    LOG_INFO("Shutting down...");
    print_stats(&stats, dev_fd, de, sdn, fb);

    /* Disable kernel filtering on exit */
    {
        int val = 0;
        ioctl(dev_fd, SENTINEL_IOCTL_ENABLE_FILTERING, &val);
        LOG_INFO("Kernel filtering disabled");
    }

    if (ws) {
        ws_stop(ws);
        ws_destroy(ws);
        LOG_INFO("WebSocket server stopped");
    }

    fb_destroy(fb);
    sdn_destroy(sdn);
    de_destroy(de);
    fe_destroy(fe);
    close(dev_fd);

    LOG_INFO("Pipeline stopped.");
    return 0;
}
