/*
 * Sentinel DDoS Core - WebSocket Server for Real-time Data Streaming
 *
 * Broadcasts 12 data streams to connected web clients:
 *   1. metrics (1s)             - System performance counters
 *   2. activity_logs (event)    - Mitigation actions
 *   3. blocked_ips (change)     - Blocked IP list
 *   4. rate_limited_ips (change)- Rate limited IPs
 *   5. monitored_ips (change)   - Monitored IPs
 *   6. whitelisted_ips (change) - Whitelisted IPs
 *   7. traffic_rate (1s)        - Traffic throughput
 *   8. protocol_distribution (1s)- Protocol breakdown
 *   9. top_sources (5s)         - Top traffic sources
 *  10. feature_importance (10s) - ML detection factors
 *  11. active_connections (1s)  - Active flows
 *  12. mitigation_status (1s)   - Mitigation summary
 *
 * Uses libwebsockets for WebSocket support.
 */

#ifndef SENTINEL_WEBSOCKET_SERVER_H
#define SENTINEL_WEBSOCKET_SERVER_H

#include <stdint.h>
#include <time.h>
#include "../core/sentinel_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

typedef struct ws_config {
    uint16_t port;                  /* WebSocket port (default 8765) */
    char     bind_addr[64];         /* Bind address (default "0.0.0.0") */
    int      max_clients;           /* Max concurrent clients */
    int      ping_interval_sec;     /* WebSocket ping interval */
} ws_config_t;

#define WS_CONFIG_DEFAULT { \
    .port = 8765,               \
    .bind_addr = "0.0.0.0",     \
    .max_clients = 100,         \
    .ping_interval_sec = 30     \
}

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/* Stream 1: Metrics */
typedef struct ws_metrics {
    uint64_t packets_per_sec;
    uint64_t bytes_per_sec;
    uint32_t active_flows;
    uint32_t active_sources;
    uint32_t ml_classifications_per_sec;
    double   cpu_usage_percent;
    double   memory_usage_mb;
    uint64_t kernel_drops;
    uint64_t userspace_drops;
} ws_metrics_t;

/* Stream 2: Activity Log Entry */
typedef struct ws_activity {
    uint64_t timestamp_ns;
    uint32_t src_ip;
    char     action[16];           /* BLOCK/RATE_LIMIT/MONITOR/WHITELIST */
    char     attack_type[32];
    double   threat_score;
    char     reason[128];
} ws_activity_t;

/* Stream 3-6: IP Lists */
typedef struct ws_ip_entry {
    uint32_t ip;
    uint64_t timestamp_added;
    uint32_t rule_id;              /* For blocked/rate_limited */
    uint32_t rate_limit_pps;       /* For rate_limited only */
} ws_ip_entry_t;

/* Stream 7: Traffic Rate */
typedef struct ws_traffic_rate {
    uint64_t total_pps;
    uint64_t total_bps;
    uint64_t tcp_pps;
    uint64_t udp_pps;
    uint64_t icmp_pps;
    uint64_t other_pps;
} ws_traffic_rate_t;

/* Stream 8: Protocol Distribution */
typedef struct ws_protocol_dist {
    double tcp_percent;
    double udp_percent;
    double icmp_percent;
    double other_percent;
    uint64_t tcp_bytes;
    uint64_t udp_bytes;
    uint64_t icmp_bytes;
    uint64_t other_bytes;
} ws_protocol_dist_t;

/* Stream 9: Top Source */
typedef struct ws_top_source {
    uint32_t src_ip;
    uint64_t packets;
    uint64_t bytes;
    uint32_t flow_count;
    int      suspicious;           /* 1 if flagged */
    double   threat_score;
} ws_top_source_t;

/* Stream 10: Feature Importance */
typedef struct ws_feature_importance {
    double volume_weight;
    double entropy_weight;
    double protocol_weight;
    double behavioral_weight;
    double avg_threat_score;
    uint32_t detections_last_10s;
} ws_feature_importance_t;

/* Stream 11: Active Connection */
typedef struct ws_connection {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint64_t packets;
    uint64_t bytes;
    uint64_t last_seen_ns;
} ws_connection_t;

/* Stream 12: Mitigation Status */
typedef struct ws_mitigation_status {
    uint32_t total_blocked;
    uint32_t total_rate_limited;
    uint32_t total_monitored;
    uint32_t total_whitelisted;
    uint64_t kernel_verdict_cache_hits;
    uint64_t kernel_verdict_cache_misses;
    uint32_t active_sdn_rules;
} ws_mitigation_status_t;

/* ============================================================================
 * OPAQUE HANDLE
 * ============================================================================ */

typedef struct ws_context ws_context_t;

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

ws_context_t *ws_init(const ws_config_t *cfg);
void           ws_destroy(ws_context_t *ctx);
int            ws_start(ws_context_t *ctx);  /* Starts background thread */
void           ws_stop(ws_context_t *ctx);

/* ============================================================================
 * STREAM UPDATES (called from main pipeline thread)
 * ============================================================================ */

/* Stream 1: Update metrics (1s interval) */
void ws_update_metrics(ws_context_t *ctx, const ws_metrics_t *metrics);

/* Stream 2: Push activity log (event-driven) */
void ws_push_activity(ws_context_t *ctx, const ws_activity_t *activity);

/* Stream 3: Update blocked IPs (on change) */
void ws_update_blocked_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count);

/* Stream 4: Update rate limited IPs (on change) */
void ws_update_rate_limited_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count);

/* Stream 5: Update monitored IPs (on change) */
void ws_update_monitored_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count);

/* Stream 6: Update whitelisted IPs (on change) */
void ws_update_whitelisted_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count);

/* Stream 7: Update traffic rate (1s interval) */
void ws_update_traffic_rate(ws_context_t *ctx, const ws_traffic_rate_t *rate);

/* Stream 8: Update protocol distribution (1s interval) */
void ws_update_protocol_dist(ws_context_t *ctx, const ws_protocol_dist_t *dist);

/* Stream 9: Update top sources (5s interval) */
void ws_update_top_sources(ws_context_t *ctx, const ws_top_source_t *sources, uint32_t count);

/* Stream 10: Update feature importance (10s interval) */
void ws_update_feature_importance(ws_context_t *ctx, const ws_feature_importance_t *importance);

/* Stream 11: Update active connections (1s interval) */
void ws_update_connections(ws_context_t *ctx, const ws_connection_t *conns, uint32_t count);

/* Stream 12: Update mitigation status (1s interval) */
void ws_update_mitigation_status(ws_context_t *ctx, const ws_mitigation_status_t *status);

/* ============================================================================
 * STATISTICS
 * ============================================================================ */

uint32_t ws_get_client_count(const ws_context_t *ctx);
uint64_t ws_get_messages_sent(const ws_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SENTINEL_WEBSOCKET_SERVER_H */
