/*
 * Sentinel DDoS Core - Shared Type Definitions
 *
 * Common data structures used across all components:
 *   proxy -> featureextractor -> decisionengine -> sdncontrolplane
 *
 * All userspace components include this header. It does NOT depend on
 * linux/types.h so it compiles cleanly in userspace with stdint.h.
 */

#ifndef SENTINEL_TYPES_H
#define SENTINEL_TYPES_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * VERSIONING
 * ============================================================================ */

#define SENTINEL_VERSION_MAJOR 1
#define SENTINEL_VERSION_MINOR 0
#define SENTINEL_VERSION_PATCH 0

/* ============================================================================
 * LIMITS
 * ============================================================================ */

#define SENTINEL_MAX_FEATURES       32
#define SENTINEL_MAX_FLOW_KEY_LEN   13   /* 4+4+2+2+1 bytes for 5-tuple */
#define SENTINEL_FLOW_TABLE_BUCKETS 65536
#define SENTINEL_WINDOW_SECONDS     10   /* sliding window duration */
#define SENTINEL_MAX_PORTS_TRACKED  1024
#define SENTINEL_PAYLOAD_SAMPLE     256

/* ============================================================================
 * FLOW KEY  (5-tuple that identifies a uni-directional flow)
 * ============================================================================ */

typedef struct sentinel_flow_key {
    uint32_t src_ip;        /* network byte order */
    uint32_t dst_ip;        /* network byte order */
    uint16_t src_port;      /* network byte order */
    uint16_t dst_port;      /* network byte order */
    uint8_t  protocol;      /* IPPROTO_TCP / UDP / ICMP */
} __attribute__((packed)) sentinel_flow_key_t;

/* ============================================================================
 * FEATURE VECTOR  (output of featureextractor, input of decision engine)
 * ============================================================================ */

typedef struct sentinel_feature_vector {
    /* --- identity (copied from flow key) --- */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;

    /* --- timing --- */
    uint64_t window_start_ns;       /* window start  (kernel ns) */
    uint64_t window_end_ns;         /* window end    (kernel ns) */
    double   window_duration_sec;   /* convenience: (end-start)/1e9 */

    /* --- volume features --- */
    uint64_t packet_count;          /* packets in window */
    uint64_t byte_count;            /* total payload bytes in window */
    double   packets_per_second;    /* packet rate */
    double   bytes_per_second;      /* byte rate */
    double   avg_packet_size;       /* mean payload length */
    double   stddev_packet_size;    /* stddev payload length */

    /* --- TCP flag features (only meaningful for TCP) --- */
    uint32_t syn_count;
    uint32_t ack_count;
    uint32_t fin_count;
    uint32_t rst_count;
    uint32_t psh_count;
    double   syn_ratio;             /* syn_count / packet_count */
    double   fin_ratio;
    double   rst_ratio;

    /* --- entropy features --- */
    double   src_port_entropy;      /* Shannon entropy of src ports in window */
    double   dst_port_entropy;      /* Shannon entropy of dst ports in window */
    double   payload_byte_entropy;  /* entropy of first N payload bytes */

    /* --- diversity features --- */
    uint32_t unique_src_ports;      /* distinct source ports seen */
    uint32_t unique_dst_ports;      /* distinct dest ports seen */
    uint32_t unique_src_ips;        /* per aggregate (src_ip=0 wildcard) */

    /* --- TTL features --- */
    double   avg_ttl;
    double   stddev_ttl;
    uint8_t  min_ttl;
    uint8_t  max_ttl;

    /* --- inter-arrival time features --- */
    double   avg_iat_us;            /* mean inter-arrival time (microseconds) */
    double   stddev_iat_us;
    double   min_iat_us;
    double   max_iat_us;

    /* --- aggregate source features (per src_ip across all flows) --- */
    uint32_t src_total_flows;       /* how many distinct flows from this src */
    uint64_t src_total_packets;     /* total packets from this src (all flows) */
    double   src_packets_per_second;

    /* --- raw scores (filled by extractor as hints) --- */
    double   anomaly_hint;          /* 0.0 = normal, 1.0 = anomalous */
} sentinel_feature_vector_t;

/* ============================================================================
 * THREAT ASSESSMENT  (output of decision engine)
 * ============================================================================ */

typedef enum sentinel_attack_type {
    SENTINEL_ATTACK_NONE          = 0,
    SENTINEL_ATTACK_SYN_FLOOD     = 1,
    SENTINEL_ATTACK_UDP_FLOOD     = 2,
    SENTINEL_ATTACK_ICMP_FLOOD    = 3,
    SENTINEL_ATTACK_DNS_AMP       = 4,
    SENTINEL_ATTACK_NTP_AMP       = 5,
    SENTINEL_ATTACK_SLOWLORIS     = 6,
    SENTINEL_ATTACK_PORT_SCAN     = 7,
    SENTINEL_ATTACK_LAND          = 8,
    SENTINEL_ATTACK_SMURF         = 9,
    SENTINEL_ATTACK_UNKNOWN       = 255
} sentinel_attack_type_t;

typedef enum sentinel_verdict_e {
    VERDICT_ALLOW      = 0,
    VERDICT_DROP       = 1,
    VERDICT_RATE_LIMIT = 2,
    VERDICT_REDIRECT   = 3,
    VERDICT_QUARANTINE = 4
} sentinel_verdict_e;

typedef struct sentinel_threat_assessment {
    /* --- identity --- */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;

    /* --- classification --- */
    sentinel_attack_type_t  attack_type;
    double                  threat_score;     /* 0.0 (safe) .. 1.0 (attack) */
    double                  confidence;       /* confidence in the score */

    /* --- decision --- */
    sentinel_verdict_e      verdict;
    uint32_t                rate_limit_pps;   /* if verdict == RATE_LIMIT */
    uint32_t                quarantine_sec;   /* if verdict == QUARANTINE */

    /* --- scoring breakdown (explainability) --- */
    double   score_volume;          /* volume anomaly component */
    double   score_entropy;         /* entropy anomaly component */
    double   score_protocol;        /* protocol anomaly component */
    double   score_behavioral;      /* behavioral anomaly component */

    /* --- timing --- */
    uint64_t assessment_time_ns;    /* wall-clock time of assessment */
} sentinel_threat_assessment_t;

/* ============================================================================
 * SDN FLOW RULE  (sent to OpenDaylight)
 * ============================================================================ */

typedef enum sentinel_sdn_action {
    SDN_ACTION_DROP       = 0,
    SDN_ACTION_ALLOW      = 1,
    SDN_ACTION_RATE_LIMIT = 2,
    SDN_ACTION_REDIRECT   = 3,
    SDN_ACTION_MIRROR     = 4
} sentinel_sdn_action_t;

typedef struct sentinel_sdn_rule {
    uint32_t rule_id;
    uint16_t priority;              /* OpenFlow priority (0-65535) */

    /* --- match fields --- */
    uint32_t match_src_ip;          /* 0 = wildcard */
    uint32_t match_dst_ip;          /* 0 = wildcard */
    uint32_t match_src_mask;        /* CIDR mask: 0xFFFFFF00 = /24 */
    uint32_t match_dst_mask;
    uint16_t match_src_port;        /* 0 = wildcard */
    uint16_t match_dst_port;        /* 0 = wildcard */
    uint8_t  match_protocol;        /* 0 = wildcard */

    /* --- actions --- */
    sentinel_sdn_action_t action;
    uint32_t rate_limit_kbps;       /* for RATE_LIMIT */
    uint32_t redirect_port;         /* for REDIRECT: output port on switch */
    char     redirect_ip[16];       /* for REDIRECT: next-hop IP string */

    /* --- metadata --- */
    uint32_t idle_timeout;          /* seconds, 0 = permanent */
    uint32_t hard_timeout;          /* seconds, 0 = permanent */
    char     table_id[16];          /* OpenFlow table, default "0" */
    char     node_id[64];           /* Ryu dpid as string, e.g. "1" */

    /* --- origin --- */
    sentinel_attack_type_t  triggered_by;
    double                  threat_score;
    uint64_t                created_ns;
} sentinel_sdn_rule_t;

/* ============================================================================
 * PIPELINE CONTEXT  (passed through the whole chain)
 * ============================================================================ */

typedef struct sentinel_pipeline_ctx {
    sentinel_feature_vector_t      features;
    sentinel_threat_assessment_t   assessment;
    sentinel_sdn_rule_t            rule;         /* populated only if action needed */
    int                            rule_needed;  /* 1 if SDN push required */
} sentinel_pipeline_ctx_t;

#ifdef __cplusplus
}
#endif

#endif /* SENTINEL_TYPES_H */
