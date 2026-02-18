/*
 * Sentinel DDoS Core - Feature Extractor API
 *
 * Public interface. Call fe_init() once, then fe_ingest_packet() for every
 * packet from the proxy, and fe_extract() to get the current feature vector
 * for a given flow or source IP.
 */

#ifndef SENTINEL_FEATURE_EXTRACTOR_H
#define SENTINEL_FEATURE_EXTRACTOR_H

#include "../core/sentinel_types.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

typedef struct fe_config {
    uint32_t window_sec;            /* sliding window length (default 10) */
    uint32_t flow_table_buckets;    /* hash table size (default 65536) */
    uint32_t max_flows;             /* hard cap on tracked flows (0=unlimited) */
    uint32_t gc_interval_sec;       /* garbage collection interval (default 30) */
} fe_config_t;

/* Sane defaults */
#define FE_CONFIG_DEFAULT { \
    .window_sec          = SENTINEL_WINDOW_SECONDS, \
    .flow_table_buckets  = SENTINEL_FLOW_TABLE_BUCKETS, \
    .max_flows           = 0, \
    .gc_interval_sec     = 30  \
}

/* ============================================================================
 * OPAQUE HANDLE
 * ============================================================================ */

typedef struct fe_context fe_context_t;

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

/*  Allocate and initialise the feature extractor.
 *  Returns NULL on failure. */
fe_context_t *fe_init(const fe_config_t *cfg);

/*  Tear down and free all resources. */
void fe_destroy(fe_context_t *ctx);

/* ============================================================================
 * PACKET INGESTION
 * ============================================================================ */

/*  Portable packet record that mirrors the kernel metadata but uses
 *  standard C types so callers don't need linux/types.h. */
typedef struct fe_packet {
    uint32_t packet_id;
    uint32_t src_ip;           /* network byte order */
    uint32_t dst_ip;
    uint16_t src_port;         /* network byte order */
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  direction;        /* 0 = inbound, 1 = outbound */
    uint16_t payload_len;
    uint64_t timestamp_ns;     /* kernel nanosecond timestamp */
    uint8_t  ttl;
    uint8_t  tcp_flags;        /* raw TCP flags byte (SYN=0x02 etc.) */
    const uint8_t *payload;    /* first N bytes, may be NULL */
} fe_packet_t;

/* TCP flag bits (standard) */
#define FE_TCP_FIN  0x01
#define FE_TCP_SYN  0x02
#define FE_TCP_RST  0x04
#define FE_TCP_PSH  0x08
#define FE_TCP_ACK  0x10

/*  Ingest one packet.  Updates flow table and per-source aggregates.
 *  Returns 0 on success, -1 on error. */
int fe_ingest_packet(fe_context_t *ctx, const fe_packet_t *pkt);

/* ============================================================================
 * FEATURE EXTRACTION
 * ============================================================================ */

/*  Extract the feature vector for a specific 5-tuple flow.
 *  Fills *out.  Returns 0 on success, -1 if flow not found. */
int fe_extract_flow(fe_context_t *ctx,
                    const sentinel_flow_key_t *key,
                    sentinel_feature_vector_t *out);

/*  Extract the aggregate feature vector for a source IP across ALL its flows.
 *  Returns 0 on success, -1 if source not seen. */
int fe_extract_source(fe_context_t *ctx,
                      uint32_t src_ip,
                      sentinel_feature_vector_t *out);

/*  Extract features for the flow of the most-recently ingested packet.
 *  Convenience wrapper.  Returns 0 on success. */
int fe_extract_last(fe_context_t *ctx, sentinel_feature_vector_t *out);

/* ============================================================================
 * MAINTENANCE
 * ============================================================================ */

/*  Run garbage collection: evict stale flows older than window. */
int fe_gc(fe_context_t *ctx);

/*  Return the number of active flows. */
uint32_t fe_active_flows(const fe_context_t *ctx);

/*  Return the number of tracked source IPs. */
uint32_t fe_active_sources(const fe_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SENTINEL_FEATURE_EXTRACTOR_H */
