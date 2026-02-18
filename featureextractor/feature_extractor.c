/*
 * Sentinel DDoS Core - Feature Extractor Implementation
 *
 * Maintains a hash-table of per-flow and per-source statistics.
 * For every ingested packet it updates running counters inside a sliding
 * window.  On extraction it computes derived features (rates, entropy,
 * standard deviations, inter-arrival statistics) and fills a
 * sentinel_feature_vector_t.
 *
 * Thread-safety: NOT thread-safe.  Caller must serialise or use one
 * fe_context_t per thread.
 */

#define _POSIX_C_SOURCE 200809L
#include "feature_extractor.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

/* ============================================================================
 * INTERNAL CONSTANTS
 * ============================================================================ */

#define MAX_RING_SIZE    4096   /* max packets kept in the sliding window */
#define PORT_HASH_SIZE   1024   /* for port entropy counting */
#define NS_PER_SEC       1000000000ULL

/* ============================================================================
 * RING BUFFER ENTRY  –  one entry per packet in the window
 * ============================================================================ */

typedef struct pkt_record {
    uint64_t timestamp_ns;
    uint16_t payload_len;
    uint8_t  ttl;
    uint8_t  tcp_flags;
    uint16_t src_port;      /* network byte order */
    uint16_t dst_port;      /* network byte order */
} pkt_record_t;

/* ============================================================================
 * PER-FLOW STATE
 * ============================================================================ */

typedef struct flow_entry {
    sentinel_flow_key_t key;

    /* ring buffer of recent packets (sliding window) */
    pkt_record_t  ring[MAX_RING_SIZE];
    uint32_t      ring_head;      /* next write position */
    uint32_t      ring_count;     /* number of valid entries */

    /* running counters for the current window */
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t window_start_ns;
    uint64_t last_timestamp_ns;

    /* TCP flag counters */
    uint32_t syn_count;
    uint32_t ack_count;
    uint32_t fin_count;
    uint32_t rst_count;
    uint32_t psh_count;

    /* port tracking (using small hash sets) */
    uint16_t src_ports_seen[PORT_HASH_SIZE];
    uint16_t dst_ports_seen[PORT_HASH_SIZE];
    uint32_t unique_src_ports;
    uint32_t unique_dst_ports;

    /* linked list for hash bucket chaining */
    struct flow_entry *next;
} flow_entry_t;

/* ============================================================================
 * PER-SOURCE AGGREGATE STATE
 * ============================================================================ */

typedef struct source_entry {
    uint32_t src_ip;
    uint32_t total_flows;
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t first_seen_ns;
    uint64_t last_seen_ns;
    struct source_entry *next;
} source_entry_t;

/* ============================================================================
 * CONTEXT
 * ============================================================================ */

struct fe_context {
    fe_config_t cfg;

    /* flow hash table */
    flow_entry_t **flow_buckets;
    uint32_t       flow_count;

    /* source aggregate hash table */
    source_entry_t **src_buckets;
    uint32_t         src_count;
    uint32_t         src_bucket_count;

    /* last-ingested tracking */
    sentinel_flow_key_t last_key;
    int                  last_valid;
};

/* ============================================================================
 * HASH HELPERS
 * ============================================================================ */

static uint32_t hash_flow_key(const sentinel_flow_key_t *k, uint32_t nbuckets)
{
    /* FNV-1a over the 13-byte 5-tuple */
    const uint8_t *p = (const uint8_t *)k;
    uint32_t h = 2166136261u;
    for (int i = 0; i < (int)sizeof(*k); i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h % nbuckets;
}

static uint32_t hash_u32(uint32_t val, uint32_t nbuckets)
{
    val = ((val >> 16) ^ val) * 0x45d9f3b;
    val = ((val >> 16) ^ val) * 0x45d9f3b;
    val = (val >> 16) ^ val;
    return val % nbuckets;
}

/* ============================================================================
 * PORT SET HELPERS  (open-address hash set on uint16_t)
 * ============================================================================ */

/* Returns 1 if newly inserted, 0 if already present */
static int port_set_insert(uint16_t *set, uint16_t port)
{
    if (port == 0) return 0;                  /* 0 is sentinel for empty */
    uint32_t idx = ((uint32_t)port * 2654435761u) % PORT_HASH_SIZE;
    for (uint32_t i = 0; i < PORT_HASH_SIZE; i++) {
        uint32_t pos = (idx + i) % PORT_HASH_SIZE;
        if (set[pos] == port) return 0;       /* already present */
        if (set[pos] == 0) { set[pos] = port; return 1; }
    }
    return 0; /* full */
}

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

fe_context_t *fe_init(const fe_config_t *cfg)
{
    fe_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    if (cfg)
        ctx->cfg = *cfg;
    else {
        fe_config_t def = FE_CONFIG_DEFAULT;
        ctx->cfg = def;
    }

    ctx->flow_buckets = calloc(ctx->cfg.flow_table_buckets, sizeof(flow_entry_t *));
    if (!ctx->flow_buckets) { free(ctx); return NULL; }

    ctx->src_bucket_count = ctx->cfg.flow_table_buckets / 4;
    if (ctx->src_bucket_count < 256) ctx->src_bucket_count = 256;
    ctx->src_buckets = calloc(ctx->src_bucket_count, sizeof(source_entry_t *));
    if (!ctx->src_buckets) { free(ctx->flow_buckets); free(ctx); return NULL; }

    return ctx;
}

void fe_destroy(fe_context_t *ctx)
{
    if (!ctx) return;

    /* free flow entries */
    for (uint32_t i = 0; i < ctx->cfg.flow_table_buckets; i++) {
        flow_entry_t *f = ctx->flow_buckets[i];
        while (f) {
            flow_entry_t *next = f->next;
            free(f);
            f = next;
        }
    }
    free(ctx->flow_buckets);

    /* free source entries */
    for (uint32_t i = 0; i < ctx->src_bucket_count; i++) {
        source_entry_t *s = ctx->src_buckets[i];
        while (s) {
            source_entry_t *next = s->next;
            free(s);
            s = next;
        }
    }
    free(ctx->src_buckets);
    free(ctx);
}

/* ============================================================================
 * INTERNAL: find or create flow
 * ============================================================================ */

static flow_entry_t *find_or_create_flow(fe_context_t *ctx,
                                          const sentinel_flow_key_t *key,
                                          int *is_new)
{
    uint32_t bucket = hash_flow_key(key, ctx->cfg.flow_table_buckets);
    flow_entry_t *f = ctx->flow_buckets[bucket];
    while (f) {
        if (memcmp(&f->key, key, sizeof(*key)) == 0) {
            *is_new = 0;
            return f;
        }
        f = f->next;
    }

    /* not found – allocate */
    f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    f->key = *key;
    f->next = ctx->flow_buckets[bucket];
    ctx->flow_buckets[bucket] = f;
    ctx->flow_count++;
    *is_new = 1;
    return f;
}

/* ============================================================================
 * INTERNAL: find or create source aggregate
 * ============================================================================ */

static source_entry_t *find_or_create_source(fe_context_t *ctx,
                                              uint32_t src_ip,
                                              int *is_new)
{
    uint32_t bucket = hash_u32(src_ip, ctx->src_bucket_count);
    source_entry_t *s = ctx->src_buckets[bucket];
    while (s) {
        if (s->src_ip == src_ip) { *is_new = 0; return s; }
        s = s->next;
    }

    s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->src_ip = src_ip;
    s->next = ctx->src_buckets[bucket];
    ctx->src_buckets[bucket] = s;
    ctx->src_count++;
    *is_new = 1;
    return s;
}

/* ============================================================================
 * INTERNAL: evict stale entries from ring (outside window)
 * ============================================================================ */

static void trim_ring(flow_entry_t *f, uint64_t window_ns)
{
    if (f->ring_count == 0 || f->last_timestamp_ns == 0) return;

    uint64_t cutoff = 0;
    if (f->last_timestamp_ns > window_ns)
        cutoff = f->last_timestamp_ns - window_ns;

    /* The ring is ordered by insertion (oldest first).
     * Head points to next-write; oldest is at (head - count) mod size. */
    while (f->ring_count > 0) {
        uint32_t oldest_idx = (f->ring_head + MAX_RING_SIZE - f->ring_count) % MAX_RING_SIZE;
        if (f->ring[oldest_idx].timestamp_ns < cutoff) {
            /* evict */
            f->ring_count--;
        } else {
            break;
        }
    }
}

/* ============================================================================
 * PACKET INGESTION
 * ============================================================================ */

int fe_ingest_packet(fe_context_t *ctx, const fe_packet_t *pkt)
{
    if (!ctx || !pkt) return -1;

    /* build flow key */
    sentinel_flow_key_t key;
    memset(&key, 0, sizeof(key));
    key.src_ip   = pkt->src_ip;
    key.dst_ip   = pkt->dst_ip;
    key.src_port = pkt->src_port;
    key.dst_port = pkt->dst_port;
    key.protocol = pkt->protocol;

    int is_new_flow = 0;
    flow_entry_t *f = find_or_create_flow(ctx, &key, &is_new_flow);
    if (!f) return -1;

    /* update source aggregate */
    int is_new_src = 0;
    source_entry_t *src = find_or_create_source(ctx, pkt->src_ip, &is_new_src);
    if (src) {
        if (is_new_flow) src->total_flows++;
        src->total_packets++;
        src->total_bytes += pkt->payload_len;
        if (is_new_src) src->first_seen_ns = pkt->timestamp_ns;
        src->last_seen_ns = pkt->timestamp_ns;
    }

    /* initialise window start */
    if (f->window_start_ns == 0)
        f->window_start_ns = pkt->timestamp_ns;

    /* trim ring */
    uint64_t window_ns = (uint64_t)ctx->cfg.window_sec * NS_PER_SEC;
    f->last_timestamp_ns = pkt->timestamp_ns;
    trim_ring(f, window_ns);

    /* push into ring */
    pkt_record_t *rec = &f->ring[f->ring_head];
    rec->timestamp_ns = pkt->timestamp_ns;
    rec->payload_len  = pkt->payload_len;
    rec->ttl          = pkt->ttl;
    rec->tcp_flags    = pkt->tcp_flags;
    rec->src_port     = pkt->src_port;
    rec->dst_port     = pkt->dst_port;

    f->ring_head = (f->ring_head + 1) % MAX_RING_SIZE;
    if (f->ring_count < MAX_RING_SIZE) f->ring_count++;

    /* update counters */
    f->total_packets++;
    f->total_bytes += pkt->payload_len;

    /* TCP flags */
    if (pkt->tcp_flags & FE_TCP_SYN) f->syn_count++;
    if (pkt->tcp_flags & FE_TCP_ACK) f->ack_count++;
    if (pkt->tcp_flags & FE_TCP_FIN) f->fin_count++;
    if (pkt->tcp_flags & FE_TCP_RST) f->rst_count++;
    if (pkt->tcp_flags & FE_TCP_PSH) f->psh_count++;

    /* port tracking */
    if (port_set_insert(f->src_ports_seen, pkt->src_port))
        f->unique_src_ports++;
    if (port_set_insert(f->dst_ports_seen, pkt->dst_port))
        f->unique_dst_ports++;

    /* remember last key */
    ctx->last_key   = key;
    ctx->last_valid = 1;

    return 0;
}

/* ============================================================================
 * INTERNAL: compute Shannon entropy of uint16 array (port distribution)
 * ============================================================================ */

static double compute_port_entropy(const pkt_record_t *ring, uint32_t head,
                                   uint32_t count, int use_src)
{
    if (count == 0) return 0.0;

    /* count frequencies in a small hash map */
    #define ENT_BUCKETS 2048
    struct { uint16_t port; uint32_t freq; } table[ENT_BUCKETS];
    memset(table, 0, sizeof(table));
    uint32_t distinct = 0;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t idx = (head + MAX_RING_SIZE - count + i) % MAX_RING_SIZE;
        uint16_t port = use_src ? ring[idx].src_port : ring[idx].dst_port;
        uint32_t h = ((uint32_t)port * 2654435761u) % ENT_BUCKETS;
        int placed = 0;
        for (uint32_t j = 0; j < ENT_BUCKETS; j++) {
            uint32_t pos = (h + j) % ENT_BUCKETS;
            if (table[pos].freq == 0) {
                table[pos].port = port;
                table[pos].freq = 1;
                distinct++;
                placed = 1;
                break;
            }
            if (table[pos].port == port) {
                table[pos].freq++;
                placed = 1;
                break;
            }
        }
        (void)placed;
    }

    double entropy = 0.0;
    double n = (double)count;
    for (uint32_t i = 0; i < ENT_BUCKETS; i++) {
        if (table[i].freq > 0) {
            double p = (double)table[i].freq / n;
            entropy -= p * log2(p);
        }
    }
    return entropy;
    #undef ENT_BUCKETS
}

/* ============================================================================
 * INTERNAL: compute payload byte entropy over the ring payload_len values
 * We approximate this using the distribution of payload sizes.
 * ============================================================================ */

static double compute_size_entropy(const pkt_record_t *ring, uint32_t head,
                                   uint32_t count)
{
    if (count == 0) return 0.0;

    /* bucket by payload_len modulo 256 */
    uint32_t buckets[256];
    memset(buckets, 0, sizeof(buckets));
    for (uint32_t i = 0; i < count; i++) {
        uint32_t idx = (head + MAX_RING_SIZE - count + i) % MAX_RING_SIZE;
        uint8_t b = (uint8_t)(ring[idx].payload_len & 0xFF);
        buckets[b]++;
    }
    double entropy = 0.0;
    double n = (double)count;
    for (int i = 0; i < 256; i++) {
        if (buckets[i] > 0) {
            double p = (double)buckets[i] / n;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

/* ============================================================================
 * FEATURE EXTRACTION (per-flow)
 * ============================================================================ */

int fe_extract_flow(fe_context_t *ctx,
                    const sentinel_flow_key_t *key,
                    sentinel_feature_vector_t *out)
{
    if (!ctx || !key || !out) return -1;
    memset(out, 0, sizeof(*out));

    uint32_t bucket = hash_flow_key(key, ctx->cfg.flow_table_buckets);
    flow_entry_t *f = ctx->flow_buckets[bucket];
    while (f) {
        if (memcmp(&f->key, key, sizeof(*key)) == 0) break;
        f = f->next;
    }
    if (!f) return -1;

    /* trim before extraction */
    uint64_t window_ns = (uint64_t)ctx->cfg.window_sec * NS_PER_SEC;
    trim_ring(f, window_ns);

    uint32_t n = f->ring_count;

    /* identity */
    out->src_ip   = key->src_ip;
    out->dst_ip   = key->dst_ip;
    out->src_port = key->src_port;
    out->dst_port = key->dst_port;
    out->protocol = key->protocol;

    /* timing */
    if (n > 0) {
        uint32_t oldest = (f->ring_head + MAX_RING_SIZE - n) % MAX_RING_SIZE;
        out->window_start_ns = f->ring[oldest].timestamp_ns;
        uint32_t newest = (f->ring_head + MAX_RING_SIZE - 1) % MAX_RING_SIZE;
        out->window_end_ns = f->ring[newest].timestamp_ns;
    } else {
        out->window_start_ns = f->window_start_ns;
        out->window_end_ns   = f->last_timestamp_ns;
    }
    if (out->window_end_ns > out->window_start_ns)
        out->window_duration_sec = (double)(out->window_end_ns - out->window_start_ns) / 1e9;
    else
        out->window_duration_sec = 0.001; /* avoid div/0 */

    /* volume */
    out->packet_count = n;
    uint64_t bytes = 0;
    double   sum_size = 0.0, sum_size2 = 0.0;
    double   sum_ttl = 0.0, sum_ttl2 = 0.0;
    uint8_t  min_ttl = 255, max_ttl = 0;
    uint32_t syn_w = 0, ack_w = 0, fin_w = 0, rst_w = 0, psh_w = 0;

    /* inter-arrival times */
    double   sum_iat = 0.0, sum_iat2 = 0.0;
    double   min_iat = 1e18, max_iat = 0.0;
    uint64_t prev_ts = 0;
    uint32_t iat_count = 0;

    for (uint32_t i = 0; i < n; i++) {
        uint32_t idx = (f->ring_head + MAX_RING_SIZE - n + i) % MAX_RING_SIZE;
        pkt_record_t *r = &f->ring[idx];

        bytes += r->payload_len;
        sum_size  += r->payload_len;
        sum_size2 += (double)r->payload_len * r->payload_len;

        sum_ttl  += r->ttl;
        sum_ttl2 += (double)r->ttl * r->ttl;
        if (r->ttl < min_ttl) min_ttl = r->ttl;
        if (r->ttl > max_ttl) max_ttl = r->ttl;

        if (r->tcp_flags & FE_TCP_SYN) syn_w++;
        if (r->tcp_flags & FE_TCP_ACK) ack_w++;
        if (r->tcp_flags & FE_TCP_FIN) fin_w++;
        if (r->tcp_flags & FE_TCP_RST) rst_w++;
        if (r->tcp_flags & FE_TCP_PSH) psh_w++;

        if (prev_ts > 0 && r->timestamp_ns > prev_ts) {
            double iat = (double)(r->timestamp_ns - prev_ts) / 1000.0; /* us */
            sum_iat  += iat;
            sum_iat2 += iat * iat;
            if (iat < min_iat) min_iat = iat;
            if (iat > max_iat) max_iat = iat;
            iat_count++;
        }
        prev_ts = r->timestamp_ns;
    }

    out->byte_count = bytes;
    if (out->window_duration_sec > 0.0) {
        out->packets_per_second = (double)n / out->window_duration_sec;
        out->bytes_per_second   = (double)bytes / out->window_duration_sec;
    }

    if (n > 0) {
        out->avg_packet_size = sum_size / n;
        double var = (sum_size2 / n) - (out->avg_packet_size * out->avg_packet_size);
        out->stddev_packet_size = var > 0 ? sqrt(var) : 0.0;

        out->avg_ttl = sum_ttl / n;
        var = (sum_ttl2 / n) - (out->avg_ttl * out->avg_ttl);
        out->stddev_ttl = var > 0 ? sqrt(var) : 0.0;
        out->min_ttl = min_ttl;
        out->max_ttl = max_ttl;
    }

    /* TCP flag features */
    out->syn_count = syn_w;
    out->ack_count = ack_w;
    out->fin_count = fin_w;
    out->rst_count = rst_w;
    out->psh_count = psh_w;
    if (n > 0) {
        out->syn_ratio = (double)syn_w / n;
        out->fin_ratio = (double)fin_w / n;
        out->rst_ratio = (double)rst_w / n;
    }

    /* entropy features */
    out->src_port_entropy     = compute_port_entropy(f->ring, f->ring_head, n, 1);
    out->dst_port_entropy     = compute_port_entropy(f->ring, f->ring_head, n, 0);
    out->payload_byte_entropy = compute_size_entropy(f->ring, f->ring_head, n);

    /* diversity */
    out->unique_src_ports = f->unique_src_ports;
    out->unique_dst_ports = f->unique_dst_ports;

    /* IAT features */
    if (iat_count > 0) {
        out->avg_iat_us    = sum_iat / iat_count;
        double var = (sum_iat2 / iat_count) - (out->avg_iat_us * out->avg_iat_us);
        out->stddev_iat_us = var > 0 ? sqrt(var) : 0.0;
        out->min_iat_us    = min_iat;
        out->max_iat_us    = max_iat;
    }

    /* source aggregates */
    int dummy;
    source_entry_t *s = find_or_create_source(ctx, key->src_ip, &dummy);
    if (s) {
        out->src_total_flows   = s->total_flows;
        out->src_total_packets = s->total_packets;
        if (s->last_seen_ns > s->first_seen_ns) {
            double src_dur = (double)(s->last_seen_ns - s->first_seen_ns) / 1e9;
            out->src_packets_per_second = (double)s->total_packets / (src_dur > 0.001 ? src_dur : 0.001);
        }
    }

    return 0;
}

/* ============================================================================
 * SOURCE-AGGREGATE EXTRACTION
 * ============================================================================ */

int fe_extract_source(fe_context_t *ctx, uint32_t src_ip,
                      sentinel_feature_vector_t *out)
{
    if (!ctx || !out) return -1;
    memset(out, 0, sizeof(*out));

    int dummy;
    source_entry_t *s = find_or_create_source(ctx, src_ip, &dummy);
    if (!s || s->total_packets == 0) return -1;

    out->src_ip           = src_ip;
    out->src_total_flows  = s->total_flows;
    out->src_total_packets = s->total_packets;

    if (s->last_seen_ns > s->first_seen_ns) {
        out->window_start_ns    = s->first_seen_ns;
        out->window_end_ns      = s->last_seen_ns;
        out->window_duration_sec = (double)(s->last_seen_ns - s->first_seen_ns) / 1e9;
        if (out->window_duration_sec > 0.001)
            out->src_packets_per_second = (double)s->total_packets / out->window_duration_sec;
    }

    /* walk all flows from this source to aggregate features */
    uint64_t total_bytes = 0;
    uint32_t total_syn = 0, total_rst = 0;
    for (uint32_t i = 0; i < ctx->cfg.flow_table_buckets; i++) {
        flow_entry_t *f = ctx->flow_buckets[i];
        while (f) {
            if (f->key.src_ip == src_ip) {
                total_bytes += f->total_bytes;
                total_syn   += f->syn_count;
                total_rst   += f->rst_count;
            }
            f = f->next;
        }
    }
    out->byte_count = total_bytes;
    out->syn_count  = total_syn;
    out->rst_count  = total_rst;
    if (s->total_packets > 0) {
        out->syn_ratio = (double)total_syn / s->total_packets;
        out->rst_ratio = (double)total_rst / s->total_packets;
    }

    return 0;
}

/* ============================================================================
 * CONVENIENCE: extract features for last-ingested packet's flow
 * ============================================================================ */

int fe_extract_last(fe_context_t *ctx, sentinel_feature_vector_t *out)
{
    if (!ctx || !ctx->last_valid) return -1;
    return fe_extract_flow(ctx, &ctx->last_key, out);
}

/* ============================================================================
 * GARBAGE COLLECTION
 * ============================================================================ */

int fe_gc(fe_context_t *ctx)
{
    if (!ctx) return -1;

    uint64_t window_ns = (uint64_t)ctx->cfg.window_sec * NS_PER_SEC;
    uint64_t now = 0;

    /* find most recent timestamp across all flows */
    for (uint32_t i = 0; i < ctx->cfg.flow_table_buckets; i++) {
        flow_entry_t *f = ctx->flow_buckets[i];
        while (f) {
            if (f->last_timestamp_ns > now) now = f->last_timestamp_ns;
            f = f->next;
        }
    }
    if (now == 0) return 0;

    uint64_t cutoff = (now > window_ns * 3) ? (now - window_ns * 3) : 0;
    int evicted = 0;

    for (uint32_t i = 0; i < ctx->cfg.flow_table_buckets; i++) {
        flow_entry_t **pp = &ctx->flow_buckets[i];
        while (*pp) {
            flow_entry_t *f = *pp;
            if (f->last_timestamp_ns < cutoff) {
                *pp = f->next;
                free(f);
                ctx->flow_count--;
                evicted++;
            } else {
                pp = &f->next;
            }
        }
    }

    return evicted;
}

/* ============================================================================
 * ACCESSORS
 * ============================================================================ */

uint32_t fe_active_flows(const fe_context_t *ctx)
{
    return ctx ? ctx->flow_count : 0;
}

uint32_t fe_active_sources(const fe_context_t *ctx)
{
    return ctx ? ctx->src_count : 0;
}
