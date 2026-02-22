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

#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <math.h>
#include <stdio.h>
#include <time.h>
#include <netinet/in.h>

#include "feature_extractor.h"

/* ============================================================================
 * INTERNAL CONSTANTS
 * ============================================================================ */

#define MAX_RING_SIZE    128    /* Reduced from 4096 to allow 5M flows in ~10GB RAM; sufficient for 10s stats. */
#define PORT_HASH_SIZE   32     /* Reduced from 1024 to keep flow_entry compact. */
#define NS_PER_SEC       1000000000ULL

/* Entropy constants for sparse maps */
#define ENT_BUCKETS   4096
#define ENT_MAX_PROBE 64   /* Bounded linear probe to capture true entropy under collision-DoS. */
#define SIZE_BUCKETS 256

/* Interval-based extraction: avoid full-ring loop per packet at 10GbE. */
#define FE_EXTRACT_INTERVAL      5000   /* packets: extract every N packets per flow */
#define FE_EXTRACT_INTERVAL_NS   100000000ULL  /* 100ms wall-clock between extracts per flow */

/* Fixed slots per bucket: cache-coherent, no linked-list chase (Tier-1 slab). */
#define SLOTS_PER_BUCKET         4

/* Tombstone: preserves linear-probe chain so we don't lose flows after deletion. */
#define FLOW_SLOT_DELETED        ((flow_entry_t *)(uintptr_t)-1)

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

    /* ring in global slab (index = pool index); keeps flow_entry < 256B for cache. */
    uint32_t      ring_slot;      /* index into ctx->ring_slab [ring_slot * MAX_RING_SIZE .. ] */
    uint32_t      ring_head;      /* next write position */
    uint32_t      ring_count;    /* number of valid entries */

    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t window_start_ns;
    uint64_t last_timestamp_ns;

    /* l7 features */
    uint32_t http_request_count;
    uint32_t dns_query_count;
    uint32_t dns_response_count;   /* DNS responses (QR=1); not used for query entropy */
    uint64_t dns_tx_id_sum;
    uint64_t dns_qcount_sum;

    /* last threat score from decision engine (for eviction priority) */
    double   threat_score;

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

    /* interval-based extraction: avoid extract on every packet (10GbE survivability) */
    uint32_t packets_since_extract;
    uint64_t last_extract_ns;

    /* next only used when entry is on free_flow_head; slots hold in-use flows by index. */
    struct flow_entry *next;
    /* O(1) source aggregation: list of flows belonging to same source (no full-table scan). */
    struct flow_entry *next_for_source;
    struct flow_entry *prev_for_source;
    /* Slot index into ctx->flow_slots for O(1) unlink on source evict (no ghost flows). */
    uint32_t slot_index;
} __attribute__((aligned(64))) flow_entry_t;

#define RING_AT(ctx, f, i)  (&(ctx)->ring_slab[(f)->ring_slot * MAX_RING_SIZE + (i)])

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
    flow_entry_t *source_flow_list;  /* head of flows for this source (O(N_src) not O(table)) */
} __attribute__((aligned(64))) source_entry_t;

/* ============================================================================
 * CONTEXT
 * ============================================================================ */

struct fe_context {
    fe_config_t cfg;

    /* pre-allocated memory pools */
    flow_entry_t *flow_pool;
    uint32_t      flow_pool_next;
    
    source_entry_t *src_pool;
    uint32_t        src_pool_next;

    /* free list for GC */
    flow_entry_t *free_flow_head;

    /* flow slab: flow_table_buckets * SLOTS_PER_BUCKET slots (cache-coherent, no list chase) */
    flow_entry_t **flow_slots;
    uint32_t       flow_slots_cap;  /* flow_table_buckets * SLOTS_PER_BUCKET */
    uint32_t       flow_count;

    /* bitmap liveness: 1 bit per bucket; GC only scans buckets that were touched (no cache thrash). */
    uint64_t      *dirty_buckets;
    uint32_t       dirty_buckets_words;
    uint64_t       recent_max_timestamp_ns;  /* for cutoff; updated on ingest */

    /* source aggregate hash table */
    source_entry_t **src_buckets;
    source_entry_t  *src_free_head;  /* recycled sources (anti-spoofing: never leak pool) */
    uint32_t         src_count;
    uint32_t         src_bucket_count;

    /* last-ingested tracking (zero-lookup path: no hash/memcmp in should_extract/mark_extracted) */
    sentinel_flow_key_t last_key;
    int                  last_valid;
    flow_entry_t        *last_flow;
    /* bucket of slot where last flow lives (for dirty bitmap: mark actual placement with linear probing). */
    uint32_t             last_flow_bucket;

    /* Global ring slab: one MAX_RING_SIZE window per flow (avoids 69KB per flow_entry). */
    pkt_record_t *ring_slab;

    /* Jitter-free entropy sparse maps (generation counter based) */
    uint32_t entropy_gen;
    struct {
        uint32_t port_gen[ENT_BUCKETS];
        struct { uint16_t port; uint32_t freq; } port_table[ENT_BUCKETS];
        uint16_t port_dirty_idx[ENT_BUCKETS];
        uint32_t port_dirty_count;

        uint32_t size_gen[SIZE_BUCKETS];
        uint32_t size_freq[SIZE_BUCKETS];
        uint16_t size_dirty_idx[SIZE_BUCKETS];
        uint32_t size_dirty_count;
    } entropy_scratch;
};

/* ============================================================================
 * HASH HELPERS
 * ============================================================================ */

static uint32_t hash_flow_key(const sentinel_flow_key_t *k, uint32_t nbuckets)
{
    /* FNV-1a over the 13-byte 5-tuple + Murmur-style mixer for adversarial resilience. */
    const uint8_t *p = (const uint8_t *)k;
    uint32_t h = 2166136261u;
    for (int i = 0; i < (int)sizeof(*k); i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    /* Finalizer mixer to prevent deliberate collision attacks */
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    h ^= h >> 16;
    return h % nbuckets;
}

static uint32_t hash_u32(uint32_t val, uint32_t nbuckets)
{
    /* Thomas Wang's 32 bit Mix or Murmur-style mixer */
    val = (val ^ 61) ^ (val >> 16);
    val = val + (val << 3);
    val = val ^ (val >> 4);
    val = val * 0x27d4eb2d;
    val = val ^ (val >> 15);
    return val % nbuckets;
}

/* ============================================================================
 * PORT SET HELPERS  (open-address hash set on uint16_t)
 * ============================================================================ */

/* Returns 1 if newly inserted, 0 if already present or table full. No buffer overflow: probe count capped. */
static int port_set_insert(uint16_t *set, uint16_t port)
{
    if (port == 0) return 0;                  /* 0 is sentinel for empty */
    if (PORT_HASH_SIZE == 0) return 0;        /* guard: no table */
    uint32_t idx = ((uint32_t)port * 2654435761u) % PORT_HASH_SIZE;
    const uint32_t max_probes = (8 < PORT_HASH_SIZE) ? 8 : PORT_HASH_SIZE;
    for (uint32_t i = 0; i < max_probes; i++) {
        uint32_t pos = (idx + i) % PORT_HASH_SIZE;
        if (set[pos] == port) return 0;       /* already present */
        if (set[pos] == 0) { set[pos] = port; return 1; }
    }
    return 0; /* full: no empty slot in probe window */
}

/* Forward: used in fe_force_evict_weakest / find_or_create_flow / fe_gc before definition. */
static void unlink_flow_from_source(fe_context_t *ctx, flow_entry_t *f);
static void fe_force_evict_source(fe_context_t *ctx);

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

    /* Avoid division by zero and invalid allocs: enforce sane minima. */
    if (ctx->cfg.flow_table_buckets == 0)
        ctx->cfg.flow_table_buckets = 256;
    if (ctx->cfg.flow_table_buckets > 1024 * 1024)
        ctx->cfg.flow_table_buckets = 1024 * 1024;

    ctx->flow_slots_cap = ctx->cfg.flow_table_buckets * SLOTS_PER_BUCKET;
    ctx->flow_slots = calloc(ctx->flow_slots_cap, sizeof(flow_entry_t *));
    if (!ctx->flow_slots) { free(ctx); return NULL; }
    ctx->dirty_buckets_words = (ctx->cfg.flow_table_buckets + 63) / 64;
    ctx->dirty_buckets = calloc(ctx->dirty_buckets_words, sizeof(uint64_t));
    if (!ctx->dirty_buckets) { free(ctx->flow_slots); free(ctx); return NULL; }

    /* 0 means "unlimited": use one flow per slot so pool never overflows before table. */
    if (ctx->cfg.max_flows == 0)
        ctx->cfg.max_flows = ctx->flow_slots_cap;
    if (ctx->cfg.max_flows < 256)
        ctx->cfg.max_flows = 256;
    if (ctx->cfg.max_flows > 5000000)
        ctx->cfg.max_flows = 5000000;

    ctx->flow_pool = calloc(ctx->cfg.max_flows, sizeof(flow_entry_t));
    if (!ctx->flow_pool) { free(ctx->dirty_buckets); free(ctx->flow_slots); free(ctx); return NULL; }

    ctx->ring_slab = calloc((size_t)ctx->cfg.max_flows * MAX_RING_SIZE, sizeof(pkt_record_t));
    if (!ctx->ring_slab) { free(ctx->flow_pool); free(ctx->dirty_buckets); free(ctx->flow_slots); free(ctx); return NULL; }

    ctx->src_bucket_count = ctx->cfg.flow_table_buckets / 4;
    if (ctx->src_bucket_count < 256) ctx->src_bucket_count = 256;
    ctx->src_buckets = calloc(ctx->src_bucket_count, sizeof(source_entry_t *));
    if (!ctx->src_buckets) { free(ctx->ring_slab); free(ctx->dirty_buckets); free(ctx->flow_pool); free(ctx->flow_slots); free(ctx); return NULL; }

    ctx->src_pool = calloc(ctx->cfg.max_flows, sizeof(source_entry_t));
    if (!ctx->src_pool) { free(ctx->ring_slab); free(ctx->src_buckets); free(ctx->dirty_buckets); free(ctx->flow_pool); free(ctx->flow_slots); free(ctx); return NULL; }

    ctx->src_free_head = NULL;  /* recycled source list; calloc zeros it but explicit for pool-reset safety */
    ctx->entropy_gen = 1; /* start from 1 so 0-initialized sparse map is 'empty' */

    return ctx;
}

void fe_destroy(fe_context_t *ctx)
{
    if (!ctx) return;

    free(ctx->ring_slab);
    free(ctx->flow_pool);
    free(ctx->dirty_buckets);
    free(ctx->flow_slots);
    free(ctx->src_pool);
    free(ctx->src_buckets);
    free(ctx);
}

/* ============================================================================
 * INTERNAL: force-evict the weakest flow (pool saturation recovery)
 * ============================================================================ */
static void fe_force_evict_weakest(fe_context_t *ctx)
{
    /*
     * Evict the flow with lowest eviction_priority (slab: scan slots, no list chase).
     * Scan up to 64 buckets * SLOTS_PER_BUCKET slots to bound latency.
     */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    uint32_t start = (uint32_t)(rand() % (int)ctx->flow_slots_cap);
    flow_entry_t *weakest = NULL;
    uint32_t weakest_slot_idx = 0;
    double lowest_priority = 1e18;
    uint32_t to_scan = 64 * SLOTS_PER_BUCKET;
    if (to_scan > ctx->flow_slots_cap) to_scan = ctx->flow_slots_cap;

    for (uint32_t i = 0; i < to_scan; i++) {
        uint32_t idx = (start + i) % ctx->flow_slots_cap;
        flow_entry_t *f = ctx->flow_slots[idx];
        if (!f || f == FLOW_SLOT_DELETED) continue;
        double relative_age_sec = (double)(now_ns - f->last_timestamp_ns) / 1e9;
        if (relative_age_sec < 0.0) relative_age_sec = 0.0;
        double eviction_score = (f->threat_score * 100.0) - (relative_age_sec * 0.1);
        if (!weakest || eviction_score < lowest_priority) {
            weakest = f;
            weakest_slot_idx = idx;
            lowest_priority = eviction_score;
        }
    }

    if (weakest) {
        if (ctx->last_flow == weakest) {
            ctx->last_flow = NULL;
            ctx->last_valid = 0;
        }
        unlink_flow_from_source(ctx, weakest);
        ctx->flow_slots[weakest_slot_idx] = FLOW_SLOT_DELETED;
        weakest->next = ctx->free_flow_head;
        ctx->free_flow_head = weakest;
        ctx->flow_count--;
    }
}

/* ============================================================================
 * INTERNAL: force-evict a source IPaggregate (pool saturation recovery)
 * ============================================================================ */
#define EVICT_SAMPLE_BUCKETS 8  /* O(1) eviction; avoids full table scans. */

static void fe_force_evict_source(fe_context_t *ctx)
{
    uint32_t start = (uint32_t)(rand() % (int)ctx->src_bucket_count);
    source_entry_t *weakest = NULL;
    source_entry_t **weakest_ptr = NULL;
    uint64_t min_packets = 0xFFFFFFFFFFFFFFFFULL;
    uint32_t min_flows = 0xFFFFFFFFu;
    uint32_t to_scan = EVICT_SAMPLE_BUCKETS;
    if (to_scan > ctx->src_bucket_count) to_scan = ctx->src_bucket_count;

    for (uint32_t i = 0; i < to_scan; i++) {
        uint32_t bucket = (start + i) % ctx->src_bucket_count;
        source_entry_t **s_ptr = &ctx->src_buckets[bucket];
        while (*s_ptr) {
            source_entry_t *s = *s_ptr;
            if (s->total_packets < min_packets ||
                (s->total_packets == min_packets && s->total_flows < min_flows)) {
                min_packets = s->total_packets;
                min_flows = s->total_flows;
                weakest = s;
                weakest_ptr = s_ptr;
            }
            s_ptr = &s->next;
        }
    }

    /* If no victim in sample, evict head of first non-empty bucket (bounded fallback). */
    if (weakest == NULL && ctx->src_count > 0) {
        for (uint32_t i = 0; i < to_scan; i++) {
            uint32_t bucket = (start + i) % ctx->src_bucket_count;
            if (ctx->src_buckets[bucket]) {
                weakest = ctx->src_buckets[bucket];
                weakest_ptr = &ctx->src_buckets[bucket];
                break;
            }
        }
    }

    if (weakest) {
        /* Unlink each flow from source list AND from flow_slots (no ghost flows). */
        flow_entry_t *f = weakest->source_flow_list;
        while (f) {
            flow_entry_t *n = f->next_for_source;
            f->prev_for_source = NULL;
            f->next_for_source = NULL;
            /* Remove from main flow table so slot does not point to freed/recycled flow. */
            if (f->slot_index < ctx->flow_slots_cap)
                ctx->flow_slots[f->slot_index] = FLOW_SLOT_DELETED;
            f->next = ctx->free_flow_head;
            ctx->free_flow_head = f;
            ctx->flow_count--;
            f = n;
        }
        weakest->source_flow_list = NULL;
        *weakest_ptr = weakest->next;
        ctx->src_count--;
        /* Recycle slot: push onto free list so find_or_create_source can reuse (no pool leak). */
        weakest->next = ctx->src_free_head;
        ctx->src_free_head = weakest;
    }
}

/* ============================================================================
 * INTERNAL: find or create flow
 * ============================================================================ */

#define MAX_PROBE 64  /* Increased probe depth for better resilience under collision churn */

static flow_entry_t *find_or_create_flow(fe_context_t *ctx,
                                          const sentinel_flow_key_t *key,
                                          uint32_t preferred_hash,
                                          int *is_new)
{
    uint32_t hash = preferred_hash ? preferred_hash : hash_flow_key(key, 0xFFFFFFFF);
    uint32_t base = (hash % ctx->cfg.flow_table_buckets) * SLOTS_PER_BUCKET;
    uint32_t cap = ctx->flow_slots_cap;
    const uint32_t probe_limit = (MAX_PROBE < cap) ? MAX_PROBE : cap;

    /* Open-addressed linear probing: cap at MAX_PROBE to avoid full-table scan under attack. */
    uint32_t first_empty = cap;  /* sentinel: none found */
    for (uint32_t i = 0; i < probe_limit; i++) {
        uint32_t idx = (base + i) % cap;
        flow_entry_t *f = ctx->flow_slots[idx];
        if (f == NULL) {
            if (first_empty == cap) first_empty = idx;
            break;  /* end of probe chain */
        }
        if (f == FLOW_SLOT_DELETED) {
            /* Record first tombstone but DON'T stop; we must find EXISTING keys later in chain. */
            if (first_empty == cap) first_empty = idx;
            
            /* Maintenance: if next is null, current tombstone is useless; clear it. */
            uint32_t next_idx = (base + i + 1) % cap;
            if (ctx->flow_slots[next_idx] == NULL) {
                ctx->flow_slots[idx] = NULL;
                if (first_empty == idx) first_empty = idx; /* still valid to reuse */
                break;
            }
            continue;
        }
        if (memcmp(&f->key, key, sizeof(*key)) == 0) {
            ctx->last_flow_bucket = idx / SLOTS_PER_BUCKET;
            *is_new = 0;
            return f;
        }
    }

    /* first_empty was set when we hit first null in probe window; if still cap, evict weakest in window. */
    if (first_empty < cap) {
        flow_entry_t *f;
        if (!ctx->free_flow_head && ctx->flow_pool_next >= ctx->cfg.max_flows)
            fe_force_evict_weakest(ctx);
        if (ctx->free_flow_head) {
            f = ctx->free_flow_head;
            ctx->free_flow_head = f->next;
            memset(f, 0, sizeof(*f));
            f->ring_slot = (uint32_t)(f - ctx->flow_pool);
        } else if (ctx->flow_pool_next < ctx->cfg.max_flows) {
            f = &ctx->flow_pool[ctx->flow_pool_next++];
            f->ring_slot = (uint32_t)(f - ctx->flow_pool);
        } else {
            return NULL;
        }
        f->key = *key;
        f->slot_index = first_empty;
        ctx->flow_slots[first_empty] = f;
        ctx->flow_count++;
        ctx->last_flow_bucket = first_empty / SLOTS_PER_BUCKET;
        *is_new = 1;
        return f;
    }

    /* No empty in MAX_PROBE window: evict weakest within that window only (no O(cap) scan). */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    flow_entry_t *weakest = NULL;
    uint32_t evict_idx = 0;
    double lowest = 1e18;
    for (uint32_t i = 0; i < probe_limit; i++) {
        uint32_t idx = (base + i) % cap;
        flow_entry_t *c = ctx->flow_slots[idx];
        if (!c || c == FLOW_SLOT_DELETED) continue;
        double age_sec = (double)(now_ns - c->last_timestamp_ns) / 1e9;
        if (age_sec < 0.0) age_sec = 0.0;
        double score = (c->threat_score * 100.0) - (age_sec * 0.1);
        if (score < lowest) { lowest = score; weakest = c; evict_idx = idx; }
    }
    if (!weakest) return NULL;
    if (ctx->last_flow == weakest) { ctx->last_flow = NULL; ctx->last_valid = 0; }
    unlink_flow_from_source(ctx, weakest);
    ctx->flow_slots[evict_idx] = FLOW_SLOT_DELETED;
    weakest->next = ctx->free_flow_head;
    ctx->free_flow_head = weakest;
    ctx->flow_count--;
    memset(weakest, 0, sizeof(*weakest));
    weakest->ring_slot = (uint32_t)(weakest - ctx->flow_pool);
    weakest->key = *key;
    weakest->slot_index = evict_idx;
    ctx->flow_slots[evict_idx] = weakest;
    ctx->flow_count++;
    ctx->last_flow_bucket = evict_idx / SLOTS_PER_BUCKET;
    *is_new = 1;
    return weakest;
}

#define MAX_SOURCE_CHAIN 8  /* Cap chain walk; evict weakest in bucket if exceeded (hash collision DoS). */

/* Evict the weakest source among the first MAX_SOURCE_CHAIN nodes in the bucket (O(1) bound). */
static void evict_weakest_in_bucket(fe_context_t *ctx, uint32_t bucket)
{
    source_entry_t **prev = &ctx->src_buckets[bucket];
    source_entry_t *s = *prev;
    source_entry_t *weakest = NULL;
    source_entry_t **weakest_prev = NULL;
    uint64_t min_packets = 0xFFFFFFFFFFFFFFFFULL;
    uint32_t step = 0;
    while (s && step < MAX_SOURCE_CHAIN) {
        if (s->total_packets < min_packets) {
            min_packets = s->total_packets;
            weakest = s;
            weakest_prev = prev;
        }
        prev = &s->next;
        s = s->next;
        step++;
    }
    if (!weakest) return;
    /* Unlink weakest and recycle its flows into free_flow_head; recycle source into src_free_head. */
    flow_entry_t *f = weakest->source_flow_list;
    while (f) {
        flow_entry_t *n = f->next_for_source;
        f->prev_for_source = f->next_for_source = NULL;
        if (f->slot_index < ctx->flow_slots_cap)
            ctx->flow_slots[f->slot_index] = FLOW_SLOT_DELETED;
        f->next = ctx->free_flow_head;
        ctx->free_flow_head = f;
        ctx->flow_count--;
        f = n;
    }
    weakest->source_flow_list = NULL;
    *weakest_prev = weakest->next;
    ctx->src_count--;
    weakest->next = ctx->src_free_head;
    ctx->src_free_head = weakest;
}

/* ============================================================================
 * INTERNAL: find or create source aggregate
 * ============================================================================ */

static source_entry_t *find_or_create_source(fe_context_t *ctx,
                                              uint32_t src_ip,
                                              uint32_t preferred_hash,
                                              int *is_new)
{
    uint32_t hash = preferred_hash ? preferred_hash : hash_u32(src_ip, 0xFFFFFFFF);
    uint32_t bucket = hash % ctx->src_bucket_count;
    source_entry_t **prev = &ctx->src_buckets[bucket];
    source_entry_t *s = *prev;
    uint32_t step = 0;

    while (s && step < MAX_SOURCE_CHAIN) {
        if (s->src_ip == src_ip) { *is_new = 0; return s; }
        prev = &s->next;
        s = s->next;
        step++;
    }

    if (s) {
        /* Chain longer than MAX_SOURCE_CHAIN: evict weakest in this bucket, then insert new at head. */
        evict_weakest_in_bucket(ctx, bucket);
        prev = &ctx->src_buckets[bucket];
        s = *prev;
    }

    if (ctx->src_free_head == NULL && ctx->src_pool_next >= ctx->cfg.max_flows) {
        fe_force_evict_source(ctx);
    }

    if (ctx->src_free_head) {
        s = ctx->src_free_head;
        ctx->src_free_head = s->next;
        memset(s, 0, sizeof(*s));
        s->total_flows = 0;
        s->total_packets = 0;
        s->total_bytes = 0;
    } else if (ctx->src_pool_next < ctx->cfg.max_flows) {
        s = &ctx->src_pool[ctx->src_pool_next++];
    } else {
        return NULL;
    }
    s->src_ip = src_ip;
    s->source_flow_list = NULL;
    s->next = ctx->src_buckets[bucket];
    ctx->src_buckets[bucket] = s;
    ctx->src_count++;
    *is_new = 1;
    return s;
}

/* Lookup source by IP only (no create). For unlink on evict. */
static source_entry_t *find_source(fe_context_t *ctx, uint32_t src_ip)
{
    uint32_t bucket = hash_u32(src_ip, 0xFFFFFFFF) % ctx->src_bucket_count;
    source_entry_t *s = ctx->src_buckets[bucket];
    while (s) {
        if (s->src_ip == src_ip) return s;
        s = s->next;
    }
    return NULL;
}

/* Unlink flow from its source's list (O(1) with prev). Call before evicting. */
static void unlink_flow_from_source(fe_context_t *ctx, flow_entry_t *f)
{
    source_entry_t *src = find_source(ctx, f->key.src_ip);
    if (!src) return;
    if (f->prev_for_source)
        f->prev_for_source->next_for_source = f->next_for_source;
    else
        src->source_flow_list = f->next_for_source;
    if (f->next_for_source)
        f->next_for_source->prev_for_source = f->prev_for_source;
    f->next_for_source = f->prev_for_source = NULL;
    if (src->total_flows > 0) src->total_flows--;
}

/* ============================================================================
 * INTERNAL: evict stale entries from ring (outside window)
 * ============================================================================ */

static void trim_ring(fe_context_t *ctx, flow_entry_t *f, uint64_t window_ns)
{
    if (f->ring_count == 0 || f->last_timestamp_ns == 0) return;

    if (f->last_timestamp_ns > window_ns &&
        RING_AT(ctx, f, (f->ring_head + MAX_RING_SIZE - 1) % MAX_RING_SIZE)->timestamp_ns < (f->last_timestamp_ns - window_ns)) {
        f->ring_count = 0;
        f->ring_head = 0;
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

    /* Hash Sanity: trust the pre-calculated software FNV-1a from the pipeline parser. */
    uint32_t h = pkt->hw_hash;
    int is_new_flow = 0;
    flow_entry_t *f = find_or_create_flow(ctx, &key, h, &is_new_flow);
    if (!f) return -1;

    /* Bitmap liveness: mark the bucket where this flow lives (linear probing may place in different bucket). */
    {
        uint32_t bucket = ctx->last_flow_bucket;
        uint32_t w = bucket / 64;
        if (w < ctx->dirty_buckets_words)
            ctx->dirty_buckets[w] |= 1ULL << (bucket % 64);
    }
    if (pkt->timestamp_ns > ctx->recent_max_timestamp_ns)
        ctx->recent_max_timestamp_ns = pkt->timestamp_ns;

    /* update source aggregate */
    int is_new_src = 0;
    source_entry_t *src = find_or_create_source(ctx, pkt->src_ip, 0, &is_new_src);
    if (src) {
        if (is_new_flow) {
            src->total_flows++;
            /* O(1) telemetry: link flow into source list so fe_extract_source only walks this list. */
            f->next_for_source = src->source_flow_list;
            f->prev_for_source = NULL;
            if (src->source_flow_list) src->source_flow_list->prev_for_source = f;
            src->source_flow_list = f;
        }
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
    trim_ring(ctx, f, window_ns);

    /* push into ring (slab-indexed by ring_slot) */
    pkt_record_t *rec = RING_AT(ctx, f, f->ring_head);
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
    f->packets_since_extract++;

    /* TRUE LAYER 7 PARSING */
    if (pkt->payload && pkt->payload_len > 4) {
        if (pkt->protocol == 6) { /* TCP -> HTTP Search */
            /* Look for standard HTTP METHODS at start of payload */
            if (memcmp(pkt->payload, "GET ", 4) == 0 ||
                memcmp(pkt->payload, "POST", 4) == 0 ||
                memcmp(pkt->payload, "PUT ", 4) == 0 ||
                memcmp(pkt->payload, "HEAD", 4) == 0 ||
                memcmp(pkt->payload, "HTTP", 4) == 0) {
                f->http_request_count++;
            }
        } 
        else if (pkt->protocol == 17 && (ntohs(pkt->dst_port) == 53 || ntohs(pkt->src_port) == 53)) {
            /* UDP 53: only treat as query if QR bit (byte 2 MSB) is 0; else count as response */
            if (pkt->payload_len >= 3) {
                uint8_t flags = pkt->payload[2];
                if ((flags & 0x80) == 0) {
                    /* DNS Query (QR=0): accumulate for entropy */
                    f->dns_query_count++;
                    if (pkt->payload_len >= 6) {
                        uint16_t tx_id   = (uint16_t)((pkt->payload[0] << 8) | pkt->payload[1]);
                        uint16_t q_count = (uint16_t)((pkt->payload[4] << 8) | pkt->payload[5]);
                        f->dns_tx_id_sum += (uint64_t)tx_id;
                        f->dns_qcount_sum += (uint32_t)q_count;
                    }
                } else {
                    /* DNS Response (QR=1): do not poison query metrics */
                    f->dns_response_count++;
                }
            }
        }
    }

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

    /* remember last key and flow pointer (zero-lookup: fe_should_extract/fe_mark_extracted use last_flow only) */
    ctx->last_key   = key;
    ctx->last_valid = 1;
    ctx->last_flow  = f;

    return 0;
}

/* ============================================================================
 * INTERNAL: compute Shannon entropy of uint16 array (port distribution)
 * ============================================================================ */

static double compute_port_entropy(fe_context_t *ctx, const pkt_record_t *ring, uint32_t head,
                                   uint32_t count, int use_src)
{
    if (count <= 1) return 0.0;

    /* Jitter-free sparse map: use generation counters instead of memset. */
    uint32_t gen = ctx->entropy_gen;
    uint32_t distinct = 0;
    ctx->entropy_scratch.port_dirty_count = 0;

    for (uint32_t i = 0; i < count; i++) {
        if (ctx->entropy_scratch.port_dirty_count >= ENT_BUCKETS)
            break;
        uint32_t idx = (head + MAX_RING_SIZE - count + i) % MAX_RING_SIZE;
        uint16_t port = use_src ? ring[idx].src_port : ring[idx].dst_port;
        uint32_t h = ((uint32_t)port * 2654435761u) % ENT_BUCKETS;
        uint32_t found = 0;
        for (uint32_t j = 0; j < ENT_MAX_PROBE && !found; j++) {
            uint32_t pos = (h + j) % ENT_BUCKETS;
            if (ctx->entropy_scratch.port_gen[pos] != gen) {
                ctx->entropy_scratch.port_gen[pos] = gen;
                ctx->entropy_scratch.port_table[pos].port = port;
                ctx->entropy_scratch.port_table[pos].freq = 1;
                ctx->entropy_scratch.port_dirty_idx[ctx->entropy_scratch.port_dirty_count++] = (uint16_t)pos;
                distinct++;
                found = 1;
            } else if (ctx->entropy_scratch.port_table[pos].port == port) {
                ctx->entropy_scratch.port_table[pos].freq++;
                found = 1;
            }
        }
    }

    /* Simpson's diversity index: 1 - D, where D = sum(n_i*(n_i-1))/(N*(N-1)).
     * Use uint64_t fixed-point math to avoid double division in hot-path. */
    uint64_t N = (uint64_t)count;
    uint64_t sum_sq = 0;
    for (uint32_t i = 0; i < ctx->entropy_scratch.port_dirty_count; i++) {
        uint32_t pos = ctx->entropy_scratch.port_dirty_idx[i];
        uint64_t f = (uint64_t)ctx->entropy_scratch.port_table[pos].freq;
        sum_sq += f * (f - 1);
    }
    
    /* Scale by 1,000,000 for precision */
    uint64_t divider = N * (N - 1);
    if (divider == 0) return 0.0;
    uint64_t D_scaled = (sum_sq * 1000000ULL) / divider;
    
    double D = (double)D_scaled / 1000000.0;
    return (D <= 1.0) ? (1.0 - D) : 0.0;
}

/* ============================================================================
 * INTERNAL: compute payload byte entropy over the ring payload_len values
 * We approximate this using the distribution of payload sizes.
 * ============================================================================ */

static double compute_size_entropy(fe_context_t *ctx, const pkt_record_t *ring, uint32_t head,
                                   uint32_t count)
{
    if (count <= 1) return 0.0;

    uint32_t gen = ctx->entropy_gen;
    ctx->entropy_scratch.size_dirty_count = 0;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t idx = (head + MAX_RING_SIZE - count + i) % MAX_RING_SIZE;
        uint8_t b = (uint8_t)(ring[idx].payload_len & 0xFF);
        if (ctx->entropy_scratch.size_gen[b] != gen) {
            ctx->entropy_scratch.size_gen[b] = gen;
            ctx->entropy_scratch.size_freq[b] = 1;
            /* Dense Indexing: track touched slots to avoid O(256) summation scan. */
            ctx->entropy_scratch.size_dirty_idx[ctx->entropy_scratch.size_dirty_count++] = (uint16_t)b;
        } else {
            ctx->entropy_scratch.size_freq[b]++;
        }
    }

    /* Simpson's diversity (fixed-point): 1 - D for payload-size distribution. */
    uint64_t N = (uint64_t)count;
    uint64_t sum_sq = 0;
    for (uint32_t i = 0; i < ctx->entropy_scratch.size_dirty_count; i++) {
        uint32_t b = ctx->entropy_scratch.size_dirty_idx[i];
        uint64_t f = (uint64_t)ctx->entropy_scratch.size_freq[b];
        sum_sq += f * (f - 1);
    }
    
    uint64_t divider = N * (N - 1);
    if (divider == 0) return 0.0;
    uint64_t D_scaled = (sum_sq * 1000000ULL) / divider;
    
    double D = (double)D_scaled / 1000000.0;
    return (D <= 1.0) ? (1.0 - D) : 0.0;
}

/* ============================================================================
 * FEATURE EXTRACTION (per-flow)
 * All 20 features are derived from the packet ring buffer and source state;
 * no hardcoded fallback values in core processing.
 * ============================================================================ */

int fe_extract_flow(fe_context_t *ctx,
                    const sentinel_flow_key_t *key,
                    sentinel_feature_vector_t *out)
{
    if (!ctx || !key || !out) return -1;
    memset(out, 0, sizeof(*out));

    uint32_t bucket = hash_flow_key(key, ctx->cfg.flow_table_buckets);
    uint32_t base = bucket * SLOTS_PER_BUCKET;
    uint32_t cap = ctx->flow_slots_cap;
    flow_entry_t *f = NULL;

    /* Probing Consistency: look across bounded linear probe chain. */
    for (uint32_t i = 0; i < MAX_PROBE; i++) {
        uint32_t idx = (base + i) % cap;
        flow_entry_t *c = ctx->flow_slots[idx];
        if (c == NULL) break; /* end of chain */
        if (c == FLOW_SLOT_DELETED) continue;
        if (memcmp(&c->key, key, sizeof(*key)) == 0) {
            f = c;
            break;
        }
    }
    if (!f) return -1;

    /* trim before extraction */
    uint64_t window_ns = (uint64_t)ctx->cfg.window_sec * NS_PER_SEC;
    trim_ring(ctx, f, window_ns);

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
        out->window_start_ns = RING_AT(ctx, f, oldest)->timestamp_ns;
        uint32_t newest = (f->ring_head + MAX_RING_SIZE - 1) % MAX_RING_SIZE;
        out->window_end_ns = RING_AT(ctx, f, newest)->timestamp_ns;
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
        pkt_record_t *r = RING_AT(ctx, f, idx);

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

    /* Generation wrap: never use gen==0 (collides with zero-initialized scratch). One-time reset. */
    if (ctx->entropy_gen == 0) {
        memset(ctx->entropy_scratch.port_gen, 0, sizeof(ctx->entropy_scratch.port_gen));
        memset(ctx->entropy_scratch.size_gen, 0, sizeof(ctx->entropy_scratch.size_gen));
        ctx->entropy_gen = 1;
    }
    /* entropy features */
    out->src_port_entropy     = compute_port_entropy(ctx, RING_AT(ctx, f, 0), f->ring_head, n, 1);
    out->dst_port_entropy     = compute_port_entropy(ctx, RING_AT(ctx, f, 0), f->ring_head, n, 0);
    out->payload_byte_entropy = compute_size_entropy(ctx, RING_AT(ctx, f, 0), f->ring_head, n);
    ctx->entropy_gen++;

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

    /* L7 parsing outcomes */
    out->http_request_count = f->http_request_count;
    out->dns_query_count    = f->dns_query_count;
    out->dns_tx_id_sum      = f->dns_tx_id_sum;
    out->dns_qcount_sum     = f->dns_qcount_sum;

    /* source aggregates */
    source_entry_t *s = find_source(ctx, key->src_ip);
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

    source_entry_t *s = find_source(ctx, src_ip);
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

    /* O(N_src): walk only this source's flow list (no full-table scan). */
    uint64_t total_bytes = 0;
    uint32_t total_syn = 0, total_rst = 0;
    for (flow_entry_t *f = s->source_flow_list; f; f = f->next_for_source) {
        total_bytes += f->total_bytes;
        total_syn   += f->syn_count;
        total_rst   += f->rst_count;
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
 * INTERVAL-BASED EXTRACTION (Zero-lookup: use ctx->last_flow only; no hash/memcmp)
 * now_ns is passed from pipeline (coarse heartbeat). Only call fe_extract_last when this returns 1.
 * ============================================================================ */

int fe_should_extract(fe_context_t *ctx, uint64_t now_ns)
{
    if (!ctx || !ctx->last_valid || !ctx->last_flow) return 0;
    flow_entry_t *f = ctx->last_flow;
    if (f->packets_since_extract >= FE_EXTRACT_INTERVAL) return 1;
    if (f->last_extract_ns == 0 || (now_ns - f->last_extract_ns) >= FE_EXTRACT_INTERVAL_NS)
        return 1;
    return 0;
}

void fe_mark_extracted(fe_context_t *ctx, uint64_t now_ns)
{
    if (!ctx || !ctx->last_valid || !ctx->last_flow) return;
    ctx->last_flow->packets_since_extract = 0;
    ctx->last_flow->last_extract_ns = now_ns;
}

/* ============================================================================
 * WRITEBACK: threat score for eviction priority
 * ============================================================================ */

void fe_writeback_threat(fe_context_t *ctx, const sentinel_flow_key_t *key, double score)
{
    if (!ctx || !key) return;
    uint32_t bucket = hash_flow_key(key, ctx->cfg.flow_table_buckets);
    uint32_t base = bucket * SLOTS_PER_BUCKET;
    uint32_t cap = ctx->flow_slots_cap;
    const uint32_t probe_limit = (MAX_PROBE < cap) ? MAX_PROBE : cap;

    /* Strict MAX_PROBE bounded search; no O(capacity) table scan. */
    for (uint32_t i = 0; i < probe_limit; i++) {
        uint32_t idx = (base + i) % cap;
        flow_entry_t *f = ctx->flow_slots[idx];
        if (f == NULL) break;
        if (f == FLOW_SLOT_DELETED) continue;
        if (memcmp(&f->key, key, sizeof(*key)) == 0) {
            f->threat_score = score;
            return;
        }
    }
}

/* ============================================================================
 * GARBAGE COLLECTION
 * ============================================================================ */

int fe_gc(fe_context_t *ctx)
{
    if (!ctx || !ctx->dirty_buckets) return -1;

    uint64_t window_ns = (uint64_t)ctx->cfg.window_sec * NS_PER_SEC;
    uint64_t now = ctx->recent_max_timestamp_ns;
    if (now == 0) return 0;

    uint64_t cutoff = (now > window_ns * 3) ? (now - window_ns * 3) : 0;
    int evicted = 0;

    /* Iterate only dirty buckets (bitmap liveness): no full-table scan, no cache thrash. */
    for (uint32_t w = 0; w < ctx->dirty_buckets_words; w++) {
        uint64_t bits = ctx->dirty_buckets[w];
        if (bits == 0) continue;
        ctx->dirty_buckets[w] = 0; /* clear after processing */

        while (bits) {
            uint32_t b = 0;
            for (; b < 64; b++) if (bits & (1ULL << b)) break;
            if (b >= 64) break;
            uint32_t bucket = w * 64 + b;
            if (bucket >= ctx->cfg.flow_table_buckets) break;
            bits &= ~(1ULL << b);

            uint32_t base = bucket * SLOTS_PER_BUCKET;
            for (uint32_t s = 0; s < SLOTS_PER_BUCKET; s++) {
                uint32_t i = base + s;
                flow_entry_t *f = ctx->flow_slots[i];
                if (!f || f == FLOW_SLOT_DELETED) continue;
                if (f->last_timestamp_ns < cutoff) {
                    if (ctx->last_flow == f) {
                        ctx->last_flow = NULL;
                        ctx->last_valid = 0;
                    }
                    unlink_flow_from_source(ctx, f);
                    ctx->flow_slots[i] = FLOW_SLOT_DELETED;
                    f->next = ctx->free_flow_head;
                    ctx->free_flow_head = f;
                    ctx->flow_count--;
                    evicted++;
                }
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

#define FE_TOP_SOURCES_CAP 4096

static void heapify_down(fe_top_source_t *heap, uint32_t n, uint32_t i)
{
    uint32_t smallest = i;
    uint32_t left = 2 * i + 1;
    uint32_t right = 2 * i + 2;

    if (left < n && heap[left].packets < heap[smallest].packets)
        smallest = left;
    if (right < n && heap[right].packets < heap[smallest].packets)
        smallest = right;

    if (smallest != i) {
        fe_top_source_t tmp = heap[i];
        heap[i] = heap[smallest];
        heap[smallest] = tmp;
        heapify_down(heap, n, smallest);
    }
}

uint32_t fe_get_top_sources(fe_context_t *ctx, fe_top_source_t *out, uint32_t max_count)
{
    if (!ctx || !out || max_count == 0) return 0;

    uint32_t n = 0;
    /* Use 'out' as the heap storage directly. */
    for (uint32_t i = 0; i < ctx->src_bucket_count; i++) {
        source_entry_t *s = ctx->src_buckets[i];
        while (s) {
            if (n < max_count) {
                out[n].src_ip     = s->src_ip;
                out[n].packets    = s->total_packets;
                out[n].bytes      = s->total_bytes;
                out[n].flow_count = s->total_flows;
                n++;
                if (n == max_count) {
                    /* Initial build of the min-heap. */
                    for (int j = (int)n / 2 - 1; j >= 0; j--)
                        heapify_down(out, n, (uint32_t)j);
                }
            } else if (s->total_packets > out[0].packets) {
                /* Replace root (smallest of the top N) and bubble down. */
                out[0].src_ip     = s->src_ip;
                out[0].packets    = s->total_packets;
                out[0].bytes      = s->total_bytes;
                out[0].flow_count = s->total_flows;
                heapify_down(out, n, 0);
            }
            s = s->next;
        }
    }

    if (n == 0) return 0;
    /* Zero-jitter: in-place heapsort (extract-min) then reverse for descending. O(N log K), no qsort. */
    for (uint32_t len = n; len > 1; len--) {
        fe_top_source_t tmp = out[0];
        out[0] = out[len - 1];
        out[len - 1] = tmp;
        heapify_down(out, len - 1, 0);
    }
    for (uint32_t i = 0, j = n - 1; i < j; i++, j--) {
        fe_top_source_t tmp = out[i];
        out[i] = out[j];
        out[j] = tmp;
    }
    return n;
}
