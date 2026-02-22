/*
 * Sentinel DDoS Core - Decision Engine Implementation
 *
 * Multi-model heuristic classification engine.
 *
 * Model 1 – EWMA Volume Anomaly:
 *   Maintains per-source EWMA baselines for pps and bps.
 *   A packet rate that deviates by > N sigma is anomalous.
 *
 * Model 2 – Entropy Analysis:
 *   Very low port entropy (single-port flood) or very high payload entropy
 *   (randomised attacks) are scored as anomalous.
 *
 * Model 3 – Protocol Ratio Analysis:
 *   High SYN/RST ratios without matching ACKs indicate SYN floods.
 *   Excessive ICMP or UDP pps triggers flood classification.
 *
 * Model 4 – Behavioral Profiling:
 *   Port-scan detection (many unique dst ports, few packets each).
 *   Excessive flow count from one source.
 *   LAND attack (src==dst), Smurf (broadcast dst), etc.
 *
 * The four scores are combined with configurable weights into a final
 * threat_score in [0,1].  The score is mapped to a verdict through
 * configurable thresholds.
 *
 * Thread-safety: NOT thread-safe.  One context per thread.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <math.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

#include "decision_engine.h"
#include "ml_model.h"
#include "../feedback/feedback.h"
#include <stdatomic.h>

/* ============================================================================
 * INTERNAL CONSTANTS
 * ============================================================================ */

#define BASELINE_BUCKETS 131072  /* Keep hash chains short under high-cardinality sources. */
#define LIST_BUCKETS     1024
#define MAX_BASELINES    1000000 /* hard cap: no unbounded calloc under spoofed-SYN OOM */
#define MAX_BASELINE_CHAIN 8     /* cap bucket chain walk: no unbounded loop at eviction */

/* ============================================================================
 * PER-SOURCE EWMA BASELINE
 * ============================================================================ */

typedef struct baseline_entry {
    uint32_t src_ip;
    /* EWMA of packets_per_second */
    double   ewma_pps;
    double   ewma_pps_var;   /* running variance for sigma */
    /* EWMA of bytes_per_second */
    double   ewma_bps;
    double   ewma_bps_var;
    uint32_t observations_pps;
    uint32_t observations_bps;
    struct baseline_entry *next;
} baseline_entry_t;

/* ============================================================================
 * IP LIST ENTRY (allow/deny)
 * ============================================================================ */

typedef struct ip_entry {
    uint32_t ip;
    struct ip_entry *next;
} ip_entry_t;

/* ============================================================================
 * CONTEXT
 * ============================================================================ */

struct de_context {
    de_thresholds_t cfg;

    baseline_entry_t **baselines;
    baseline_entry_t  *baseline_slab;   /* pre-allocated slab: zero hot-path alloc */
    baseline_entry_t  *baseline_free;   /* free list into slab */
    uint32_t           baseline_count;

    ip_entry_t **allowlist;
    ip_entry_t **denylist;
};

/* ============================================================================
 * HASH HELPER
 * ============================================================================ */

static uint32_t hash_ip(uint32_t ip, uint32_t nbuckets)
{
    ip = ((ip >> 16) ^ ip) * 0x45d9f3b;
    ip = ((ip >> 16) ^ ip) * 0x45d9f3b;
    ip = (ip >> 16) ^ ip;
    return ip % nbuckets;
}

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

de_context_t *de_init(const de_thresholds_t *cfg)
{
    de_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    if (cfg)
        ctx->cfg = *cfg;
    else {
        de_thresholds_t def = DE_THRESHOLDS_DEFAULT;
        ctx->cfg = def;
    }
    /* Division-by-zero guard: thresh and sigma must be > 0. */
    if (ctx->cfg.udp_pps_thresh <= 0) ctx->cfg.udp_pps_thresh = 50000;
    if (ctx->cfg.icmp_pps_thresh <= 0) ctx->cfg.icmp_pps_thresh = 5000;
    if (ctx->cfg.ewma_volume_sigma <= 0.0) ctx->cfg.ewma_volume_sigma = 3.0;

    ctx->baselines = calloc(BASELINE_BUCKETS, sizeof(baseline_entry_t *));
    ctx->allowlist = calloc(LIST_BUCKETS, sizeof(ip_entry_t *));
    ctx->denylist  = calloc(LIST_BUCKETS, sizeof(ip_entry_t *));

    if (!ctx->baselines || !ctx->allowlist || !ctx->denylist) {
        free(ctx->baselines);
        free(ctx->allowlist);
        free(ctx->denylist);
        free(ctx);
        return NULL;
    }

    /* Pre-allocate baseline slab: avoid dynamic allocation in hot path. */
    ctx->baseline_slab = calloc(MAX_BASELINES, sizeof(baseline_entry_t));
    if (!ctx->baseline_slab) {
        free(ctx->baselines);
        free(ctx->allowlist);
        free(ctx->denylist);
        free(ctx);
        return NULL;
    }
    ctx->baseline_free = &ctx->baseline_slab[0];
    for (uint32_t i = 0; i + 1 < MAX_BASELINES; i++)
        ctx->baseline_slab[i].next = &ctx->baseline_slab[i + 1];
    ctx->baseline_slab[MAX_BASELINES - 1].next = NULL;

    return ctx;
}

const de_thresholds_t *de_get_thresholds(const de_context_t *ctx)
{
    return ctx ? &ctx->cfg : NULL;
}

void de_apply_adjustments(de_context_t *ctx, const void *adj)
{
    if (!ctx || !adj) return;
    const fb_adjustments_t *a = (const fb_adjustments_t *)adj;
    if (!a->should_adjust) return;

    double allow = atomic_load_explicit(&ctx->cfg.score_allow_max, memory_order_relaxed);
    double rate  = atomic_load_explicit(&ctx->cfg.score_rate_limit, memory_order_relaxed);
    double drop  = atomic_load_explicit(&ctx->cfg.score_drop, memory_order_relaxed);

    allow += a->delta_allow_max;
    if (allow < 0.0) allow = 0.0;
    if (allow > 1.0) allow = 1.0;

    rate += a->delta_rate_limit;
    if (rate < allow) rate = allow;
    if (rate > 1.0)   rate = 1.0;

    drop += a->delta_drop;
    if (drop < rate) drop = rate;
    if (drop > 1.0)  drop = 1.0;

    atomic_store_explicit(&ctx->cfg.score_allow_max, allow, memory_order_release);
    atomic_store_explicit(&ctx->cfg.score_rate_limit, rate,  memory_order_release);
    atomic_store_explicit(&ctx->cfg.score_drop,       drop,  memory_order_release);
}

void de_destroy(de_context_t *ctx)
{
    if (!ctx) return;

    /* Baselines are in slab; no per-node free. */
    free(ctx->baseline_slab);
    ctx->baseline_slab = NULL;
    ctx->baseline_free = NULL;
    free(ctx->baselines);

    for (uint32_t i = 0; i < LIST_BUCKETS; i++) {
        ip_entry_t *e = ctx->allowlist[i];
        while (e) { ip_entry_t *n = e->next; free(e); e = n; }
        e = ctx->denylist[i];
        while (e) { ip_entry_t *n = e->next; free(e); e = n; }
    }
    free(ctx->allowlist);
    free(ctx->denylist);
    free(ctx);
}

/* ============================================================================
 * INTERNAL: IP list helpers
 * ============================================================================ */

static int ip_in_list(ip_entry_t **list, uint32_t ip)
{
    uint32_t b = hash_ip(ip, LIST_BUCKETS);
    ip_entry_t *e = list[b];
    while (e) { if (e->ip == ip) return 1; e = e->next; }
    return 0;
}

static int ip_list_add(ip_entry_t **list, uint32_t ip)
{
    if (ip_in_list(list, ip)) return 0;
    ip_entry_t *e = calloc(1, sizeof(*e));
    if (!e) return -1;
    e->ip = ip;
    uint32_t b = hash_ip(ip, LIST_BUCKETS);
    e->next = list[b];
    list[b] = e;
    return 0;
}

static int ip_list_remove(ip_entry_t **list, uint32_t ip)
{
    uint32_t b = hash_ip(ip, LIST_BUCKETS);
    ip_entry_t **pp = &list[b];
    while (*pp) {
        if ((*pp)->ip == ip) {
            ip_entry_t *rm = *pp;
            *pp = rm->next;
            free(rm);
            return 0;
        }
        pp = &(*pp)->next;
    }
    return -1;
}

int de_add_allowlist(de_context_t *ctx, uint32_t ip)  { return ip_list_add(ctx->allowlist, ip); }
int de_add_denylist(de_context_t *ctx, uint32_t ip)   { return ip_list_add(ctx->denylist, ip); }
int de_remove_allowlist(de_context_t *ctx, uint32_t ip){ return ip_list_remove(ctx->allowlist, ip); }
int de_remove_denylist(de_context_t *ctx, uint32_t ip) { return ip_list_remove(ctx->denylist, ip); }

/* ============================================================================
 * INTERNAL: find or create baseline
 * ============================================================================ */

static baseline_entry_t *get_baseline(de_context_t *ctx, uint32_t src_ip)
{
    uint32_t b = hash_ip(src_ip, BASELINE_BUCKETS);
    baseline_entry_t *bl = ctx->baselines[b];
    while (bl) {
        if (bl->src_ip == src_ip) return bl;
        bl = bl->next;
    }
    /* At cap: reuse a node from this bucket with bounded chain walk. */
    if (ctx->baseline_count >= MAX_BASELINES) {
        baseline_entry_t **prev = &ctx->baselines[b];
        baseline_entry_t *cur = *prev;
        uint32_t steps = 0;
        while (cur && cur->next && steps < MAX_BASELINE_CHAIN) {
            prev = &cur->next;
            cur = cur->next;
            steps++;
        }
        if (cur) {
            *prev = cur->next;
            memset(cur, 0, sizeof(*cur));
            cur->src_ip = src_ip;
            cur->next = ctx->baselines[b];
            ctx->baselines[b] = cur;
            return cur;  /* reused; count unchanged */
        }
        /* Chain longer than MAX_BASELINE_CHAIN: reuse head of bucket. */
        cur = ctx->baselines[b];
        if (cur) {
            ctx->baselines[b] = cur->next;
            memset(cur, 0, sizeof(*cur));
            cur->src_ip = src_ip;
            cur->next = ctx->baselines[b];
            ctx->baselines[b] = cur;
            return cur;
        }
        return NULL;
    }
    /* Take from pre-allocated slab (no allocation in hot path). */
    bl = ctx->baseline_free;
    if (!bl) return NULL;
    ctx->baseline_free = bl->next;
    memset(bl, 0, sizeof(*bl));
    bl->src_ip = src_ip;
    bl->next = ctx->baselines[b];
    ctx->baselines[b] = bl;
    ctx->baseline_count++;
    return bl;
}

/* ============================================================================
 * INTERNAL: update EWMA baseline and return z-score
 * ============================================================================ */

static double ewma_update_and_score(double value,
                                    double *ewma, double *ewma_var,
                                    uint32_t *obs, double smoothing)
{
    /* Sanitize float inputs to prevent NaN/Inf propagation. */
    if (isnan(value) || isinf(value))
        value = 0.0;

    if (*obs == 0) {
        *ewma = value;
        *ewma_var = 0.0;
        (*obs)++;
        return 0.0;
    }

    /* Drift protection: periodic variance decay. */
    if (*obs > 1000000000u) {
        *obs = 1000000u;
        *ewma_var *= 0.5;
        if (*ewma_var < 1e-18) *ewma_var = 0.0;
    }

    double prev = *ewma;
    *ewma = smoothing * value + (1.0 - smoothing) * prev;
    double diff = value - prev;
    *ewma_var = (1.0 - smoothing) * (*ewma_var) + smoothing * diff * diff;
    (*obs)++;

    /* Clamp outputs so NaN/Inf cannot propagate. */
    if (isnan(*ewma) || isinf(*ewma)) *ewma = 0.0;
    if (isnan(*ewma_var) || isinf(*ewma_var) || *ewma_var < 0.0) *ewma_var = 0.0;

    double sigma = sqrt(*ewma_var);
    if (sigma < 1e-9) return 0.0;
    double z = fabs(value - *ewma) / sigma;
    return (isnan(z) || isinf(z)) ? 0.0 : z;
}

/* ============================================================================
 * INTERNAL: clamp to [0, 1]
 * ============================================================================ */

static inline double clamp01(double x)
{
    if (isnan(x) || isinf(x)) return 0.0;
    if (x < 0.0) return 0.0;
    if (x > 1.0) return 1.0;
    return x;
}

/* Non-linear z-to-score: logistic mapping centered at 3 sigma to reduce false positives on noisy traffic. */
static inline double z_to_score(double z_ratio)
{
    if (z_ratio <= 0.0) return 0.0;
    if (z_ratio >= 6.0) return 1.0;
    return 1.0 / (1.0 + exp(-2.0 * (z_ratio - 3.0)));
}

/* ============================================================================
 * MODEL 1: VOLUME ANOMALY (EWMA)
 * ============================================================================ */

static double score_volume(de_context_t *ctx,
                           const sentinel_feature_vector_t *f,
                           baseline_entry_t *bl)
{
    double z_pps = ewma_update_and_score(f->packets_per_second,
                                          &bl->ewma_pps, &bl->ewma_pps_var,
                                          &bl->observations_pps, ctx->cfg.ewma_smoothing);
    double z_bps = ewma_update_and_score(f->bytes_per_second,
                                          &bl->ewma_bps, &bl->ewma_bps_var,
                                          &bl->observations_bps, ctx->cfg.ewma_smoothing);

    /* Non-linear mapping: z/sigma -> [0,1] via logistic (deviation not linear) */
    double sigma = ctx->cfg.ewma_volume_sigma;
    double s_pps = z_to_score(z_pps / sigma);
    double s_bps = z_to_score(z_bps / sigma);

    /* take the max as the volume score */
    return (s_pps > s_bps) ? s_pps : s_bps;
}

/* ============================================================================
 * MODEL 2: ENTROPY ANOMALY
 * ============================================================================ */

static double score_entropy(de_context_t *ctx,
                            const sentinel_feature_vector_t *f)
{
    double score = 0.0;

    /* Low src_port_entropy: many packets from same port -> flood */
    if (f->packet_count > 20 && f->src_port_entropy < ctx->cfg.entropy_low_thresh) {
        score += 0.4;
    }
    /* Low dst_port_entropy: single destination port -> targeted flood */
    if (f->packet_count > 20 && f->dst_port_entropy < ctx->cfg.entropy_low_thresh) {
        score += 0.2;
    }
    /* High payload entropy: randomised attack payloads */
    if (f->payload_byte_entropy > ctx->cfg.entropy_high_thresh) {
        score += 0.3;
    }
    /* Zero-size packets in bulk */
    if (f->packet_count > 100 && f->avg_packet_size < 1.0) {
        score += 0.3;
    }

    return clamp01(score);
}

/* ============================================================================
 * MODEL 3: PROTOCOL ANOMALY
 * ============================================================================ */

static double score_protocol(de_context_t *ctx,
                             const sentinel_feature_vector_t *f)
{
    double score = 0.0;

    /* TCP analysis */
    if (f->protocol == 6) { /* TCP */
        /* SYN flood: high SYN ratio without corresponding ACKs */
        if (f->syn_ratio > ctx->cfg.syn_ratio_thresh && f->packet_count > 10) {
            double syn_ack_imbalance = f->syn_ratio - ((double)f->ack_count / (f->packet_count > 0 ? f->packet_count : 1));
            score += clamp01(syn_ack_imbalance) * 0.7;
        }
        /* RST storm */
        if (f->rst_ratio > ctx->cfg.rst_ratio_thresh && f->packet_count > 10) {
            score += 0.3;
        }
        /* FIN storm */
        if (f->fin_ratio > 0.8 && f->packet_count > 10) {
            score += 0.2;
        }
    }

    /* UDP flood (guard division: thresh enforced > 0 in de_init). */
    if (f->protocol == 17 && ctx->cfg.udp_pps_thresh > 0 && f->packets_per_second > ctx->cfg.udp_pps_thresh) {
        score += clamp01(f->packets_per_second / (ctx->cfg.udp_pps_thresh * 5.0));
    }

    /* ICMP flood (guard division: thresh enforced > 0 in de_init). */
    if (f->protocol == 1 && ctx->cfg.icmp_pps_thresh > 0 && f->packets_per_second > ctx->cfg.icmp_pps_thresh) {
        score += clamp01(f->packets_per_second / (ctx->cfg.icmp_pps_thresh * 3.0));
    }

    /* DNS amplification: UDP port 53, large response sizes */
    if (f->protocol == 17 && ntohs(f->src_port) == 53 &&
        f->avg_packet_size > 512 && f->packets_per_second > 100) {
        score += 0.5;
    }

    /* NTP amplification: UDP port 123, large monlist responses */
    if (f->protocol == 17 && ntohs(f->src_port) == 123 &&
        f->avg_packet_size > 400 && f->packets_per_second > 100) {
        score += 0.5;
    }

    return clamp01(score);
}

/* ============================================================================
 * MODEL 4: BEHAVIORAL ANOMALY
 * ============================================================================ */

static double score_behavioral(de_context_t *ctx,
                               const sentinel_feature_vector_t *f)
{
    double score = 0.0;

    /* Port scan: many unique destination ports from one source */
    if (f->unique_dst_ports > ctx->cfg.port_scan_thresh) {
        score += clamp01((double)f->unique_dst_ports /
                         (ctx->cfg.port_scan_thresh * 5.0));
    }

    /* Excessive flow count from one source */
    if (f->src_total_flows > ctx->cfg.flow_count_thresh) {
        score += clamp01((double)f->src_total_flows /
                         (ctx->cfg.flow_count_thresh * 3.0));
    }

    /* LAND attack: src_ip == dst_ip */
    if (f->src_ip == f->dst_ip && f->src_ip != 0) {
        score += 0.9;
    }

    /* Very low TTL variance with high packet count -> botnet behaviour */
    if (f->packet_count > 100 && f->stddev_ttl < 0.5 && f->avg_ttl > 0) {
        score += 0.15;
    }

    /* Very low IAT (inter-arrival time) with high count -> flood tool */
    if (f->packet_count > 50 && f->avg_iat_us < 100.0 && f->avg_iat_us > 0) {
        score += 0.3;
    }

    /* Slowloris: TCP, very low pps but many concurrent flows */
    if (f->protocol == 6 && f->packets_per_second < 2.0 &&
        f->src_total_flows > 50 && f->window_duration_sec > 30.0) {
        score += 0.4;
    }

    return clamp01(score);
}

/* ============================================================================
 * MODEL 5: MACHINE LEARNING (DECISION TREE / RANDOM FOREST ENSEMBLE)
 * ============================================================================ */

/* Heuristic min-max ranges for model input normalization (avoid raw large integers). */
static void ml_minmax_scale(double *x)
{
    static const double lo[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    static const double hi[] = {
        1e6, 1e9, 1, 1, 8, 8, 65535, 1500, 1000, 100, 1, 8, 65535, 64, 16, 1e6, 1e6, 10000, 1e6, 1000
    };
    for (int i = 0; i < 20; i++) {
        double range = hi[i] - lo[i];
        if (range > 0) {
            if (x[i] < lo[i]) x[i] = 0.0;
            else if (x[i] > hi[i]) x[i] = 1.0;
            else x[i] = (x[i] - lo[i]) / range;
        }
    }
}

static double score_ml_inference(const sentinel_feature_vector_t *f)
{
    /*
     * Min-max normalize inputs then ML inference (statistically robust).
     * Output probability calibrated with logistic sigmoid.
     */
    double input[20];
    input[0]  = f->packets_per_second;
    input[1]  = f->bytes_per_second;
    input[2]  = f->syn_ratio;
    input[3]  = f->rst_ratio;
    input[4]  = f->dst_port_entropy;
    input[5]  = f->payload_byte_entropy;
    input[6]  = (double)f->unique_dst_ports;
    input[7]  = f->avg_packet_size;
    input[8]  = f->stddev_packet_size;
    input[9]  = (double)f->http_request_count;
    input[10] = f->fin_ratio;
    input[11] = f->src_port_entropy;
    input[12] = (double)f->unique_src_ports;
    input[13] = f->avg_ttl;
    input[14] = f->stddev_ttl;
    input[15] = f->avg_iat_us;
    input[16] = f->stddev_iat_us;
    input[17] = (double)f->src_total_flows;
    input[18] = f->src_packets_per_second;
    input[19] = (double)f->dns_query_count;
    ml_minmax_scale(input);
    double output[2];
    ml_scratch_t scr;
    score(input, output, &scr);
    double p = output[1];
    if (p <= 0.0) return 0.0;
    if (p >= 1.0) return 1.0;
    {
        const double k = 6.0;  /* steepness: sharpens decision around 0.5 */
        double x = k * (p - 0.5);
        if (x >= 20.0) return 1.0;
        if (x <= -20.0) return 0.0;
        return 1.0 / (1.0 + exp(-x));
    }
}

/* ============================================================================
 * MODEL 6: LAYER 7 / ASYMMETRY ANOMALY
 * ============================================================================ */

static double score_l7_asymmetry(de_context_t *ctx,
                                 const sentinel_feature_vector_t *f)
{
    double score = 0.0;

    /* Only evaluate if we have enough packets to make a judgment */
    if (f->packet_count < ctx->cfg.l7_asymmetry_count_thresh) {
        return 0.0;
    }

    /* TCP Application Attack Profile (e.g., HTTP GET floods) */
    if (f->protocol == 6) {
        /*
         * True L7 Parsing detection: 
         * If we actively parsed HTTP method strings (GET/POST) in the payload buffer, 
         * and the user is blasting them fast, this is definitively an L7 flood.
         */
        if (f->http_request_count > 20 && f->packets_per_second > 50) {
            score += 0.8; /* High confidence L7 Flood */
        }

        /*
         * Asymmetry fallback: Attacker sends very small requests (HTTP GET)
         * and expects large responses. Usually translates to low avg_packet_size
         * on the ingress path with high frequency.
         */
        else if (f->avg_packet_size < ctx->cfg.l7_asymmetry_size_thresh && f->packets_per_second > 100) {
            score += 0.4;
        }

        /* 
         * Push flag dominance: 
         * High application data frequency usually sets PSH flags often.
         */
        double psh_ratio = (double)f->psh_count / f->packet_count;
        if (psh_ratio > 0.8) {
            score += 0.2;
        }

        /* 
         * Application Structural Uniformity:
         * All requests look exactly the same (botnet tools often fail to randomize L7 headers)
         */
        if (f->payload_byte_entropy > 0 && f->payload_byte_entropy < 0.20) {
            score += 0.3;
        }
    }

    return clamp01(score);
}

/* ============================================================================
 * ATTACK TYPE CLASSIFICATION
 * ============================================================================ */

static sentinel_attack_type_t classify_attack(const sentinel_feature_vector_t *f,
                                              double s_vol, double s_ent,
                                              double s_proto, double s_behav,
                                              double s_ml, double s_l7)
{
    (void)s_ent;  /* entropy score not used directly for type classification */
    (void)s_ml;   /* ML flags anomalies broadly */

    /* Layer 7 Application Flood */
    if (s_l7 > 0.6 && f->protocol == 6)
        return SENTINEL_ATTACK_UNKNOWN; /* Typically indicates an L7 GET/POST flood */

    /* LAND attack */
    if (f->src_ip == f->dst_ip && f->src_ip != 0)
        return SENTINEL_ATTACK_LAND;

    /* SYN flood */
    if (f->protocol == 6 && f->syn_ratio > 0.7 && s_proto > 0.4)
        return SENTINEL_ATTACK_SYN_FLOOD;

    /* Slowloris */
    if (f->protocol == 6 && f->packets_per_second < 2.0 &&
        f->src_total_flows > 50 && s_behav > 0.3)
        return SENTINEL_ATTACK_SLOWLORIS;

    /* DNS amplification */
    if (f->protocol == 17 && ntohs(f->src_port) == 53 && s_proto > 0.3)
        return SENTINEL_ATTACK_DNS_AMP;

    /* NTP amplification */
    if (f->protocol == 17 && ntohs(f->src_port) == 123 && s_proto > 0.3)
        return SENTINEL_ATTACK_NTP_AMP;

    /* UDP flood */
    if (f->protocol == 17 && s_vol > 0.5)
        return SENTINEL_ATTACK_UDP_FLOOD;

    /* ICMP flood */
    if (f->protocol == 1 && s_vol > 0.5)
        return SENTINEL_ATTACK_ICMP_FLOOD;

    /* Port scan */
    if (f->unique_dst_ports > 50 && s_behav > 0.3)
        return SENTINEL_ATTACK_PORT_SCAN;

    return SENTINEL_ATTACK_UNKNOWN;
}

/* ============================================================================
 * MAIN CLASSIFICATION
 * ============================================================================ */

int de_classify(de_context_t *ctx,
                const sentinel_feature_vector_t *features,
                sentinel_threat_assessment_t *out)
{
    if (!ctx || !features || !out) return -1;
    memset(out, 0, sizeof(*out));

    /* copy identity */
    out->src_ip   = features->src_ip;
    out->dst_ip   = features->dst_ip;
    out->src_port = features->src_port;
    out->dst_port = features->dst_port;
    out->protocol = features->protocol;

    /* fast-path: allowlist */
    if (ip_in_list(ctx->allowlist, features->src_ip)) {
        out->verdict     = VERDICT_ALLOW;
        out->threat_score = 0.0;
        out->confidence   = 1.0;
        out->attack_type  = SENTINEL_ATTACK_NONE;
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        out->assessment_time_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
        return 0;
    }

    /* fast-path: denylist */
    if (ip_in_list(ctx->denylist, features->src_ip)) {
        out->verdict       = VERDICT_QUARANTINE;
        out->threat_score  = 1.0;
        out->confidence    = 1.0;
        out->attack_type   = SENTINEL_ATTACK_UNKNOWN;
        out->quarantine_sec = ctx->cfg.default_quarantine;
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        out->assessment_time_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
        return 0;
    }

    /* get or create EWMA baseline for this source */
    baseline_entry_t *bl = get_baseline(ctx, features->src_ip);
    if (!bl) return -1;

    /* run all six models */
    double s_vol   = score_volume(ctx, features, bl);
    double s_ent   = score_entropy(ctx, features);
    double s_proto = score_protocol(ctx, features);
    double s_behav = score_behavioral(ctx, features);
    double s_ml    = score_ml_inference(features);
    double s_l7    = score_l7_asymmetry(ctx, features);

    /* weighted combination */
    double threat = ctx->cfg.weight_volume    * s_vol
                  + ctx->cfg.weight_entropy   * s_ent
                  + ctx->cfg.weight_protocol  * s_proto
                  + ctx->cfg.weight_behavioral * s_behav
                  + ctx->cfg.weight_ml        * s_ml
                  + ctx->cfg.weight_l7        * s_l7;

    /* Absolute Reckoning Fix: Global Weight Normalization */
    double total_weight = ctx->cfg.weight_volume + ctx->cfg.weight_entropy +
                         ctx->cfg.weight_protocol + ctx->cfg.weight_behavioral +
                         ctx->cfg.weight_ml + ctx->cfg.weight_l7;
    if (total_weight > 0.0) threat /= total_weight;

    threat = clamp01(threat);

    /* confidence: higher when more observations and scores agree */
    double agreement = 1.0;
    {
        double scores[6] = { s_vol, s_ent, s_proto, s_behav, s_ml, s_l7 };
        double mean = (s_vol + s_ent + s_proto + s_behav + s_ml + s_l7) / 6.0;
        double var = 0;
        for (int i = 0; i < 6; i++) var += (scores[i] - mean) * (scores[i] - mean);
        var /= 6.0;
        /* low variance -> high agreement -> high confidence */
        agreement = 1.0 - clamp01(sqrt(var));
    }
    double obs_mean = ((double)bl->observations_pps + (double)bl->observations_bps) * 0.5;
    double obs_factor = clamp01(obs_mean / 50.0);
    double confidence = 0.5 * agreement + 0.5 * obs_factor;

    /* store scores */
    out->score_volume     = s_vol;
    out->score_entropy    = s_ent;
    out->score_protocol   = s_proto;
    out->score_behavioral = s_behav;
    /* ML and L7 aren't included in the public threat assessment breakdown 
       struct yet, so we don't assign them here but they affect total threat_score */
    out->threat_score     = threat;
    out->confidence       = confidence;

    /* Load thresholds once (atomic: no torn read vs feedback thread). */
    double allow = atomic_load_explicit(&ctx->cfg.score_allow_max, memory_order_relaxed);
    double rate  = atomic_load_explicit(&ctx->cfg.score_rate_limit, memory_order_relaxed);
    double drop  = atomic_load_explicit(&ctx->cfg.score_drop, memory_order_relaxed);

    /* classify attack type */
    if (threat > allow) {
        out->attack_type = classify_attack(features, s_vol, s_ent, s_proto, s_behav, s_ml, s_l7);
    } else {
        out->attack_type = SENTINEL_ATTACK_NONE;
    }

    /* map score to verdict */
    if (threat <= allow) {
        out->verdict = VERDICT_ALLOW;
    } else if (threat <= rate) {
        out->verdict = VERDICT_RATE_LIMIT;
        out->rate_limit_pps = ctx->cfg.default_rate_limit;
    } else if (threat <= drop) {
        out->verdict = VERDICT_DROP;
    } else {
        out->verdict = VERDICT_QUARANTINE;
        out->quarantine_sec = ctx->cfg.default_quarantine;
    }

    /* timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    out->assessment_time_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    return 0;
}

/* ============================================================================
 * BASELINE MANAGEMENT
 * ============================================================================ */

void de_reset_baselines(de_context_t *ctx)
{
    if (!ctx || !ctx->baseline_slab) return;
    for (uint32_t i = 0; i < BASELINE_BUCKETS; i++)
        ctx->baselines[i] = NULL;
    ctx->baseline_free = &ctx->baseline_slab[0];
    for (uint32_t i = 0; i + 1 < MAX_BASELINES; i++)
        ctx->baseline_slab[i].next = &ctx->baseline_slab[i + 1];
    ctx->baseline_slab[MAX_BASELINES - 1].next = NULL;
    ctx->baseline_count = 0;
}

uint32_t de_baseline_count(const de_context_t *ctx)
{
    return ctx ? ctx->baseline_count : 0;
}
