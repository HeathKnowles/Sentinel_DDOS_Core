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
#include "decision_engine.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

/* ============================================================================
 * INTERNAL CONSTANTS
 * ============================================================================ */

#define BASELINE_BUCKETS 8192
#define LIST_BUCKETS     1024

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
    uint32_t observations;
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

    return ctx;
}

void de_destroy(de_context_t *ctx)
{
    if (!ctx) return;

    for (uint32_t i = 0; i < BASELINE_BUCKETS; i++) {
        baseline_entry_t *b = ctx->baselines[i];
        while (b) { baseline_entry_t *n = b->next; free(b); b = n; }
    }
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
    bl = calloc(1, sizeof(*bl));
    if (!bl) return NULL;
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
                                    uint32_t *obs, double alpha)
{
    if (*obs == 0) {
        /* first observation: initialise */
        *ewma = value;
        *ewma_var = 0.0;
        (*obs)++;
        return 0.0;
    }

    /* update EWMA */
    double prev = *ewma;
    *ewma = alpha * value + (1.0 - alpha) * prev;

    /* update variance (Welford-EWMA hybrid) */
    double diff = value - prev;
    *ewma_var = (1.0 - alpha) * (*ewma_var) + alpha * diff * diff;
    (*obs)++;

    /* compute z-score */
    double sigma = sqrt(*ewma_var);
    if (sigma < 1e-9) return 0.0;
    return fabs(value - *ewma) / sigma;
}

/* ============================================================================
 * INTERNAL: clamp to [0, 1]
 * ============================================================================ */

static inline double clamp01(double x)
{
    if (x < 0.0) return 0.0;
    if (x > 1.0) return 1.0;
    return x;
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
                                          &bl->observations, ctx->cfg.ewma_alpha);
    double z_bps = ewma_update_and_score(f->bytes_per_second,
                                          &bl->ewma_bps, &bl->ewma_bps_var,
                                          &bl->observations, ctx->cfg.ewma_alpha);

    /* normalise z-score to [0,1] using the configured sigma threshold */
    double sigma = ctx->cfg.ewma_volume_sigma;
    double s_pps = clamp01(z_pps / sigma);
    double s_bps = clamp01(z_bps / sigma);

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

    /* UDP flood */
    if (f->protocol == 17 && f->packets_per_second > ctx->cfg.udp_pps_thresh) {
        score += clamp01(f->packets_per_second / (ctx->cfg.udp_pps_thresh * 5.0));
    }

    /* ICMP flood */
    if (f->protocol == 1 && f->packets_per_second > ctx->cfg.icmp_pps_thresh) {
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
 * ATTACK TYPE CLASSIFICATION
 * ============================================================================ */

static sentinel_attack_type_t classify_attack(const sentinel_feature_vector_t *f,
                                              double s_vol, double s_ent,
                                              double s_proto, double s_behav)
{
    (void)s_ent;  /* entropy score not used directly for type classification */

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

    /* run all four models */
    double s_vol   = score_volume(ctx, features, bl);
    double s_ent   = score_entropy(ctx, features);
    double s_proto = score_protocol(ctx, features);
    double s_behav = score_behavioral(ctx, features);

    /* weighted combination */
    double threat = ctx->cfg.weight_volume    * s_vol
                  + ctx->cfg.weight_entropy   * s_ent
                  + ctx->cfg.weight_protocol  * s_proto
                  + ctx->cfg.weight_behavioral * s_behav;
    threat = clamp01(threat);

    /* confidence: higher when more observations and scores agree */
    double agreement = 1.0;
    {
        double scores[4] = { s_vol, s_ent, s_proto, s_behav };
        double mean = (s_vol + s_ent + s_proto + s_behav) / 4.0;
        double var = 0;
        for (int i = 0; i < 4; i++) var += (scores[i] - mean) * (scores[i] - mean);
        var /= 4.0;
        /* low variance -> high agreement -> high confidence */
        agreement = 1.0 - clamp01(sqrt(var));
    }
    double obs_factor = clamp01((double)bl->observations / 50.0);
    double confidence = 0.5 * agreement + 0.5 * obs_factor;

    /* store scores */
    out->score_volume     = s_vol;
    out->score_entropy    = s_ent;
    out->score_protocol   = s_proto;
    out->score_behavioral = s_behav;
    out->threat_score     = threat;
    out->confidence       = confidence;

    /* classify attack type */
    if (threat > ctx->cfg.score_allow_max) {
        out->attack_type = classify_attack(features, s_vol, s_ent, s_proto, s_behav);
    } else {
        out->attack_type = SENTINEL_ATTACK_NONE;
    }

    /* map score to verdict */
    if (threat <= ctx->cfg.score_allow_max) {
        out->verdict = VERDICT_ALLOW;
    } else if (threat <= ctx->cfg.score_rate_limit) {
        out->verdict = VERDICT_RATE_LIMIT;
        out->rate_limit_pps = ctx->cfg.default_rate_limit;
    } else if (threat <= ctx->cfg.score_drop) {
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
    if (!ctx) return;
    for (uint32_t i = 0; i < BASELINE_BUCKETS; i++) {
        baseline_entry_t *b = ctx->baselines[i];
        while (b) {
            baseline_entry_t *n = b->next;
            free(b);
            b = n;
        }
        ctx->baselines[i] = NULL;
    }
    ctx->baseline_count = 0;
}

uint32_t de_baseline_count(const de_context_t *ctx)
{
    return ctx ? ctx->baseline_count : 0;
}
