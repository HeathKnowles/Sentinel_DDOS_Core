/*
 * Sentinel DDoS Core - Feedback Loop Implementation
 *
 * Ring-buffer based history with outcome tracking, automatic false-positive
 * and false-negative detection, and threshold adjustment suggestions.
 */

#define _POSIX_C_SOURCE 200809L
#include "feedback.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>

/* ============================================================================
 * CONTEXT
 * ============================================================================ */

struct fb_context {
    fb_config_t   cfg;
    fb_record_t  *ring;
    uint64_t      head;        /* next write position */
    uint64_t      count;       /* total entries written (wraps in ring) */
};

/* ============================================================================
 * HELPERS
 * ============================================================================ */

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

fb_context_t *fb_init(const fb_config_t *cfg)
{
    fb_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    if (cfg)
        ctx->cfg = *cfg;
    else {
        fb_config_t def = FB_CONFIG_DEFAULT;
        ctx->cfg = def;
    }

    ctx->ring = calloc(ctx->cfg.history_size, sizeof(fb_record_t));
    if (!ctx->ring) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

void fb_destroy(fb_context_t *ctx)
{
    if (!ctx) return;
    free(ctx->ring);
    free(ctx);
}

/* ============================================================================
 * RECORD
 * ============================================================================ */

int fb_record_action(fb_context_t *ctx,
                     uint32_t src_ip,
                     sentinel_verdict_e verdict,
                     sentinel_attack_type_t attack_type,
                     double threat_score)
{
    if (!ctx) return -1;

    uint64_t idx = ctx->head % ctx->cfg.history_size;
    fb_record_t *r = &ctx->ring[idx];

    r->src_ip       = src_ip;
    r->verdict      = verdict;
    r->attack_type  = attack_type;
    r->threat_score = threat_score;
    r->outcome      = FB_OUTCOME_UNKNOWN;
    r->timestamp_ns = now_ns();

    ctx->head++;
    ctx->count++;
    return 0;
}

/* ============================================================================
 * OUTCOME MARKING
 * ============================================================================ */

int fb_mark_outcome(fb_context_t *ctx, uint32_t src_ip,
                    uint64_t timestamp_ns, fb_outcome_t outcome)
{
    if (!ctx) return -1;

    uint64_t n = (ctx->count < ctx->cfg.history_size)
                  ? ctx->count : ctx->cfg.history_size;

    /* search backwards from most recent */
    for (uint64_t i = 0; i < n; i++) {
        uint64_t idx = (ctx->head - 1 - i) % ctx->cfg.history_size;
        fb_record_t *r = &ctx->ring[idx];
        if (r->src_ip == src_ip && r->timestamp_ns == timestamp_ns) {
            r->outcome = outcome;
            return 0;
        }
    }
    return -1; /* not found */
}

/* ============================================================================
 * AUTO-DETECTION
 * ============================================================================ */

int fb_auto_detect_fn(fb_context_t *ctx, uint32_t src_ip,
                      double current_score)
{
    if (!ctx) return -1;
    if (current_score < 0.7) return 0; /* not clearly an attack */

    uint64_t n = (ctx->count < ctx->cfg.history_size)
                  ? ctx->count : ctx->cfg.history_size;
    uint64_t window_ns = (uint64_t)ctx->cfg.evaluation_window_sec * 1000000000ULL;
    uint64_t cutoff = now_ns() - window_ns;
    int marked = 0;

    for (uint64_t i = 0; i < n; i++) {
        uint64_t idx = (ctx->head - 1 - i) % ctx->cfg.history_size;
        fb_record_t *r = &ctx->ring[idx];
        if (r->timestamp_ns < cutoff) break;
        if (r->src_ip == src_ip &&
            r->verdict == VERDICT_ALLOW &&
            r->outcome == FB_OUTCOME_UNKNOWN) {
            r->outcome = FB_OUTCOME_FALSE_NEG;
            marked++;
        }
    }
    return marked;
}

int fb_auto_detect_fp(fb_context_t *ctx, uint32_t src_ip,
                      double current_score)
{
    if (!ctx) return -1;
    if (current_score > 0.2) return 0; /* not clearly benign */

    uint64_t n = (ctx->count < ctx->cfg.history_size)
                  ? ctx->count : ctx->cfg.history_size;
    uint64_t window_ns = (uint64_t)ctx->cfg.evaluation_window_sec * 1000000000ULL;
    uint64_t cutoff = now_ns() - window_ns;
    int marked = 0;

    for (uint64_t i = 0; i < n; i++) {
        uint64_t idx = (ctx->head - 1 - i) % ctx->cfg.history_size;
        fb_record_t *r = &ctx->ring[idx];
        if (r->timestamp_ns < cutoff) break;
        if (r->src_ip == src_ip &&
            r->verdict != VERDICT_ALLOW &&
            r->outcome == FB_OUTCOME_UNKNOWN) {
            r->outcome = FB_OUTCOME_FALSE_POS;
            marked++;
        }
    }
    return marked;
}

/* ============================================================================
 * EVALUATION
 * ============================================================================ */

int fb_evaluate(fb_context_t *ctx, fb_metrics_t *out)
{
    if (!ctx || !out) return -1;
    memset(out, 0, sizeof(*out));

    uint64_t n = (ctx->count < ctx->cfg.history_size)
                  ? ctx->count : ctx->cfg.history_size;
    uint64_t window_ns = (uint64_t)ctx->cfg.evaluation_window_sec * 1000000000ULL;
    uint64_t cutoff = now_ns() - window_ns;

    for (uint64_t i = 0; i < n; i++) {
        uint64_t idx = (ctx->head - 1 - i) % ctx->cfg.history_size;
        fb_record_t *r = &ctx->ring[idx];
        if (r->timestamp_ns < cutoff) break;

        out->total_records++;
        switch (r->outcome) {
        case FB_OUTCOME_TRUE_POS:  out->true_positives++;  break;
        case FB_OUTCOME_TRUE_NEG:  out->true_negatives++;  break;
        case FB_OUTCOME_FALSE_POS: out->false_positives++; break;
        case FB_OUTCOME_FALSE_NEG: out->false_negatives++; break;
        default: break;
        }
    }

    /* compute metrics (avoid division by zero) */
    uint64_t tp = out->true_positives;
    uint64_t tn = out->true_negatives;
    uint64_t fp = out->false_positives;
    uint64_t fn = out->false_negatives;

    out->precision = (tp + fp > 0) ? (double)tp / (tp + fp) : 1.0;
    out->recall    = (tp + fn > 0) ? (double)tp / (tp + fn) : 1.0;

    double p = out->precision, r_val = out->recall;
    out->f1_score = (p + r_val > 0) ? 2.0 * p * r_val / (p + r_val) : 0.0;

    out->false_pos_rate = (fp + tn > 0) ? (double)fp / (fp + tn) : 0.0;
    out->false_neg_rate = (fn + tp > 0) ? (double)fn / (fn + tp) : 0.0;

    return 0;
}

/* ============================================================================
 * THRESHOLD ADJUSTMENT SUGGESTIONS
 * ============================================================================ */

int fb_suggest_adjustments(fb_context_t *ctx, fb_adjustments_t *out)
{
    if (!ctx || !out) return -1;
    memset(out, 0, sizeof(*out));

    fb_metrics_t m;
    if (fb_evaluate(ctx, &m) != 0) return -1;

    /* need enough classified records to be meaningful */
    uint64_t classified = m.true_positives + m.true_negatives +
                          m.false_positives + m.false_negatives;
    if (classified < 20) {
        snprintf(out->reason, sizeof(out->reason),
                 "Not enough classified records (%lu) to suggest adjustments",
                 classified);
        return 0;
    }

    double step = ctx->cfg.adjustment_step;

    if (m.false_pos_rate > ctx->cfg.fp_threshold) {
        /* too many false positives: raise the allow threshold (be more lenient) */
        out->should_adjust    = 1;
        out->delta_allow_max  = +step;
        out->delta_rate_limit = +step * 0.5;
        out->delta_drop       = +step * 0.25;
        snprintf(out->reason, sizeof(out->reason),
                 "High FP rate (%.2f%% > %.2f%%): raising thresholds to reduce false blocks",
                 m.false_pos_rate * 100, ctx->cfg.fp_threshold * 100);
    } else if (m.false_neg_rate > ctx->cfg.fn_threshold) {
        /* too many false negatives: lower thresholds (be more aggressive) */
        out->should_adjust    = 1;
        out->delta_allow_max  = -step;
        out->delta_rate_limit = -step * 0.5;
        out->delta_drop       = -step * 0.25;
        snprintf(out->reason, sizeof(out->reason),
                 "High FN rate (%.2f%% > %.2f%%): lowering thresholds to catch more attacks",
                 m.false_neg_rate * 100, ctx->cfg.fn_threshold * 100);
    } else {
        snprintf(out->reason, sizeof(out->reason),
                 "FP=%.2f%% FN=%.2f%% F1=%.3f - within acceptable range",
                 m.false_pos_rate * 100, m.false_neg_rate * 100, m.f1_score);
    }

    return 0;
}

/* ============================================================================
 * UTILITY
 * ============================================================================ */

uint64_t fb_record_count(const fb_context_t *ctx)
{
    return ctx ? ctx->count : 0;
}
