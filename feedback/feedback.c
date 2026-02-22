/*
 * Sentinel DDoS Core - Feedback Loop Implementation
 *
 * Ring-buffer based history with outcome tracking, automatic false-positive
 * and false-negative detection, and threshold adjustment suggestions.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <stdatomic.h>
#include <math.h>
#include <time.h>

#include "feedback.h"

/* ============================================================================
 * CONTEXT
 * ============================================================================ */

struct fb_context {
    fb_config_t     cfg;
    fb_record_t    *ring;
    atomic_uint_fast64_t record_head; /* atomic monotonic counter */
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
    atomic_init(&ctx->record_head, 0);

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

    /* SPSC: Acquire current head, write data, then store-release.
     * Note: We assume a single producer (main pipeline). If MPMC is needed,
     * reservation would be required, but Sentinel uses a single hot-path. */
    uint64_t head = atomic_load_explicit(&ctx->record_head, memory_order_relaxed);
    uint64_t idx = head % ctx->cfg.history_size;
    fb_record_t *r = &ctx->ring[idx];

    r->src_ip       = src_ip;
    r->verdict      = verdict;
    r->attack_type  = attack_type;
    r->threat_score = threat_score;
    r->timestamp_ns = now_ns();
    atomic_store_explicit(&r->outcome, FB_OUTCOME_UNKNOWN, memory_order_relaxed);

    /* Commit: make data visible to consumer (fb_evaluate) */
    atomic_store_explicit(&ctx->record_head, head + 1, memory_order_release);

    return 0;
}

/* ============================================================================
 * OUTCOME MARKING
 * ============================================================================ */

int fb_mark_outcome(fb_context_t *ctx, uint32_t src_ip,
                    uint64_t timestamp_ns, fb_outcome_t outcome)
{
    if (!ctx) return -1;

    uint64_t current_head = atomic_load_explicit(&ctx->record_head, memory_order_acquire);
    uint64_t n = (current_head < ctx->cfg.history_size)
                  ? current_head : ctx->cfg.history_size;

    /* search backwards from most recent */
    for (uint64_t i = 0; i < n; i++) {
        uint64_t idx = (current_head - 1 - i) % ctx->cfg.history_size;
        fb_record_t *r = &ctx->ring[idx];
        if (r->src_ip == src_ip && r->timestamp_ns == timestamp_ns) {
            atomic_store_explicit(&r->outcome, outcome, memory_order_release);
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

    uint64_t current_head = atomic_load_explicit(&ctx->record_head, memory_order_acquire);
    uint64_t n = (current_head < ctx->cfg.history_size)
                  ? current_head : ctx->cfg.history_size;
    uint64_t window_ns = (uint64_t)ctx->cfg.evaluation_window_sec * 1000000000ULL;
    uint64_t cutoff = now_ns() - window_ns;
    int marked = 0;

    for (uint64_t i = 0; i < n; i++) {
        uint64_t idx = (current_head - 1 - i) % ctx->cfg.history_size;
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

    uint64_t current_head = atomic_load_explicit(&ctx->record_head, memory_order_acquire);
    uint64_t n = (current_head < ctx->cfg.history_size)
                  ? current_head : ctx->cfg.history_size;
    uint64_t window_ns = (uint64_t)ctx->cfg.evaluation_window_sec * 1000000000ULL;
    uint64_t cutoff = now_ns() - window_ns;
    int marked = 0;

    for (uint64_t i = 0; i < n; i++) {
        uint64_t idx = (current_head - 1 - i) % ctx->cfg.history_size;
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

    uint64_t current_head = atomic_load_explicit(&ctx->record_head, memory_order_acquire);
    uint64_t n = (current_head < ctx->cfg.history_size)
                  ? current_head : ctx->cfg.history_size;
    uint64_t window_ns = (uint64_t)ctx->cfg.evaluation_window_sec * 1000000000ULL;
    uint64_t cutoff = now_ns() - window_ns;

    for (uint64_t i = 0; i < n; i++) {
        uint64_t idx = (current_head - 1 - i) % ctx->cfg.history_size;
        fb_record_t *r = &ctx->ring[idx];
        if (r->timestamp_ns < cutoff) break;

        out->total_records++;
        fb_outcome_t occ = atomic_load_explicit(&r->outcome, memory_order_relaxed);
        switch (occ) {
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

    /* 1. Compute error rates (FP rate, FN rate) from history. */
    fb_metrics_t m;
    if (fb_evaluate(ctx, &m) != 0) return -1;

    /* need enough classified records to be meaningful */
    uint64_t classified = m.true_positives + m.true_negatives +
                          m.false_positives + m.false_negatives;
    if (classified < 20) {
        snprintf(out->reason, sizeof(out->reason),
                 "Not enough classified records (%llu) to suggest adjustments",
                 (unsigned long long)classified);
        return 0;
    }

    /* 2. Compute step from config; clamp so thresholds remain in valid range. */
    double step = ctx->cfg.adjustment_step;
    if (step <= 0.0) step = 0.02;
    if (step > 0.2) step = 0.2;
    double max_delta = step * 2.0;
    if (max_delta > 0.15) max_delta = 0.15;

    /* 3. Apply step (direction from FP/FN), then clamp deltas. */
    if (m.false_pos_rate > ctx->cfg.fp_threshold) {
        /* too many false positives: raise the allow threshold (be more lenient) */
        out->should_adjust    = 1;
        out->delta_allow_max  = +step;
        out->delta_rate_limit = +step * 0.5;
        out->delta_drop       = +step * 0.25;
        /* Clamp deltas so applied thresholds remain in valid range */
        if (out->delta_allow_max > max_delta) out->delta_allow_max = max_delta;
        if (out->delta_rate_limit > max_delta) out->delta_rate_limit = max_delta;
        if (out->delta_drop > max_delta) out->delta_drop = max_delta;
        snprintf(out->reason, sizeof(out->reason),
                 "High FP rate (%.2f%% > %.2f%%): raising thresholds to reduce false blocks",
                 m.false_pos_rate * 100, ctx->cfg.fp_threshold * 100);
    } else if (m.false_neg_rate > ctx->cfg.fn_threshold) {
        /* too many false negatives: lower thresholds (be more aggressive) */
        out->should_adjust    = 1;
        out->delta_allow_max  = -step;
        out->delta_rate_limit = -step * 0.5;
        out->delta_drop       = -step * 0.25;
        if (out->delta_allow_max < -max_delta) out->delta_allow_max = -max_delta;
        if (out->delta_rate_limit < -max_delta) out->delta_rate_limit = -max_delta;
        if (out->delta_drop < -max_delta) out->delta_drop = -max_delta;
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
    return ctx ? atomic_load_explicit(&ctx->record_head, memory_order_relaxed) : 0;
}
