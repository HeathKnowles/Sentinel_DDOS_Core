/*
 * Sentinel DDoS Core - Feedback Loop API
 *
 * Provides a mechanism to track the effectiveness of past verdicts
 * and feed corrections back into the decision engine.
 *
 * The feedback loop tracks:
 *   - False positives (legitimate traffic that was blocked)
 *   - False negatives (attack traffic that was allowed)
 *   - Threshold drift (adjusting thresholds based on outcomes)
 *
 * Usage:
 *   1. After pushing an SDN rule, call fb_record_action()
 *   2. Periodically call fb_evaluate() to compute metrics
 *   3. Call fb_suggest_adjustments() to get threshold corrections
 *   4. Apply suggestions to the decision engine
 */

#ifndef SENTINEL_FEEDBACK_H
#define SENTINEL_FEEDBACK_H

#include "../core/sentinel_types.h"
#include "../decisionengine/decision_engine.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

typedef struct fb_config {
    uint32_t history_size;           /* max entries in the ring buffer */
    uint32_t evaluation_window_sec;  /* look back N seconds for metrics */
    double   fp_threshold;           /* false-positive rate that triggers tuning */
    double   fn_threshold;           /* false-negative rate that triggers tuning */
    double   adjustment_step;        /* how much to nudge thresholds per cycle */
} fb_config_t;

#define FB_CONFIG_DEFAULT { \
    .history_size          = 65536, \
    .evaluation_window_sec = 300,   \
    .fp_threshold          = 0.05,  \
    .fn_threshold          = 0.02,  \
    .adjustment_step       = 0.02   \
}

/* ============================================================================
 * FEEDBACK RECORD
 * ============================================================================ */

typedef enum fb_outcome {
    FB_OUTCOME_UNKNOWN = 0,     /* not yet verified */
    FB_OUTCOME_TRUE_POS = 1,    /* correctly blocked attack */
    FB_OUTCOME_TRUE_NEG = 2,    /* correctly allowed legitimate traffic */
    FB_OUTCOME_FALSE_POS = 3,   /* blocked legitimate traffic */
    FB_OUTCOME_FALSE_NEG = 4    /* allowed attack traffic */
} fb_outcome_t;

typedef struct fb_record {
    uint32_t             src_ip;
    sentinel_verdict_e   verdict;
    sentinel_attack_type_t attack_type;
    double               threat_score;
    fb_outcome_t         outcome;
    uint64_t             timestamp_ns;
} fb_record_t;

/* ============================================================================
 * METRICS
 * ============================================================================ */

typedef struct fb_metrics {
    uint64_t total_records;
    uint64_t true_positives;
    uint64_t true_negatives;
    uint64_t false_positives;
    uint64_t false_negatives;
    double   precision;        /* TP / (TP + FP) */
    double   recall;           /* TP / (TP + FN) */
    double   f1_score;         /* 2 * P * R / (P + R) */
    double   false_pos_rate;   /* FP / (FP + TN) */
    double   false_neg_rate;   /* FN / (FN + TP) */
} fb_metrics_t;

/* ============================================================================
 * THRESHOLD ADJUSTMENTS
 * ============================================================================ */

typedef struct fb_adjustments {
    int    should_adjust;          /* 1 if adjustments recommended */
    double delta_allow_max;        /* add to score_allow_max */
    double delta_rate_limit;       /* add to score_rate_limit */
    double delta_drop;             /* add to score_drop */
    char   reason[256];            /* human-readable reason */
} fb_adjustments_t;

/* ============================================================================
 * OPAQUE HANDLE
 * ============================================================================ */

typedef struct fb_context fb_context_t;

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

fb_context_t *fb_init(const fb_config_t *cfg);
void          fb_destroy(fb_context_t *ctx);

/* ============================================================================
 * OPERATIONS
 * ============================================================================ */

/*  Record an action taken by the pipeline. */
int fb_record_action(fb_context_t *ctx,
                     uint32_t src_ip,
                     sentinel_verdict_e verdict,
                     sentinel_attack_type_t attack_type,
                     double threat_score);

/*  Mark the outcome of a previous action (e.g., after manual review). */
int fb_mark_outcome(fb_context_t *ctx, uint32_t src_ip,
                    uint64_t timestamp_ns, fb_outcome_t outcome);

/*  Auto-detect false negatives: if a source was allowed but later
 *  triggered a high-score assessment, mark prior ALLOWs as FN. */
int fb_auto_detect_fn(fb_context_t *ctx, uint32_t src_ip,
                      double current_score);

/*  Auto-detect false positives: if traffic from a blocked source
 *  later appears benign, mark prior blocks as FP. */
int fb_auto_detect_fp(fb_context_t *ctx, uint32_t src_ip,
                      double current_score);

/*  Compute metrics over the evaluation window. */
int fb_evaluate(fb_context_t *ctx, fb_metrics_t *out);

/*  Suggest threshold adjustments based on current metrics. */
int fb_suggest_adjustments(fb_context_t *ctx, fb_adjustments_t *out);

/*  Get total records stored. */
uint64_t fb_record_count(const fb_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SENTINEL_FEEDBACK_H */
