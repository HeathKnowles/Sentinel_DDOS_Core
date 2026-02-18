/*
 * Sentinel DDoS Core - Decision Engine API
 *
 * Takes a sentinel_feature_vector_t and produces a
 * sentinel_threat_assessment_t with verdict, attack type classification,
 * and score breakdown.
 *
 * The engine uses multiple heuristic models:
 *   1. EWMA baseline comparison  (volume anomaly)
 *   2. Entropy analysis           (entropy anomaly)
 *   3. Protocol ratio analysis    (protocol anomaly)
 *   4. Behavioral profiling       (behavioral anomaly)
 *
 * These are combined into a weighted threat score and mapped to a verdict.
 */

#ifndef SENTINEL_DECISION_ENGINE_H
#define SENTINEL_DECISION_ENGINE_H

#include "../core/sentinel_types.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

typedef struct de_thresholds {
    /* verdict thresholds on the final 0..1 threat score */
    double   score_allow_max;      /* <= this  -> ALLOW   (default 0.3)  */
    double   score_rate_limit;     /* <= this  -> RATE_LIMIT (def 0.6)   */
    double   score_drop;           /* <= this  -> DROP       (def 0.85)  */
    /* above score_drop -> QUARANTINE */

    /* EWMA parameters */
    double   ewma_alpha;           /* smoothing factor (default 0.1)     */
    double   ewma_volume_sigma;    /* # of std-devs for volume anomaly   */

    /* entropy thresholds */
    double   entropy_low_thresh;   /* entropy below this is suspicious   */
    double   entropy_high_thresh;  /* entropy above this is suspicious   */

    /* protocol-specific thresholds */
    double   syn_ratio_thresh;     /* SYN ratio above this -> SYN flood  */
    double   rst_ratio_thresh;     /* RST ratio above this -> anomaly    */
    double   icmp_pps_thresh;      /* ICMP pps above this -> ICMP flood  */
    double   udp_pps_thresh;       /* UDP pps above this -> UDP flood    */

    /* behavioral */
    double   port_scan_thresh;     /* unique dst ports above this -> scan */
    double   flow_count_thresh;    /* flows from one src above this       */

    /* rate limit config */
    uint32_t default_rate_limit;   /* pps when RATE_LIMIT verdict        */
    uint32_t default_quarantine;   /* seconds when QUARANTINE verdict    */

    /* component weights (must sum to ~1.0) */
    double   weight_volume;
    double   weight_entropy;
    double   weight_protocol;
    double   weight_behavioral;
} de_thresholds_t;

#define DE_THRESHOLDS_DEFAULT { \
    .score_allow_max    = 0.30, \
    .score_rate_limit   = 0.60, \
    .score_drop         = 0.85, \
    .ewma_alpha         = 0.10, \
    .ewma_volume_sigma  = 3.0,  \
    .entropy_low_thresh = 0.5,  \
    .entropy_high_thresh= 7.5,  \
    .syn_ratio_thresh   = 0.80, \
    .rst_ratio_thresh   = 0.50, \
    .icmp_pps_thresh    = 5000, \
    .udp_pps_thresh     = 50000,\
    .port_scan_thresh   = 100,  \
    .flow_count_thresh  = 500,  \
    .default_rate_limit = 1000, \
    .default_quarantine = 300,  \
    .weight_volume      = 0.35, \
    .weight_entropy     = 0.20, \
    .weight_protocol    = 0.30, \
    .weight_behavioral  = 0.15  \
}

/* ============================================================================
 * OPAQUE HANDLE
 * ============================================================================ */

typedef struct de_context de_context_t;

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

de_context_t *de_init(const de_thresholds_t *cfg);
void          de_destroy(de_context_t *ctx);

/* ============================================================================
 * CLASSIFICATION
 * ============================================================================ */

/*  Classify a feature vector and produce a threat assessment.
 *  Returns 0 on success. */
int de_classify(de_context_t *ctx,
                const sentinel_feature_vector_t *features,
                sentinel_threat_assessment_t *out);

/* ============================================================================
 * BASELINE MANAGEMENT
 * ============================================================================ */

/*  Manually reset all learned baselines (useful after config change). */
void de_reset_baselines(de_context_t *ctx);

/*  Get the number of tracked baselines. */
uint32_t de_baseline_count(const de_context_t *ctx);

/* ============================================================================
 * ALLOW/DENY LISTS
 * ============================================================================ */

int de_add_allowlist(de_context_t *ctx, uint32_t ip);
int de_add_denylist(de_context_t *ctx, uint32_t ip);
int de_remove_allowlist(de_context_t *ctx, uint32_t ip);
int de_remove_denylist(de_context_t *ctx, uint32_t ip);

#ifdef __cplusplus
}
#endif

#endif /* SENTINEL_DECISION_ENGINE_H */
