/*
 * Sentinel DDoS Core - SDN Control Plane API  (Ryu)
 *
 * Communicates with a Ryu SDN controller via its ofctl_rest REST API
 * to install, remove, and query OpenFlow rules on SDN switches.
 *
 * Ryu ofctl_rest endpoints (default http://127.0.0.1:8080):
 *   POST  /stats/flowentry/add          - install a flow
 *   POST  /stats/flowentry/delete       - remove matching flows
 *   POST  /stats/flowentry/delete_strict - remove exact flow
 *   GET   /stats/flow/<dpid>            - list flows on a switch
 *   GET   /stats/switches               - list connected switches
 *
 * Uses libcurl for HTTP.  All functions are synchronous.
 */

#ifndef SENTINEL_SDN_CONTROLLER_H
#define SENTINEL_SDN_CONTROLLER_H

#include "../core/sentinel_types.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

typedef struct sdn_config {
    char     controller_url[256];   /* e.g. "http://127.0.0.1:8080"          */
    uint64_t default_dpid;          /* datapath ID, e.g. 1                   */
    char     default_table[16];     /* default table id, e.g. "0"            */
    uint32_t connect_timeout_ms;    /* libcurl connect timeout                */
    uint32_t request_timeout_ms;    /* libcurl request timeout                */
    int      verify_ssl;            /* 0 = skip SSL verify (dev only)         */
    char     auth_bearer_token[64]; /* optional: bearer token for CURLOPT_HTTPAUTH */
} sdn_config_t;

#define SDN_CONFIG_DEFAULT { \
    .controller_url    = "http://127.0.0.1:8080", \
    .default_dpid      = 1,                        \
    .default_table     = "0",                      \
    .connect_timeout_ms = 5000,                    \
    .request_timeout_ms = 10000,                   \
    .verify_ssl         = 0,                       \
    .auth_bearer_token  = ""                       \
}

/* ============================================================================
 * OPAQUE HANDLE
 * ============================================================================ */

typedef struct sdn_context sdn_context_t;

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

sdn_context_t *sdn_init(const sdn_config_t *cfg);
void            sdn_destroy(sdn_context_t *ctx);

/* ============================================================================
 * RULE MANAGEMENT
 * ============================================================================ */

/*  Push a flow rule to the Ryu controller.
 *  Returns 0 on success, SDN_ERR_QUEUE_FULL if busy. */
#define SDN_ERR_QUEUE_FULL -2
int sdn_push_rule(sdn_context_t *ctx, const sentinel_sdn_rule_t *rule);

/*  Remove a rule by its ID (cookie), dpid, and table.
 *  Uses delete_strict with the cookie to target the exact flow.
 *  Returns 0 on success, -1 on error.  */
int sdn_remove_rule(sdn_context_t *ctx, uint32_t rule_id,
                    const char *node_id, const char *table_id);

/*  Remove ALL rules for a given source IP.
 *  Uses the match-based delete endpoint.
 *  Returns 0 on success, -1 on error. */
int sdn_remove_rules_for_src(sdn_context_t *ctx, uint32_t src_ip);

/* ============================================================================
 * THREAT-TO-RULE CONVERSION
 * ============================================================================ */

/*  Build an sdn_rule from a threat assessment.  Fills in match fields,
 *  action, priority, and timeouts automatically.
 *  Returns 0 on success. */
int sdn_build_rule_from_assessment(sdn_context_t *ctx,
                                   const sentinel_threat_assessment_t *assessment,
                                   sentinel_sdn_rule_t *out_rule);

/* ============================================================================
 * HEALTH / DIAGNOSTICS
 * ============================================================================ */

/*  Ping Ryu GET /stats/switches. Returns 0 if reachable. */
int sdn_health_check(sdn_context_t *ctx);

/*  Get the number of flows installed on a dpid (table 0).
 *  Returns the flow count, or -1 on error. */
int sdn_get_flow_count(sdn_context_t *ctx, const char *node_id);

/*  Check if the SDN command queue is saturated (>90% full).
 *  Returns 1 if saturated, 0 otherwise. */
int sdn_is_saturated(const sdn_context_t *ctx);

/*  Get the total rules pushed since init. */
uint64_t sdn_rules_pushed(const sdn_context_t *ctx);

/*  Get the total rules that failed to push. */
uint64_t sdn_rules_failed(const sdn_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SENTINEL_SDN_CONTROLLER_H */
