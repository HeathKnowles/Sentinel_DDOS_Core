/*
 * Sentinel DDoS Core - SDN Control Plane  (Ryu ofctl_rest)
 *
 * Pushes OpenFlow rules to a Ryu SDN controller via ofctl_rest.
 *
 * Ryu ofctl_rest REST layout:
 *   POST  /stats/flowentry/add            - install a flow entry
 *   POST  /stats/flowentry/delete         - delete matching flows
 *   POST  /stats/flowentry/delete_strict  - delete exact flow
 *   GET   /stats/flow/<dpid>              - list all flows on switch
 *   GET   /stats/switches                 - list connected switches
 *
 * All payloads are JSON.  Ryu does not use HTTP authentication by default.
 *
 * Cookie convention: sentinel flows use cookie = (COOKIE_PREFIX | rule_id)
 * so they can be identified and removed without affecting other flows.
 */

#define _POSIX_C_SOURCE 200809L
#include "sdn_controller.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <curl/curl.h>

/* Sentinel flows use the top 32 bits of the 64-bit cookie for identification */
#define SENTINEL_COOKIE_PREFIX  UINT64_C(0x5E40000000000000)
#define SENTINEL_COOKIE_MASK    UINT64_C(0xFFFFFFFF00000000)

/* ============================================================================
 * CONTEXT
 * ============================================================================ */

struct sdn_context {
    sdn_config_t  cfg;
    CURL          *curl;
    uint64_t       rules_pushed;
    uint64_t       rules_failed;
    uint32_t       next_rule_id;
    char           errbuf[CURL_ERROR_SIZE];
};

/* ============================================================================
 * HELPERS
 * ============================================================================ */

/* write callback that captures the response body */
typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} resp_buf_t;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    resp_buf_t *buf = (resp_buf_t *)userdata;
    size_t total = size * nmemb;
    if (buf->len + total + 1 > buf->cap) {
        size_t newcap = (buf->cap == 0) ? 4096 : buf->cap * 2;
        while (newcap < buf->len + total + 1) newcap *= 2;
        char *tmp = realloc(buf->data, newcap);
        if (!tmp) return 0;
        buf->data = tmp;
        buf->cap = newcap;
    }
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

static void resp_buf_reset(resp_buf_t *buf)
{
    buf->len = 0;
    if (buf->data) buf->data[0] = '\0';
}

static void resp_buf_free(resp_buf_t *buf)
{
    free(buf->data);
    buf->data = NULL;
    buf->len = buf->cap = 0;
}

/* format an IPv4 address in network byte order to "x.x.x.x" */
static void ip_to_str(uint32_t ip_nbo, char *out, size_t len)
{
    struct in_addr a = { .s_addr = ip_nbo };
    inet_ntop(AF_INET, &a, out, (socklen_t)len);
}

/* parse dpid from node_id string – accepts plain integer or "openflow:N" */
static uint64_t parse_dpid(const char *s, uint64_t fallback)
{
    if (!s || !s[0]) return fallback;
    /* strip "openflow:" prefix if present (compatibility) */
    if (strncmp(s, "openflow:", 9) == 0)
        s += 9;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (end == s) return fallback;
    return (uint64_t)v;
}

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

sdn_context_t *sdn_init(const sdn_config_t *cfg)
{
    sdn_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    if (cfg)
        ctx->cfg = *cfg;
    else {
        sdn_config_t def = SDN_CONFIG_DEFAULT;
        ctx->cfg = def;
    }

    /* global curl init (idempotent) */
    curl_global_init(CURL_GLOBAL_ALL);

    ctx->curl = curl_easy_init();
    if (!ctx->curl) {
        free(ctx);
        return NULL;
    }

    /* persistent connection settings */
    curl_easy_setopt(ctx->curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(ctx->curl, CURLOPT_ERRORBUFFER, ctx->errbuf);
    curl_easy_setopt(ctx->curl, CURLOPT_CONNECTTIMEOUT_MS,
                     (long)ctx->cfg.connect_timeout_ms);
    curl_easy_setopt(ctx->curl, CURLOPT_TIMEOUT_MS,
                     (long)ctx->cfg.request_timeout_ms);

    if (!ctx->cfg.verify_ssl) {
        curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    ctx->next_rule_id = 9000; /* start from 9000 to avoid colliding */

    return ctx;
}

void sdn_destroy(sdn_context_t *ctx)
{
    if (!ctx) return;
    if (ctx->curl) curl_easy_cleanup(ctx->curl);
    curl_global_cleanup();
    free(ctx);
}

/* ============================================================================
 * INTERNAL: perform a REST call
 * ============================================================================ */

typedef enum { HTTP_GET, HTTP_POST } http_method_t;

static int rest_call(sdn_context_t *ctx, http_method_t method,
                     const char *path, const char *body,
                     resp_buf_t *resp, long *http_code)
{
    char url[1024];
    snprintf(url, sizeof(url), "%s%s", ctx->cfg.controller_url, path);

    curl_easy_setopt(ctx->curl, CURLOPT_URL, url);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);

    resp_buf_reset(resp);
    curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, resp);

    switch (method) {
    case HTTP_GET:
        curl_easy_setopt(ctx->curl, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(ctx->curl, CURLOPT_CUSTOMREQUEST, NULL);
        break;
    case HTTP_POST:
        curl_easy_setopt(ctx->curl, CURLOPT_POST, 1L);
        curl_easy_setopt(ctx->curl, CURLOPT_CUSTOMREQUEST, NULL);
        curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, body ? body : "{}");
        break;
    }

    CURLcode res = curl_easy_perform(ctx->curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        fprintf(stderr, "[sentinel-sdn] curl error: %s\n",
                ctx->errbuf[0] ? ctx->errbuf : curl_easy_strerror(res));
        return -1;
    }

    long code = 0;
    curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &code);
    if (http_code) *http_code = code;

    return 0;
}

/* ============================================================================
 * JSON BUILDERS  (Ryu ofctl_rest format)
 * ============================================================================ */

/*
 * Build a Ryu ofctl_rest flow JSON for POST /stats/flowentry/add.
 *
 * Ryu format:
 * {
 *   "dpid": <dpid>,
 *   "cookie": <cookie>,
 *   "cookie_mask": <mask>,
 *   "table_id": <table>,
 *   "idle_timeout": <sec>,
 *   "hard_timeout": <sec>,
 *   "priority": <pri>,
 *   "match": {
 *     "dl_type": 2048,
 *     "nw_src": "x.x.x.x/N",
 *     "nw_dst": "x.x.x.x/N",
 *     "nw_proto": <proto>,
 *     "tp_src": <port>,
 *     "tp_dst": <port>
 *   },
 *   "actions": [
 *     {"type": "OUTPUT", "port": "NORMAL"}
 *   ]
 * }
 */
static int build_flow_json(uint64_t dpid, const sentinel_sdn_rule_t *rule,
                           char *buf, size_t buflen)
{
    char src_ip_str[INET_ADDRSTRLEN] = "";
    char dst_ip_str[INET_ADDRSTRLEN] = "";

    /* ---- match fields ---- */
    /* We build the match object piece by piece */
    char match_buf[1024];
    int mlen = 0;

    /* always match IPv4 */
    mlen += snprintf(match_buf + mlen, sizeof(match_buf) - (size_t)mlen,
                     "\"dl_type\": 2048");

    /* source IP */
    if (rule->match_src_ip != 0) {
        ip_to_str(rule->match_src_ip, src_ip_str, sizeof(src_ip_str));
        uint32_t mask = ntohl(rule->match_src_mask);
        int bits = 0;
        for (uint32_t m = mask; m & 0x80000000; m <<= 1) bits++;
        if (bits == 0) bits = 32;
        mlen += snprintf(match_buf + mlen, sizeof(match_buf) - (size_t)mlen,
                         ", \"nw_src\": \"%s/%d\"", src_ip_str, bits);
    }

    /* destination IP */
    if (rule->match_dst_ip != 0) {
        ip_to_str(rule->match_dst_ip, dst_ip_str, sizeof(dst_ip_str));
        uint32_t mask = ntohl(rule->match_dst_mask);
        int bits = 0;
        for (uint32_t m = mask; m & 0x80000000; m <<= 1) bits++;
        if (bits == 0) bits = 32;
        mlen += snprintf(match_buf + mlen, sizeof(match_buf) - (size_t)mlen,
                         ", \"nw_dst\": \"%s/%d\"", dst_ip_str, bits);
    }

    /* IP protocol */
    if (rule->match_protocol != 0) {
        mlen += snprintf(match_buf + mlen, sizeof(match_buf) - (size_t)mlen,
                         ", \"nw_proto\": %u", rule->match_protocol);

        /* L4 port matching (TCP=6 or UDP=17) */
        if (rule->match_src_port != 0) {
            mlen += snprintf(match_buf + mlen, sizeof(match_buf) - (size_t)mlen,
                             ", \"tp_src\": %u", ntohs(rule->match_src_port));
        }
        if (rule->match_dst_port != 0) {
            mlen += snprintf(match_buf + mlen, sizeof(match_buf) - (size_t)mlen,
                             ", \"tp_dst\": %u", ntohs(rule->match_dst_port));
        }
    }

    /* ---- actions ---- */
    char action_json[512] = "";

    switch (rule->action) {
    case SDN_ACTION_DROP:
        /* Ryu: empty actions list = drop */
        snprintf(action_json, sizeof(action_json), "[]");
        break;

    case SDN_ACTION_ALLOW:
        snprintf(action_json, sizeof(action_json),
                 "[{\"type\": \"OUTPUT\", \"port\": \"NORMAL\"}]");
        break;

    case SDN_ACTION_REDIRECT:
        snprintf(action_json, sizeof(action_json),
                 "[{\"type\": \"OUTPUT\", \"port\": %u}]",
                 rule->redirect_port);
        break;

    case SDN_ACTION_MIRROR:
        /* Mirror: output to both NORMAL and a mirror port */
        snprintf(action_json, sizeof(action_json),
                 "[{\"type\": \"OUTPUT\", \"port\": \"NORMAL\"}, "
                 "{\"type\": \"OUTPUT\", \"port\": %u}]",
                 rule->redirect_port);
        break;

    case SDN_ACTION_RATE_LIMIT:
        /*
         * Ryu supports meter bands for rate limiting via ofctl_rest when
         * using OpenFlow 1.3+.  For simplicity, we fall back to DROP.
         * A real deployment would POST /stats/meterentry/add first,
         * then reference the meter ID in the flow instructions.
         */
        snprintf(action_json, sizeof(action_json), "[]");
        break;
    }

    /* ---- cookie ---- */
    uint64_t cookie = SENTINEL_COOKIE_PREFIX | (uint64_t)rule->rule_id;

    const char *table = (rule->table_id[0] != '\0') ? rule->table_id : "0";
    int table_int = atoi(table);

    /* ---- assemble the full JSON ---- */
    int n = snprintf(buf, buflen,
        "{"
        "\"dpid\": %" PRIu64 ", "
        "\"cookie\": %" PRIu64 ", "
        "\"cookie_mask\": %" PRIu64 ", "
        "\"table_id\": %d, "
        "\"idle_timeout\": %u, "
        "\"hard_timeout\": %u, "
        "\"priority\": %u, "
        "\"match\": { %s }, "
        "\"actions\": %s"
        "}",
        dpid,
        cookie,
        SENTINEL_COOKIE_MASK,
        table_int,
        rule->idle_timeout,
        rule->hard_timeout,
        rule->priority,
        match_buf,
        action_json);

    return (n > 0 && (size_t)n < buflen) ? 0 : -1;
}

/*
 * Build a delete JSON for POST /stats/flowentry/delete_strict
 * Identifies the flow by cookie + match + priority.
 */
static int build_delete_json(uint64_t dpid, uint32_t rule_id,
                             int table_id, char *buf, size_t buflen)
{
    uint64_t cookie = SENTINEL_COOKIE_PREFIX | (uint64_t)rule_id;

    int n = snprintf(buf, buflen,
        "{"
        "\"dpid\": %" PRIu64 ", "
        "\"cookie\": %" PRIu64 ", "
        "\"cookie_mask\": %" PRIu64 ", "
        "\"table_id\": %d"
        "}",
        dpid, cookie, SENTINEL_COOKIE_MASK, table_id);

    return (n > 0 && (size_t)n < buflen) ? 0 : -1;
}

/*
 * Build a delete-by-src JSON for POST /stats/flowentry/delete
 * Matches any flow with the specified source IP.
 */
static int build_delete_by_src_json(uint64_t dpid, uint32_t src_ip,
                                    char *buf, size_t buflen)
{
    char src_str[INET_ADDRSTRLEN];
    ip_to_str(src_ip, src_str, sizeof(src_str));

    /* Only delete flows with our cookie prefix */
    int n = snprintf(buf, buflen,
        "{"
        "\"dpid\": %" PRIu64 ", "
        "\"cookie\": %" PRIu64 ", "
        "\"cookie_mask\": %" PRIu64 ", "
        "\"match\": {"
        "  \"dl_type\": 2048, "
        "  \"nw_src\": \"%s/32\""
        "}"
        "}",
        dpid, SENTINEL_COOKIE_PREFIX, SENTINEL_COOKIE_MASK, src_str);

    return (n > 0 && (size_t)n < buflen) ? 0 : -1;
}

/* ============================================================================
 * RULE MANAGEMENT
 * ============================================================================ */

int sdn_push_rule(sdn_context_t *ctx, const sentinel_sdn_rule_t *rule)
{
    if (!ctx || !rule) return -1;

    uint64_t dpid = (rule->node_id[0] != '\0')
                    ? parse_dpid(rule->node_id, ctx->cfg.default_dpid)
                    : ctx->cfg.default_dpid;

    char body[4096];
    if (build_flow_json(dpid, rule, body, sizeof(body)) != 0) {
        ctx->rules_failed++;
        return -1;
    }

    resp_buf_t resp = {0};
    long http_code = 0;
    int rc = rest_call(ctx, HTTP_POST, "/stats/flowentry/add",
                       body, &resp, &http_code);
    resp_buf_free(&resp);

    if (rc != 0 || http_code != 200) {
        fprintf(stderr, "[sentinel-sdn] push rule %u failed: HTTP %ld\n",
                rule->rule_id, http_code);
        ctx->rules_failed++;
        return -1;
    }

    ctx->rules_pushed++;
    return 0;
}

int sdn_remove_rule(sdn_context_t *ctx, uint32_t rule_id,
                    const char *node_id, const char *table_id)
{
    if (!ctx) return -1;

    uint64_t dpid = parse_dpid(node_id, ctx->cfg.default_dpid);
    int table = (table_id && table_id[0]) ? atoi(table_id)
                                          : atoi(ctx->cfg.default_table);

    char body[1024];
    if (build_delete_json(dpid, rule_id, table, body, sizeof(body)) != 0)
        return -1;

    resp_buf_t resp = {0};
    long http_code = 0;
    int rc = rest_call(ctx, HTTP_POST, "/stats/flowentry/delete_strict",
                       body, &resp, &http_code);
    resp_buf_free(&resp);

    if (rc != 0 || http_code != 200)
        return -1;
    return 0;
}

int sdn_remove_rules_for_src(sdn_context_t *ctx, uint32_t src_ip)
{
    if (!ctx) return -1;

    char body[1024];
    if (build_delete_by_src_json(ctx->cfg.default_dpid, src_ip,
                                 body, sizeof(body)) != 0)
        return -1;

    resp_buf_t resp = {0};
    long http_code = 0;
    int rc = rest_call(ctx, HTTP_POST, "/stats/flowentry/delete",
                       body, &resp, &http_code);
    resp_buf_free(&resp);

    if (rc != 0 || http_code != 200)
        return -1;
    return 0;
}

/* ============================================================================
 * THREAT-TO-RULE CONVERSION
 * ============================================================================ */

int sdn_build_rule_from_assessment(sdn_context_t *ctx,
                                   const sentinel_threat_assessment_t *a,
                                   sentinel_sdn_rule_t *r)
{
    if (!ctx || !a || !r) return -1;
    memset(r, 0, sizeof(*r));

    r->rule_id = ctx->next_rule_id++;

    /* match on source IP (exact), dest IP (exact), protocol */
    r->match_src_ip   = a->src_ip;
    r->match_src_mask = 0xFFFFFFFF;   /* /32 */
    r->match_dst_ip   = a->dst_ip;
    r->match_dst_mask = 0xFFFFFFFF;
    r->match_protocol = a->protocol;
    r->match_src_port = a->src_port;
    r->match_dst_port = a->dst_port;

    /* store dpid as string in node_id for compatibility */
    snprintf(r->node_id,  sizeof(r->node_id),  "%" PRIu64,
             ctx->cfg.default_dpid);
    snprintf(r->table_id, sizeof(r->table_id), "%s", ctx->cfg.default_table);

    /* origin info */
    r->triggered_by = a->attack_type;
    r->threat_score = a->threat_score;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    r->created_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    /* map verdict -> action + priority + timeouts */
    switch (a->verdict) {
    case VERDICT_ALLOW:
        r->action   = SDN_ACTION_ALLOW;
        r->priority = 100;
        r->idle_timeout = 300;
        r->hard_timeout = 600;
        break;

    case VERDICT_DROP:
        r->action   = SDN_ACTION_DROP;
        r->priority = 500;
        r->idle_timeout = 120;
        r->hard_timeout = 300;
        break;

    case VERDICT_RATE_LIMIT:
        r->action          = SDN_ACTION_RATE_LIMIT;
        r->rate_limit_kbps = a->rate_limit_pps * 2; /* rough kbps estimate */
        r->priority        = 400;
        r->idle_timeout    = 60;
        r->hard_timeout    = 180;
        break;

    case VERDICT_QUARANTINE:
        r->action   = SDN_ACTION_DROP;   /* quarantine = drop for now */
        r->priority = 600;
        r->idle_timeout = a->quarantine_sec;
        r->hard_timeout = a->quarantine_sec;
        break;

    case VERDICT_REDIRECT:
        r->action   = SDN_ACTION_REDIRECT;
        r->priority = 450;
        r->idle_timeout = 60;
        r->hard_timeout = 180;
        break;
    }

    /* higher threat -> higher priority (dynamic boost) */
    r->priority += (uint16_t)(a->threat_score * 100);

    return 0;
}

/* ============================================================================
 * HEALTH / DIAGNOSTICS
 * ============================================================================ */

int sdn_health_check(sdn_context_t *ctx)
{
    if (!ctx) return -1;

    resp_buf_t resp = {0};
    long http_code = 0;
    int rc = rest_call(ctx, HTTP_GET, "/stats/switches",
                       NULL, &resp, &http_code);
    resp_buf_free(&resp);

    if (rc != 0 || http_code != 200) return -1;
    return 0;
}

int sdn_get_flow_count(sdn_context_t *ctx, const char *node_id)
{
    if (!ctx) return -1;
    uint64_t dpid = parse_dpid(node_id, ctx->cfg.default_dpid);

    char path[256];
    snprintf(path, sizeof(path), "/stats/flow/%" PRIu64, dpid);

    resp_buf_t resp = {0};
    long http_code = 0;
    int rc = rest_call(ctx, HTTP_GET, path, NULL, &resp, &http_code);

    if (rc != 0 || http_code != 200) {
        resp_buf_free(&resp);
        return -1;
    }

    /*
     * Ryu returns: { "<dpid>": [ {flow1}, {flow2}, ... ] }
     * Count occurrences of "\"cookie\":" as a rough flow count.
     * A proper implementation would parse JSON with a library.
     */
    int count = 0;
    if (resp.data) {
        const char *p = resp.data;
        while ((p = strstr(p, "\"cookie\":")) != NULL) {
            count++;
            p += 9;
        }
    }
    resp_buf_free(&resp);
    return count;
}

uint64_t sdn_rules_pushed(const sdn_context_t *ctx)
{
    return ctx ? ctx->rules_pushed : 0;
}

uint64_t sdn_rules_failed(const sdn_context_t *ctx)
{
    return ctx ? ctx->rules_failed : 0;
}
