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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <time.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdatomic.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <pthread.h>

#include "sdn_controller.h"
#include "jsmn.h"

/* Sentinel flows use the top 32 bits of the 64-bit cookie for identification */
#define SENTINEL_COOKIE_PREFIX  UINT64_C(0x5E40000000000000)
#define SENTINEL_COOKIE_MASK    UINT64_C(0xFFFFFFFF00000000)

/* ============================================================================
 * CONTEXT
 * ============================================================================ */

/* Async queue definitions */
#define SDN_QUEUE_SIZE 65536
#define SDN_METER_TRACK 65536  /* Match queue size; used as hash table slots. */
static atomic_uint g_curl_users = 0;

struct sdn_context {
    sdn_config_t  cfg;
    CURL          *curl;
    atomic_uint_fast64_t rules_pushed;
    atomic_uint_fast64_t rules_failed;
    uint32_t       next_rule_id;
    char           errbuf[CURL_ERROR_SIZE];

    /* Async Thread State */
    pthread_t       worker_thread;
    int             worker_started;
    atomic_int      stop_worker;

    /* Lockless Rule Ring Buffer (SPSC) */
    sentinel_sdn_rule_t rule_queue[SDN_QUEUE_SIZE];
    atomic_uint         queue_head;
    atomic_uint         queue_tail;

    /* Rule indexing for O(1) rule removal */
    struct meter_node {
        uint32_t src_ip;
        uint32_t rule_id;
        struct meter_node *next_ip;   /* Link for IP-based hash table */
        struct meter_node *next_id;   /* Link for rule_id-based hash table */
    } *ip_ht[SDN_METER_TRACK], *id_ht[SDN_METER_TRACK];

    struct meter_node meter_slab[SDN_METER_TRACK];
    struct meter_node *meter_free;
    pthread_mutex_t     meter_track_mutex;
    pthread_mutex_t     curl_mutex;
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
        /* 10MB hard cap on response buffers to prevent heap exhaustion. */
        const size_t RESP_MAX = 10 * 1024 * 1024;
        size_t newcap = (buf->cap == 0) ? 4096 : buf->cap * 2;
        while (newcap < buf->len + total + 1) newcap *= 2;
        if (newcap > RESP_MAX) {
            if (buf->len + total + 1 > RESP_MAX) return 0; /* Too large */
            newcap = RESP_MAX;
        }
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

/* extract dpid from node_id string */
static uint64_t parse_dpid(const char *s, uint64_t fallback)
{
    if (!s || !s[0]) return fallback;
    if (strncmp(s, "openflow:", 9) == 0) s += 9;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (end == s) return fallback;
    return (uint64_t)v;
}

/* Fast FNV-1a hash for internal indexing */
static inline uint32_t fnv1a_hash(const void *key, size_t len)
{
    const uint8_t *data = (const uint8_t *)key;
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

/* Forward declaration for thread worker */
static void *sdn_worker(void *arg);

sdn_context_t *sdn_init(const sdn_config_t *cfg)
{
    sdn_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    if (cfg) ctx->cfg = *cfg;
    else {
        sdn_config_t def = SDN_CONFIG_DEFAULT;
        ctx->cfg = def;
    }

    unsigned int prev_users = atomic_fetch_add_explicit(&g_curl_users, 1, memory_order_acq_rel);
    if (prev_users == 0) {
        if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
            atomic_fetch_sub_explicit(&g_curl_users, 1, memory_order_acq_rel);
            free(ctx);
            return NULL;
        }
    }
    ctx->curl = curl_easy_init();
    if (!ctx->curl) {
        if (atomic_fetch_sub_explicit(&g_curl_users, 1, memory_order_acq_rel) == 1)
            curl_global_cleanup();
        free(ctx);
        return NULL;
    }

    pthread_mutex_init(&ctx->meter_track_mutex, NULL);
    pthread_mutex_init(&ctx->curl_mutex, NULL);

    /* Initialize rule-index hash tables and slab (O(1) indexing) */
    ctx->meter_free = &ctx->meter_slab[0];
    for (uint32_t i = 0; i + 1 < SDN_METER_TRACK; i++)
        ctx->meter_slab[i].next_id = &ctx->meter_slab[i + 1];
    ctx->meter_slab[SDN_METER_TRACK - 1].next_id = NULL;

    /* Init Lockless Pthreads */
    atomic_init(&ctx->queue_head, 0);
    atomic_init(&ctx->queue_tail, 0);
    atomic_init(&ctx->stop_worker, 0);
    
    ctx->errbuf[0] = '\0';
    curl_easy_setopt(ctx->curl, CURLOPT_ERRORBUFFER, ctx->errbuf);
    if (pthread_create(&ctx->worker_thread, NULL, sdn_worker, ctx) != 0) {
        pthread_mutex_destroy(&ctx->meter_track_mutex);
        pthread_mutex_destroy(&ctx->curl_mutex);
        curl_easy_cleanup(ctx->curl);
        if (atomic_fetch_sub_explicit(&g_curl_users, 1, memory_order_acq_rel) == 1)
            curl_global_cleanup();
        free(ctx);
        return NULL;
    }
    ctx->worker_started = 1;

    return ctx;
}

void sdn_destroy(sdn_context_t *ctx)
{
    if (!ctx) return;
    
    /* Stop thread gracefully */
    atomic_store_explicit(&ctx->stop_worker, 1, memory_order_relaxed);
    
    if (ctx->worker_started)
        pthread_join(ctx->worker_thread, NULL);

    pthread_mutex_destroy(&ctx->meter_track_mutex);
    pthread_mutex_destroy(&ctx->curl_mutex);
    
    if (ctx->curl) curl_easy_cleanup(ctx->curl);
    if (atomic_fetch_sub_explicit(&g_curl_users, 1, memory_order_acq_rel) == 1)
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
    if (ctx->cfg.auth_bearer_token[0] != '\0') {
        char auth_hdr[160];
        snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", ctx->cfg.auth_bearer_token);
        headers = curl_slist_append(headers, auth_hdr);
    }
    curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);

    resp_buf_reset(resp);
    curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, resp);

    /* Strictly enforce network resilience timeouts */
    curl_easy_setopt(ctx->curl, CURLOPT_CONNECTTIMEOUT_MS, (long)ctx->cfg.connect_timeout_ms);
    curl_easy_setopt(ctx->curl, CURLOPT_TIMEOUT_MS, (long)ctx->cfg.request_timeout_ms);
    curl_easy_setopt(ctx->curl, CURLOPT_LOW_SPEED_LIMIT, 100L);
    curl_easy_setopt(ctx->curl, CURLOPT_LOW_SPEED_TIME, 10L);
    curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYPEER, ctx->cfg.verify_ssl ? 1L : 0L);
    curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYHOST, ctx->cfg.verify_ssl ? 2L : 0L);

    switch (method) {
    case HTTP_GET:
        curl_easy_setopt(ctx->curl, CURLOPT_POST, 0L);
        curl_easy_setopt(ctx->curl, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(ctx->curl, CURLOPT_CUSTOMREQUEST, NULL);
        curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, NULL);
        break;
    case HTTP_POST:
        curl_easy_setopt(ctx->curl, CURLOPT_HTTPGET, 0L);
        curl_easy_setopt(ctx->curl, CURLOPT_POST, 1L);
        curl_easy_setopt(ctx->curl, CURLOPT_CUSTOMREQUEST, NULL);
        curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, body ? body : "{}");
        break;
    }

    ctx->errbuf[0] = '\0';
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
    /* Strict boundary check before every append to prevent overflow. */
    char match_buf[1024];
    int mlen = 0;
    size_t match_cap = sizeof(match_buf);

    /* always match IPv4 */
    if (match_cap - (size_t)mlen <= 0) return -1;
    { int n = snprintf(match_buf + mlen, match_cap - (size_t)mlen, "\"dl_type\": 2048"); if (n < 0 || (size_t)(mlen + n) >= match_cap) return -1; mlen += n; }

    /* source IP */
    if (rule->match_src_ip != 0) {
        ip_to_str(rule->match_src_ip, src_ip_str, sizeof(src_ip_str));
        uint32_t mask = ntohl(rule->match_src_mask);
        int bits = 0;
        for (uint32_t m = mask; m & 0x80000000; m <<= 1) bits++;
        if (bits == 0) bits = 32;
        if (match_cap - (size_t)mlen <= 0) return -1;
        { int n = snprintf(match_buf + mlen, match_cap - (size_t)mlen, ", \"nw_src\": \"%s/%d\"", src_ip_str, bits); if (n < 0 || (size_t)(mlen + n) >= match_cap) return -1; mlen += n; }
    }

    /* destination IP */
    if (rule->match_dst_ip != 0) {
        ip_to_str(rule->match_dst_ip, dst_ip_str, sizeof(dst_ip_str));
        uint32_t mask = ntohl(rule->match_dst_mask);
        int bits = 0;
        for (uint32_t m = mask; m & 0x80000000; m <<= 1) bits++;
        if (bits == 0) bits = 32;
        if (match_cap - (size_t)mlen <= 0) return -1;
        { int n = snprintf(match_buf + mlen, match_cap - (size_t)mlen, ", \"nw_dst\": \"%s/%d\"", dst_ip_str, bits); if (n < 0 || (size_t)(mlen + n) >= match_cap) return -1; mlen += n; }
    }

    /* IP protocol */
    if (rule->match_protocol != 0) {
        if (match_cap - (size_t)mlen <= 0) return -1;
        { int n = snprintf(match_buf + mlen, match_cap - (size_t)mlen, ", \"nw_proto\": %u", rule->match_protocol); if (n < 0 || (size_t)(mlen + n) >= match_cap) return -1; mlen += n; }
        if (rule->match_src_port != 0) {
            if (match_cap - (size_t)mlen <= 0) return -1;
            { int n = snprintf(match_buf + mlen, match_cap - (size_t)mlen, ", \"tp_src\": %u", ntohs(rule->match_src_port)); if (n < 0 || (size_t)(mlen + n) >= match_cap) return -1; mlen += n; }
        }
        if (rule->match_dst_port != 0) {
            if (match_cap - (size_t)mlen <= 0) return -1;
            { int n = snprintf(match_buf + mlen, match_cap - (size_t)mlen, ", \"tp_dst\": %u", ntohs(rule->match_dst_port)); if (n < 0 || (size_t)(mlen + n) >= match_cap) return -1; mlen += n; }
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
        /* OpenFlow 1.3 metering: flow references meter_id (meter added separately).
         * Traffic is rate-limited by the switch; excess dropped by meter band. */
        snprintf(action_json, sizeof(action_json),
                 "[{\"type\": \"METER\", \"meter_id\": %u}, "
                 "{\"type\": \"APPLY_ACTIONS\", \"actions\": [{\"type\": \"OUTPUT\", \"port\": \"NORMAL\"}]}]",
                 rule->rule_id);
        break;
    }

    /* ---- cookie: prefix + full 32-bit rule_id for stable strict-delete matching ---- */
    uint64_t cookie = SENTINEL_COOKIE_PREFIX | (uint64_t)rule->rule_id;

    /* Ryu ofctl_rest: Sentinel Droplist rules as high-priority overrides (table 0, priority 65535) */
    int table_int = (rule->table_id[0] != '\0') ? atoi(rule->table_id) : 0;
    uint32_t priority = (rule->priority != 0) ? rule->priority : 65535;

    /* ---- assemble the full JSON ---- */
    int n;
    if (rule->action == SDN_ACTION_RATE_LIMIT) {
        /* OpenFlow 1.3: use "instructions" (METER + APPLY_ACTIONS) instead of "actions" */
        n = snprintf(buf, buflen,
            "{"
            "\"dpid\": %" PRIu64 ", "
            "\"cookie\": %" PRIu64 ", "
            "\"cookie_mask\": %" PRIu64 ", "
            "\"table_id\": %d, "
            "\"idle_timeout\": %u, "
            "\"hard_timeout\": %u, "
            "\"priority\": %u, "
            "\"match\": { %s }, "
            "\"instructions\": %s"
            "}",
            dpid,
            cookie,
            SENTINEL_COOKIE_MASK,
            table_int,
            rule->idle_timeout,
            rule->hard_timeout,
            priority,
            match_buf,
            action_json);
    } else {
        n = snprintf(buf, buflen,
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
            priority,
            match_buf,
            action_json);
    }

    return (n > 0 && (size_t)n < buflen) ? 0 : -1;
}

/*
 * Build meter entry JSON for POST /stats/meterentry/add (OpenFlow 1.3).
 * rate_kbps: limit in kbps; band type DROP drops excess. Rate in OF is 1/1000 kbps.
 */
static int build_meter_json(uint64_t dpid, uint32_t meter_id, uint32_t rate_kbps,
                            char *buf, size_t buflen)
{
    /* OF 1.3: rate in 1/1000 of 1 kbps, burst_size in kb. Use burst 2 kb. */
    uint32_t of_rate = (rate_kbps > 0) ? (rate_kbps * 1000) : 1000000;
    if (of_rate == 0) of_rate = 1000;
    int n = snprintf(buf, buflen,
        "{"
        "\"dpid\": %" PRIu64 ", "
        "\"meter_id\": %u, "
        "\"flags\": 0, "
        "\"bands\": [{\"type\": \"DROP\", \"rate\": %u, \"burst_size\": 2000}]"
        "}",
        dpid, meter_id, of_rate);
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
 * Build JSON for POST /stats/meterentry/delete (OpenFlow 1.3).
 * Prevents meter leak when flow is removed.
 */
static int build_meter_delete_json(uint64_t dpid, uint32_t meter_id,
                                   char *buf, size_t buflen)
{
    int n = snprintf(buf, buflen,
        "{"
        "\"dpid\": %" PRIu64 ", "
        "\"meter_id\": %u"
        "}",
        dpid, meter_id);
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

static int build_flow_json(uint64_t dpid, const sentinel_sdn_rule_t *rule,
                           char *buf, size_t buflen); /* Forward decl needed now */

/* 
 * Async Background Thread
 * Picks up enqueued structs and POSTs them to Ryu using libcurl 
 */
static void *sdn_worker(void *arg)
{
    sdn_context_t *ctx = (sdn_context_t *)arg;

    while (1) {
        uint32_t tail = atomic_load_explicit(&ctx->queue_tail, memory_order_relaxed);
        uint32_t head = atomic_load_explicit(&ctx->queue_head, memory_order_acquire);

        if (tail == head) {
            if (atomic_load_explicit(&ctx->stop_worker, memory_order_relaxed)) {
                break;
            }
            /* Backoff sleep when empty */
            struct timespec req = {0, 1000000}; /* 1ms sleep avoids 100% CPU lock while keeping low latency */
            nanosleep(&req, NULL);
            continue;
        }

        sentinel_sdn_rule_t rule = ctx->rule_queue[tail];
        
        uint32_t next_tail = (tail + 1) & (SDN_QUEUE_SIZE - 1);
        atomic_store_explicit(&ctx->queue_tail, next_tail, memory_order_release);

        /* Process HTTP call outside ring bounds */
        uint64_t dpid = (rule.node_id[0] != '\0')
                        ? parse_dpid(rule.node_id, ctx->cfg.default_dpid)
                        : ctx->cfg.default_dpid;

        /* VERDICT_RATE_LIMIT: create meter before installing flow entry. */
        int meter_added = 0;
        if (rule.action == SDN_ACTION_RATE_LIMIT) {
            char meter_body[512];
            if (build_meter_json(dpid, rule.rule_id,
                                 rule.rate_limit_kbps ? rule.rate_limit_kbps : 1000,
                                 meter_body, sizeof(meter_body)) == 0) {
                resp_buf_t mresp = {0};
                long mcode = 0;
                pthread_mutex_lock(&ctx->curl_mutex);
                int mrc = rest_call(ctx, HTTP_POST, "/stats/meterentry/add", meter_body, &mresp, &mcode);
                pthread_mutex_unlock(&ctx->curl_mutex);
                resp_buf_free(&mresp);
                if (mrc == 0 && mcode == 200)
                    meter_added = 1;
            }
            if (!meter_added) {
                fprintf(stderr, "[sentinel-sdn] meter create failed for rule %u\n", rule.rule_id);
                atomic_fetch_add_explicit(&ctx->rules_failed, 1, memory_order_relaxed);
                continue;
            }
        }

        char body[4096];
        if (build_flow_json(dpid, &rule, body, sizeof(body)) != 0) {
            if (meter_added) {
                char meter_del[256];
                if (build_meter_delete_json(dpid, rule.rule_id, meter_del, sizeof(meter_del)) == 0) {
                    resp_buf_t mresp = {0};
                    long mcode = 0;
                    pthread_mutex_lock(&ctx->curl_mutex);
                    rest_call(ctx, HTTP_POST, "/stats/meterentry/delete", meter_del, &mresp, &mcode);
                    pthread_mutex_unlock(&ctx->curl_mutex);
                    resp_buf_free(&mresp);
                }
            }
            atomic_fetch_add_explicit(&ctx->rules_failed, 1, memory_order_relaxed);
            continue;
        }

        /* Process rule via HTTP call */

        resp_buf_t resp = {0};
        long http_code = 0;
        pthread_mutex_lock(&ctx->curl_mutex);
        int rc = rest_call(ctx, HTTP_POST, "/stats/flowentry/add",
                           body, &resp, &http_code);
        pthread_mutex_unlock(&ctx->curl_mutex);
        resp_buf_free(&resp);

        if (rc != 0 || http_code != 200) {
            fprintf(stderr, "[sentinel-sdn] async push rule %u failed: HTTP %ld\n",
                    rule.rule_id, http_code);
            if (meter_added) {
                char meter_del[256];
                if (build_meter_delete_json(dpid, rule.rule_id, meter_del, sizeof(meter_del)) == 0) {
                    resp_buf_t mresp = {0};
                    long mcode = 0;
                    pthread_mutex_lock(&ctx->curl_mutex);
                    rest_call(ctx, HTTP_POST, "/stats/meterentry/delete", meter_del, &mresp, &mcode);
                    pthread_mutex_unlock(&ctx->curl_mutex);
                    resp_buf_free(&mresp);
                }
            }
            atomic_fetch_add_explicit(&ctx->rules_failed, 1, memory_order_relaxed);
        } else {
            if (rule.action == SDN_ACTION_RATE_LIMIT) {
                int tracked = 0;
                pthread_mutex_lock(&ctx->meter_track_mutex);
                if (ctx->meter_free) {
                    struct meter_node *n = ctx->meter_free;
                    ctx->meter_free = n->next_id;
                    memset(n, 0, sizeof(*n));
                    n->src_ip = rule.match_src_ip;
                    n->rule_id = rule.rule_id;
                    uint32_t h_ip = fnv1a_hash(&n->src_ip, 4) & (SDN_METER_TRACK - 1);
                    n->next_ip = ctx->ip_ht[h_ip];
                    ctx->ip_ht[h_ip] = n;
                    uint32_t h_id = fnv1a_hash(&n->rule_id, 4) & (SDN_METER_TRACK - 1);
                    n->next_id = ctx->id_ht[h_id];
                    ctx->id_ht[h_id] = n;
                    tracked = 1;
                } else {
                    fprintf(stderr, "[sentinel-sdn] meter tracking exhausted for rule %u\n", rule.rule_id);
                }
                pthread_mutex_unlock(&ctx->meter_track_mutex);
                if (!tracked) {
                    char meter_del[256];
                    if (build_meter_delete_json(dpid, rule.rule_id, meter_del, sizeof(meter_del)) == 0) {
                        resp_buf_t mresp = {0};
                        long mcode = 0;
                        pthread_mutex_lock(&ctx->curl_mutex);
                        rest_call(ctx, HTTP_POST, "/stats/meterentry/delete", meter_del, &mresp, &mcode);
                        pthread_mutex_unlock(&ctx->curl_mutex);
                        resp_buf_free(&mresp);
                    }
                    atomic_fetch_add_explicit(&ctx->rules_failed, 1, memory_order_relaxed);
                    continue;
                }
            }
            atomic_fetch_add_explicit(&ctx->rules_pushed, 1, memory_order_relaxed);
        }
    }

    return NULL;
}

int sdn_push_rule(sdn_context_t *ctx, const sentinel_sdn_rule_t *rule)
{
    if (!ctx || !rule) return -1;

    /* Lockless Hotpath Push */
    uint32_t head = atomic_load_explicit(&ctx->queue_head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&ctx->queue_tail, memory_order_acquire);

    uint32_t next_head = (head + 1) & (SDN_QUEUE_SIZE - 1);
    if (next_head == tail) {
        atomic_fetch_add_explicit(&ctx->rules_failed, 1, memory_order_relaxed);
        return SDN_ERR_QUEUE_FULL;
    }

    ctx->rule_queue[head] = *rule;
    atomic_store_explicit(&ctx->queue_head, next_head, memory_order_release);

    return 0;
}

int sdn_remove_rule(sdn_context_t *ctx, uint32_t rule_id,
                    const char *node_id, const char *table_id)
{
    if (!ctx) return -1;

    uint64_t dpid = parse_dpid(node_id, ctx->cfg.default_dpid);
    int table = (table_id && table_id[0]) ? (int)strtol(table_id, NULL, 10)
                                          : (int)strtol(ctx->cfg.default_table, NULL, 10);

    /* Delete meter first (rule_id was used as meter_id for RATE_LIMIT); avoid TCAM/meter leak. */
    char meter_body[256];
    if (build_meter_delete_json(dpid, rule_id, meter_body, sizeof(meter_body)) == 0) {
        resp_buf_t mresp = {0};
        long mcode = 0;
        pthread_mutex_lock(&ctx->curl_mutex);
        rest_call(ctx, HTTP_POST, "/stats/meterentry/delete", meter_body, &mresp, &mcode);
        pthread_mutex_unlock(&ctx->curl_mutex);
        resp_buf_free(&mresp);
    }

    /* Clean up index when rule is removed (O(1) chain removal). */
    pthread_mutex_lock(&ctx->meter_track_mutex);
    uint32_t h_id = fnv1a_hash(&rule_id, 4) & (SDN_METER_TRACK - 1);
    struct meter_node **curr_id = &ctx->id_ht[h_id];
    while (*curr_id) {
        if ((*curr_id)->rule_id == rule_id) {
            struct meter_node *n = *curr_id;
            *curr_id = n->next_id;

            /* Also unlink from IP table */
            uint32_t h_ip = fnv1a_hash(&n->src_ip, 4) & (SDN_METER_TRACK - 1);
            struct meter_node **curr_ip = &ctx->ip_ht[h_ip];
            while (*curr_ip) {
                if (*curr_ip == n) {
                    *curr_ip = n->next_ip;
                    break;
                }
                curr_ip = &(*curr_ip)->next_ip;
            }
            /* Recycle node to slab */
            n->next_id = ctx->meter_free;
            ctx->meter_free = n;
            break;
        }
        curr_id = &(*curr_id)->next_id;
    }
    pthread_mutex_unlock(&ctx->meter_track_mutex);

    char body[1024];
    if (build_delete_json(dpid, rule_id, table, body, sizeof(body)) != 0)
        return -1;

    resp_buf_t resp = {0};
    long http_code = 0;
    pthread_mutex_lock(&ctx->curl_mutex);
    int rc = rest_call(ctx, HTTP_POST, "/stats/flowentry/delete_strict",
                       body, &resp, &http_code);
    pthread_mutex_unlock(&ctx->curl_mutex);
    resp_buf_free(&resp);

    if (rc != 0 || http_code != 200)
        return -1;
    return 0;
}

#define SDN_METER_TRACK_MAX SDN_METER_TRACK

int sdn_remove_rules_for_src(sdn_context_t *ctx, uint32_t src_ip)
{
    if (!ctx) return -1;

    uint64_t dpid = ctx->cfg.default_dpid;
    uint32_t rule_ids[SDN_METER_TRACK_MAX];
    uint32_t n_to_delete = 0;

    pthread_mutex_lock(&ctx->meter_track_mutex);
    uint32_t h_ip = fnv1a_hash(&src_ip, 4) & (SDN_METER_TRACK - 1);
    struct meter_node *n = ctx->ip_ht[h_ip];
    while (n) {
        if (n->src_ip == src_ip) {
            if (n_to_delete < SDN_METER_TRACK_MAX) {
                rule_ids[n_to_delete++] = n->rule_id;
            }
            /* Collect node for recycling (deferred until after loop for safety) */
        }
        n = n->next_ip;
    }

    /* Atomically clear IP chain and recycle nodes (O(1) reset) */
    struct meter_node *node = ctx->ip_ht[h_ip];
    struct meter_node *prev = NULL;
    while (node) {
        struct meter_node *next = node->next_ip;
        if (node->src_ip == src_ip) {
            /* Unlink from ID table too */
            uint32_t h_id = fnv1a_hash(&node->rule_id, 4) & (SDN_METER_TRACK - 1);
            struct meter_node **curr_id = &ctx->id_ht[h_id];
            while (*curr_id) {
                if (*curr_id == node) {
                    *curr_id = node->next_id;
                    break;
                }
                curr_id = &(*curr_id)->next_id;
            }
            /* Unlink from IP table */
            if (prev) prev->next_ip = next;
            else ctx->ip_ht[h_ip] = next;
            /* Recycle */
            node->next_id = ctx->meter_free;
            ctx->meter_free = node;
        } else {
            prev = node;
        }
    node = next;
    }
    pthread_mutex_unlock(&ctx->meter_track_mutex);

    for (uint32_t j = 0; j < n_to_delete; j++) {
        char meter_body[256];
        if (build_meter_delete_json(dpid, rule_ids[j], meter_body, sizeof(meter_body)) == 0) {
            resp_buf_t mresp = {0};
            long mcode = 0;
            pthread_mutex_lock(&ctx->curl_mutex);
            rest_call(ctx, HTTP_POST, "/stats/meterentry/delete", meter_body, &mresp, &mcode);
            pthread_mutex_unlock(&ctx->curl_mutex);
            resp_buf_free(&mresp);
        }
    }

    char body[1024];
    if (build_delete_by_src_json(dpid, src_ip, body, sizeof(body)) != 0)
        return -1;

    resp_buf_t resp = {0};
    long http_code = 0;
    pthread_mutex_lock(&ctx->curl_mutex);
    int rc = rest_call(ctx, HTTP_POST, "/stats/flowentry/delete",
                       body, &resp, &http_code);
    pthread_mutex_unlock(&ctx->curl_mutex);
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
        r->priority = 65535; /* Absolute priority for DDoS mitigation */
        r->idle_timeout = 120;
        r->hard_timeout = 300;
        break;

    case VERDICT_RATE_LIMIT:
        r->action          = SDN_ACTION_RATE_LIMIT;
        /* rate_limit_kbps used by async worker for POST /stats/meterentry/add to Ryu */
        {
            uint64_t kbps = (uint64_t)a->rate_limit_pps * 2ULL; /* rough kbps estimate */
            if (kbps > 0xFFFFFFFFULL) kbps = 0xFFFFFFFFULL;
            r->rate_limit_kbps = (uint32_t)kbps;
        }
        r->priority        = 400;
        r->idle_timeout    = 60;
        r->hard_timeout    = 180;
        break;

    case VERDICT_QUARANTINE:
        r->action   = SDN_ACTION_DROP;   /* quarantine = drop for now */
        r->priority = 65535;
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

    /* higher threat -> higher priority (dynamic boost), saturated to OpenFlow max */
    {
        uint32_t p = r->priority;
        uint32_t boost = (uint32_t)(a->threat_score * 100.0);
        if (boost > 100) boost = 100;
        p += boost;
        if (p > 65535U) p = 65535U;
        r->priority = (uint16_t)p;
    }

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
    pthread_mutex_lock(&ctx->curl_mutex);
    int rc = rest_call(ctx, HTTP_GET, "/stats/switches",
                       NULL, &resp, &http_code);
    pthread_mutex_unlock(&ctx->curl_mutex);
    resp_buf_free(&resp);

    if (rc != 0 || http_code != 200) return -1;
    return 0;
}

int sdn_is_saturated(const sdn_context_t *ctx)
{
    if (!ctx) return 0;
    uint32_t head = atomic_load_explicit(&ctx->queue_head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&ctx->queue_tail, memory_order_relaxed);
    uint32_t fill = (head - tail) & (SDN_QUEUE_SIZE - 1);
    return (fill > (SDN_QUEUE_SIZE * 9) / 10); /* > 90% full */
}

/* Strict JSMN token skip: return index past token at idx and all descendants (nested object/array). */
static unsigned int skip_jsmn_tokens(const jsmntok_t *tokens, unsigned int n, unsigned int idx)
{
    if (idx >= n) return idx;
    const jsmntok_t *t = &tokens[idx];
    unsigned int next = idx + 1;
    
    /* JSMN_OBJECT size is number of members (pairs). 
     * JSMN_ARRAY size is number of elements. 
     * In both cases, we must skip 'size' child tokens recursively.
     * Note: In JSMN, for OBJECTs, each member is TWO tokens (key and value).
     */
    int children = t->size;
    if (t->type == JSMN_OBJECT) children *= 2;

    for (int i = 0; i < children && next < n; i++)
        next = skip_jsmn_tokens(tokens, n, next);
    return next;
}

int sdn_get_flow_count(sdn_context_t *ctx, const char *node_id)
{
    if (!ctx) return -1;
    uint64_t dpid = parse_dpid(node_id, ctx->cfg.default_dpid);

    char path[256];
    snprintf(path, sizeof(path), "/stats/flow/%" PRIu64, dpid);

    resp_buf_t resp = {0};
    long http_code = 0;
    pthread_mutex_lock(&ctx->curl_mutex);
    int rc = rest_call(ctx, HTTP_GET, path, NULL, &resp, &http_code);
    pthread_mutex_unlock(&ctx->curl_mutex);

    if (rc != 0 || http_code != 200) {
        resp_buf_free(&resp);
        return -1;
    }

    /*
     * Ryu returns: { "<dpid>": [ {flow1}, {flow2}, ... ] }.
     * Parse using expandable token buffer.
     */
    int count = 0;
    if (resp.data && resp.len > 0) {
        char dpid_str[32];
        snprintf(dpid_str, sizeof(dpid_str), "%" PRIu64, dpid);
        size_t dpid_len = strlen(dpid_str);
        const char *js = resp.data;

        int ntok = 1024;
        jsmntok_t *tokens = malloc(ntok * sizeof(jsmntok_t));
        if (!tokens) {
            resp_buf_free(&resp);
            return 0;
        }

        while (1) {
            jsmn_parser parser;
            jsmn_init(&parser);
            int n = jsmn_parse(&parser, js, resp.len, tokens, ntok);
            if (n >= 0) {
                if (n > 0 && tokens[0].type == JSMN_OBJECT && tokens[0].size > 0) {
                    unsigned int pos = 1;
                    int npairs = tokens[0].size;
                    for (int p = 0; p < npairs && pos < (unsigned int)n; p++) {
                        const jsmntok_t *key_tok = &tokens[pos];
                        if (key_tok->type != JSMN_STRING) {
                            pos = skip_jsmn_tokens(tokens, (unsigned int)n, pos);
                            continue;
                        }
                        int key_len = key_tok->end - key_tok->start;
                        /* Fix: use resp.len instead of undefined js_len */
                        if (key_len <= 0 || key_tok->start < 0 || (size_t)key_tok->end > resp.len) {
                            pos = skip_jsmn_tokens(tokens, (unsigned int)n, pos);
                            continue;
                        }
                        if ((size_t)key_len == dpid_len &&
                            strncmp(js + key_tok->start, dpid_str, dpid_len) == 0) {
                            pos++;
                            if (pos < (unsigned int)n && tokens[pos].type == JSMN_ARRAY)
                                count = tokens[pos].size;
                            break;
                        }
                        pos++;
                        if (pos < (unsigned int)n)
                            pos = skip_jsmn_tokens(tokens, (unsigned int)n, pos);
                    }
                }
                break;
            }
            if (n != JSMN_ERROR_NOMEM || ntok >= 65536) break;
            int next_ntok = ntok * 2;
            jsmntok_t *tmp = realloc(tokens, next_ntok * sizeof(jsmntok_t));
            if (!tmp) break;
            tokens = tmp;
            ntok = next_ntok;
        }
        free(tokens);
    }
    resp_buf_free(&resp);
    return count;
}

uint64_t sdn_rules_pushed(const sdn_context_t *ctx)
{
    return ctx ? atomic_load_explicit(&ctx->rules_pushed, memory_order_relaxed) : 0;
}

uint64_t sdn_rules_failed(const sdn_context_t *ctx)
{
    return ctx ? atomic_load_explicit(&ctx->rules_failed, memory_order_relaxed) : 0;
}
