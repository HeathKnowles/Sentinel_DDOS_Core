/*
 * Sentinel DDoS Core - WebSocket Server Implementation
 *
 * Lightweight WebSocket server using POSIX sockets + HTTP upgrade.
 * Broadcasts JSON data to all connected clients.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "websocket_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <endian.h>
#include <openssl/sha.h>

/* Simple WebSocket implementation */
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_MAX_FRAME_SIZE (64 * 1024)

/* WebSocket opcodes */
#define WS_OPCODE_TEXT   0x1
#define WS_OPCODE_CLOSE  0x8
#define WS_OPCODE_PING   0x9
#define WS_OPCODE_PONG   0xA

/* ============================================================================
 * CLIENT STATE
 * ============================================================================ */

typedef struct ws_client {
    int      fd;
    int      handshake_done;
    time_t   last_ping;
    char     remote_addr[64];
} ws_client_t;

/* ============================================================================
 * CONTEXT
 * ============================================================================ */

#define MAX_PENDING_MESSAGES 1000

typedef struct pending_message {
    char     *data;
    size_t    len;
    uint64_t  seq;
} pending_message_t;

struct ws_context {
    ws_config_t      cfg;
    int              listen_fd;
    pthread_t        thread;
    volatile int     running;
    
    /* Client management */
    ws_client_t      clients[100];
    int              client_count;
    pthread_mutex_t  client_mutex;
    
    /* Message queue (ring buffer) */
    pending_message_t messages[MAX_PENDING_MESSAGES];
    uint32_t          msg_head;
    uint32_t          msg_tail;
    pthread_mutex_t   msg_mutex;
    
    /* Statistics */
    uint64_t         messages_sent;
    uint64_t         messages_dropped;
};

/* ============================================================================
 * BASE64 ENCODING (for WebSocket handshake)
 * ============================================================================ */

static const char b64_table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const unsigned char *in, size_t len, char *out)
{
    size_t i, j;
    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        uint32_t v = (in[i] << 16) | 
                     ((i + 1 < len) ? (in[i + 1] << 8) : 0) | 
                     ((i + 2 < len) ? in[i + 2] : 0);
        out[j]     = b64_table[(v >> 18) & 0x3F];
        out[j + 1] = b64_table[(v >> 12) & 0x3F];
        out[j + 2] = (i + 1 < len) ? b64_table[(v >> 6) & 0x3F] : '=';
        out[j + 3] = (i + 2 < len) ? b64_table[v & 0x3F] : '=';
    }
    out[j] = '\0';
}

/* SHA-1 for WebSocket handshake using OpenSSL */
static void sha1_hash(const unsigned char *msg, size_t len, unsigned char hash[20])
{
    SHA1(msg, len, hash);
}

/* ============================================================================
 * WEBSOCKET FRAME ENCODING
 * ============================================================================ */

static int ws_send_frame(int fd, uint8_t opcode, const char *data, size_t len)
{
    unsigned char header[10];
    size_t hdr_len = 2;
    
    header[0] = 0x80 | (opcode & 0x0F);  /* FIN + opcode */
    
    if (len < 126) {
        header[1] = (uint8_t)len;
    } else if (len < 65536) {
        header[1] = 126;
        header[2] = (len >> 8) & 0xFF;
        header[3] = len & 0xFF;
        hdr_len = 4;
    } else {
        header[1] = 127;
        for (int i = 0; i < 8; i++)
            header[2 + i] = (len >> (56 - i * 8)) & 0xFF;
        hdr_len = 10;
    }
    
    if (send(fd, header, hdr_len, MSG_NOSIGNAL) < 0)
        return -1;
    if (len > 0 && send(fd, data, len, MSG_NOSIGNAL) < 0)
        return -1;
    return 0;
}

/* ============================================================================
 * WEBSOCKET HANDSHAKE
 * ============================================================================ */

static int ws_handshake(int fd, const char *request)
{
    char key[256] = {0};
    const char *p = strstr(request, "Sec-WebSocket-Key:");
    if (!p) return -1;
    
    p += 18;
    while (*p == ' ') p++;
    
    char *end = strchr(p, '\r');
    if (!end || end - p > 255) return -1;
    memcpy(key, p, end - p);
    
    /* Compute accept key: SHA1(key + GUID) */
    char combined[512];
    snprintf(combined, sizeof(combined), "%s%s", key, WS_GUID);
    
    unsigned char hash[20];
    sha1_hash((unsigned char *)combined, strlen(combined), hash);
    
    char accept[64];
    base64_encode(hash, 20, accept);
    
    /* Send HTTP 101 Switching Protocols */
    char response[1024];
    int n = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n", accept);
    
    return send(fd, response, n, MSG_NOSIGNAL) > 0 ? 0 : -1;
}

/* ============================================================================
 * CLIENT MANAGEMENT
 * ============================================================================ */

static void ws_add_client(ws_context_t *ctx, int fd, const char *addr)
{
    pthread_mutex_lock(&ctx->client_mutex);
    
    if (ctx->client_count < ctx->cfg.max_clients) {
        ws_client_t *c = &ctx->clients[ctx->client_count++];
        c->fd = fd;
        c->handshake_done = 0;
        c->last_ping = time(NULL);
        snprintf(c->remote_addr, sizeof(c->remote_addr), "%s", addr);
    } else {
        close(fd);
    }
    
    pthread_mutex_unlock(&ctx->client_mutex);
}

static void ws_remove_client(ws_context_t *ctx, int fd)
{
    /* NOTE: caller must NOT hold client_mutex */
    pthread_mutex_lock(&ctx->client_mutex);
    
    for (int i = 0; i < ctx->client_count; i++) {
        if (ctx->clients[i].fd == fd) {
            close(fd);
            /* Shift remaining clients */
            for (int j = i; j < ctx->client_count - 1; j++)
                ctx->clients[j] = ctx->clients[j + 1];
            ctx->client_count--;
            break;
        }
    }
    
    pthread_mutex_unlock(&ctx->client_mutex);
}

/* Remove a client by index; caller MUST hold client_mutex */
static void ws_remove_client_locked(ws_context_t *ctx, int idx)
{
    close(ctx->clients[idx].fd);
    for (int j = idx; j < ctx->client_count - 1; j++)
        ctx->clients[j] = ctx->clients[j + 1];
    ctx->client_count--;
}

/* ============================================================================
 * MESSAGE QUEUE
 * ============================================================================ */

static void ws_queue_message(ws_context_t *ctx, const char *json)
{
    pthread_mutex_lock(&ctx->msg_mutex);
    
    uint32_t next = (ctx->msg_tail + 1) % MAX_PENDING_MESSAGES;
    if (next == ctx->msg_head) {
        /* Queue full, drop oldest */
        free(ctx->messages[ctx->msg_head].data);
        ctx->msg_head = (ctx->msg_head + 1) % MAX_PENDING_MESSAGES;
        ctx->messages_dropped++;
    }
    
    ctx->messages[ctx->msg_tail].data = strdup(json);
    ctx->messages[ctx->msg_tail].len = strlen(json);
    ctx->msg_tail = next;
    
    pthread_mutex_unlock(&ctx->msg_mutex);
}

static int ws_dequeue_message(ws_context_t *ctx, char **data, size_t *len)
{
    pthread_mutex_lock(&ctx->msg_mutex);
    
    if (ctx->msg_head == ctx->msg_tail) {
        pthread_mutex_unlock(&ctx->msg_mutex);
        return 0;  /* Empty */
    }
    
    *data = ctx->messages[ctx->msg_head].data;
    *len = ctx->messages[ctx->msg_head].len;
    ctx->msg_head = (ctx->msg_head + 1) % MAX_PENDING_MESSAGES;
    
    pthread_mutex_unlock(&ctx->msg_mutex);
    return 1;
}

/* ============================================================================
 * SERVER THREAD
 * ============================================================================ */

static void *ws_server_thread(void *arg)
{
    ws_context_t *ctx = (ws_context_t *)arg;
    char buf[8192];
    
    while (ctx->running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(ctx->listen_fd, &readfds);
        
        int max_fd = ctx->listen_fd;
        
        pthread_mutex_lock(&ctx->client_mutex);
        for (int i = 0; i < ctx->client_count; i++) {
            FD_SET(ctx->clients[i].fd, &readfds);
            if (ctx->clients[i].fd > max_fd)
                max_fd = ctx->clients[i].fd;
        }
        pthread_mutex_unlock(&ctx->client_mutex);
        
        struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };  /* 100ms */
        int n = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        /* Accept new connections */
        if (FD_ISSET(ctx->listen_fd, &readfds)) {
            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);
            int fd = accept(ctx->listen_fd, (struct sockaddr *)&addr, &len);
            if (fd >= 0) {
                /* Set non-blocking so recv() won't stall the thread */
                int flags = fcntl(fd, F_GETFL, 0);
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);
                
                char ip[64];
                inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
                ws_add_client(ctx, fd, ip);
            }
        }
        
        /* Handle client data */
        pthread_mutex_lock(&ctx->client_mutex);
        for (int i = 0; i < ctx->client_count; i++) {
            int fd = ctx->clients[i].fd;
            if (!FD_ISSET(fd, &readfds)) continue;
            
            ssize_t nr = recv(fd, buf, sizeof(buf) - 1, 0);
            if (nr <= 0) {
                ws_remove_client_locked(ctx, i);
                i--;
                continue;
            }
            
            if (!ctx->clients[i].handshake_done) {
                buf[nr] = '\0';
                if (ws_handshake(fd, buf) == 0)
                    ctx->clients[i].handshake_done = 1;
                else {
                    ws_remove_client_locked(ctx, i);
                    i--;
                }
            }
        }
        pthread_mutex_unlock(&ctx->client_mutex);
        
        /* Broadcast queued messages */
        char *msg;
        size_t msg_len;
        while (ws_dequeue_message(ctx, &msg, &msg_len)) {
            pthread_mutex_lock(&ctx->client_mutex);
            for (int i = 0; i < ctx->client_count; i++) {
                if (ctx->clients[i].handshake_done) {
                    if (ws_send_frame(ctx->clients[i].fd, WS_OPCODE_TEXT, 
                                     msg, msg_len) == 0)
                        ctx->messages_sent++;
                }
            }
            pthread_mutex_unlock(&ctx->client_mutex);
            free(msg);
        }
    }
    
    return NULL;
}

/* ============================================================================
 * LIFECYCLE
 * ============================================================================ */

ws_context_t *ws_init(const ws_config_t *cfg)
{
    ws_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    
    if (cfg)
        ctx->cfg = *cfg;
    else {
        ws_config_t def = WS_CONFIG_DEFAULT;
        ctx->cfg = def;
    }
    
    pthread_mutex_init(&ctx->client_mutex, NULL);
    pthread_mutex_init(&ctx->msg_mutex, NULL);
    
    /* Create listen socket */
    ctx->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->listen_fd < 0) {
        free(ctx);
        return NULL;
    }
    
    int opt = 1;
    setsockopt(ctx->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(ctx->cfg.port),
        .sin_addr.s_addr = INADDR_ANY
    };
    
    if (bind(ctx->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(ctx->listen_fd, 10) < 0) {
        close(ctx->listen_fd);
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

void ws_destroy(ws_context_t *ctx)
{
    if (!ctx) return;
    
    ws_stop(ctx);
    
    pthread_mutex_lock(&ctx->client_mutex);
    for (int i = 0; i < ctx->client_count; i++)
        close(ctx->clients[i].fd);
    pthread_mutex_unlock(&ctx->client_mutex);
    
    close(ctx->listen_fd);
    
    pthread_mutex_destroy(&ctx->client_mutex);
    pthread_mutex_destroy(&ctx->msg_mutex);
    
    free(ctx);
}

int ws_start(ws_context_t *ctx)
{
    if (!ctx || ctx->running) return -1;
    
    ctx->running = 1;
    if (pthread_create(&ctx->thread, NULL, ws_server_thread, ctx) != 0) {
        ctx->running = 0;
        return -1;
    }
    
    return 0;
}

void ws_stop(ws_context_t *ctx)
{
    if (!ctx || !ctx->running) return;
    
    ctx->running = 0;
    pthread_join(ctx->thread, NULL);
}

/* ============================================================================
 * STREAM UPDATES (JSON formatting + queue)
 * ============================================================================ */

void ws_update_metrics(ws_context_t *ctx, const ws_metrics_t *m)
{
    if (!ctx || !m) return;
    
    char json[2048];
    snprintf(json, sizeof(json),
        "{\"type\":\"metrics\",\"data\":{"
        "\"packets_per_sec\":%lu,"
        "\"bytes_per_sec\":%lu,"
        "\"active_flows\":%u,"
        "\"active_sources\":%u,"
        "\"ml_classifications_per_sec\":%u,"
        "\"cpu_usage_percent\":%.2f,"
        "\"memory_usage_mb\":%.2f,"
        "\"kernel_drops\":%lu,"
        "\"userspace_drops\":%lu"
        "}}",
        (unsigned long)m->packets_per_sec,
        (unsigned long)m->bytes_per_sec,
        m->active_flows, m->active_sources,
        m->ml_classifications_per_sec,
        m->cpu_usage_percent, m->memory_usage_mb,
        (unsigned long)m->kernel_drops,
        (unsigned long)m->userspace_drops);
    
    ws_queue_message(ctx, json);
}

void ws_push_activity(ws_context_t *ctx, const ws_activity_t *a)
{
    if (!ctx || !a) return;
    
    char json[1024];
    char ip[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = a->src_ip };
    inet_ntop(AF_INET, &addr, ip, sizeof(ip));
    
    snprintf(json, sizeof(json),
        "{\"type\":\"activity_logs\",\"data\":{"
        "\"timestamp\":%lu,"
        "\"src_ip\":\"%s\","
        "\"action\":\"%s\","
        "\"attack_type\":\"%s\","
        "\"threat_score\":%.3f,"
        "\"reason\":\"%s\""
        "}}",
        (unsigned long)(a->timestamp_ns / 1000000000ULL),
        ip, a->action, a->attack_type,
        a->threat_score, a->reason);
    
    ws_queue_message(ctx, json);
}

void ws_update_blocked_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count)
{
    if (!ctx) return;
    
    char json[65536];
    int pos = snprintf(json, sizeof(json), "{\"type\":\"blocked_ips\",\"data\":[");
    
    for (uint32_t i = 0; i < count && i < 1000; i++) {
        char ip[INET_ADDRSTRLEN];
        struct in_addr addr = { .s_addr = ips[i].ip };
        inet_ntop(AF_INET, &addr, ip, sizeof(ip));
        
        pos += snprintf(json + pos, sizeof(json) - pos,
            "%s{\"ip\":\"%s\",\"rule_id\":%u,\"timestamp\":%lu}",
            i > 0 ? "," : "", ip, ips[i].rule_id,
            (unsigned long)(ips[i].timestamp_added / 1000000000ULL));
    }
    
    snprintf(json + pos, sizeof(json) - pos, "]}");
    ws_queue_message(ctx, json);
}

void ws_update_rate_limited_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count)
{
    if (!ctx) return;
    
    char json[65536];
    int pos = snprintf(json, sizeof(json), "{\"type\":\"rate_limited_ips\",\"data\":[");
    
    for (uint32_t i = 0; i < count && i < 1000; i++) {
        char ip[INET_ADDRSTRLEN];
        struct in_addr addr = { .s_addr = ips[i].ip };
        inet_ntop(AF_INET, &addr, ip, sizeof(ip));
        
        pos += snprintf(json + pos, sizeof(json) - pos,
            "%s{\"ip\":\"%s\",\"limit_pps\":%u,\"rule_id\":%u}",
            i > 0 ? "," : "", ip, ips[i].rate_limit_pps, ips[i].rule_id);
    }
    
    snprintf(json + pos, sizeof(json) - pos, "]}");
    ws_queue_message(ctx, json);
}

void ws_update_monitored_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count)
{
    if (!ctx) return;
    
    char json[65536];
    int pos = snprintf(json, sizeof(json), "{\"type\":\"monitored_ips\",\"data\":[");
    
    for (uint32_t i = 0; i < count && i < 1000; i++) {
        char ip[INET_ADDRSTRLEN];
        struct in_addr addr = { .s_addr = ips[i].ip };
        inet_ntop(AF_INET, &addr, ip, sizeof(ip));
        
        pos += snprintf(json + pos, sizeof(json) - pos,
            "%s{\"ip\":\"%s\",\"timestamp\":%lu}",
            i > 0 ? "," : "", ip,
            (unsigned long)(ips[i].timestamp_added / 1000000000ULL));
    }
    
    snprintf(json + pos, sizeof(json) - pos, "]}");
    ws_queue_message(ctx, json);
}

void ws_update_whitelisted_ips(ws_context_t *ctx, const ws_ip_entry_t *ips, uint32_t count)
{
    if (!ctx) return;
    
    char json[65536];
    int pos = snprintf(json, sizeof(json), "{\"type\":\"whitelisted_ips\",\"data\":[");
    
    for (uint32_t i = 0; i < count && i < 1000; i++) {
        char ip[INET_ADDRSTRLEN];
        struct in_addr addr = { .s_addr = ips[i].ip };
        inet_ntop(AF_INET, &addr, ip, sizeof(ip));
        
        pos += snprintf(json + pos, sizeof(json) - pos,
            "%s{\"ip\":\"%s\"}",
            i > 0 ? "," : "", ip);
    }
    
    snprintf(json + pos, sizeof(json) - pos, "]}");
    ws_queue_message(ctx, json);
}

void ws_update_traffic_rate(ws_context_t *ctx, const ws_traffic_rate_t *r)
{
    if (!ctx || !r) return;
    
    char json[1024];
    snprintf(json, sizeof(json),
        "{\"type\":\"traffic_rate\",\"data\":{"
        "\"total_pps\":%lu,"
        "\"total_bps\":%lu,"
        "\"tcp_pps\":%lu,"
        "\"udp_pps\":%lu,"
        "\"icmp_pps\":%lu,"
        "\"other_pps\":%lu"
        "}}",
        (unsigned long)r->total_pps,
        (unsigned long)r->total_bps,
        (unsigned long)r->tcp_pps,
        (unsigned long)r->udp_pps,
        (unsigned long)r->icmp_pps,
        (unsigned long)r->other_pps);
    
    ws_queue_message(ctx, json);
}

void ws_update_protocol_dist(ws_context_t *ctx, const ws_protocol_dist_t *d)
{
    if (!ctx || !d) return;
    
    char json[1024];
    snprintf(json, sizeof(json),
        "{\"type\":\"protocol_distribution\",\"data\":{"
        "\"tcp_percent\":%.2f,"
        "\"udp_percent\":%.2f,"
        "\"icmp_percent\":%.2f,"
        "\"other_percent\":%.2f,"
        "\"tcp_bytes\":%lu,"
        "\"udp_bytes\":%lu,"
        "\"icmp_bytes\":%lu,"
        "\"other_bytes\":%lu"
        "}}",
        d->tcp_percent, d->udp_percent,
        d->icmp_percent, d->other_percent,
        (unsigned long)d->tcp_bytes,
        (unsigned long)d->udp_bytes,
        (unsigned long)d->icmp_bytes,
        (unsigned long)d->other_bytes);
    
    ws_queue_message(ctx, json);
}

void ws_update_top_sources(ws_context_t *ctx, const ws_top_source_t *sources, uint32_t count)
{
    if (!ctx) return;
    
    char json[65536];
    int pos = snprintf(json, sizeof(json), "{\"type\":\"top_sources\",\"data\":[");
    
    for (uint32_t i = 0; i < count && i < 100; i++) {
        char ip[INET_ADDRSTRLEN];
        struct in_addr addr = { .s_addr = sources[i].src_ip };
        inet_ntop(AF_INET, &addr, ip, sizeof(ip));
        
        pos += snprintf(json + pos, sizeof(json) - pos,
            "%s{\"ip\":\"%s\",\"packets\":%lu,\"bytes\":%lu,"
            "\"flows\":%u,\"suspicious\":%d,\"threat_score\":%.3f}",
            i > 0 ? "," : "", ip,
            (unsigned long)sources[i].packets,
            (unsigned long)sources[i].bytes,
            sources[i].flow_count,
            sources[i].suspicious,
            sources[i].threat_score);
    }
    
    snprintf(json + pos, sizeof(json) - pos, "]}");
    ws_queue_message(ctx, json);
}

void ws_update_feature_importance(ws_context_t *ctx, const ws_feature_importance_t *f)
{
    if (!ctx || !f) return;
    
    char json[1024];
    snprintf(json, sizeof(json),
        "{\"type\":\"feature_importance\",\"data\":{"
        "\"volume_weight\":%.3f,"
        "\"entropy_weight\":%.3f,"
        "\"protocol_weight\":%.3f,"
        "\"behavioral_weight\":%.3f,"
        "\"avg_threat_score\":%.3f,"
        "\"detections_last_10s\":%u"
        "}}",
        f->volume_weight, f->entropy_weight,
        f->protocol_weight, f->behavioral_weight,
        f->avg_threat_score, f->detections_last_10s);
    
    ws_queue_message(ctx, json);
}

void ws_update_connections(ws_context_t *ctx, const ws_connection_t *conns, uint32_t count)
{
    if (!ctx) return;
    
    char json[65536];
    int pos = snprintf(json, sizeof(json), "{\"type\":\"active_connections\",\"data\":[");
    
    for (uint32_t i = 0; i < count && i < 500; i++) {
        char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
        struct in_addr sa = { .s_addr = conns[i].src_ip };
        struct in_addr da = { .s_addr = conns[i].dst_ip };
        inet_ntop(AF_INET, &sa, sip, sizeof(sip));
        inet_ntop(AF_INET, &da, dip, sizeof(dip));
        
        pos += snprintf(json + pos, sizeof(json) - pos,
            "%s{\"src\":\"%s:%u\",\"dst\":\"%s:%u\","
            "\"proto\":%u,\"packets\":%lu,\"bytes\":%lu}",
            i > 0 ? "," : "", sip, ntohs(conns[i].src_port),
            dip, ntohs(conns[i].dst_port),
            conns[i].protocol,
            (unsigned long)conns[i].packets,
            (unsigned long)conns[i].bytes);
    }
    
    snprintf(json + pos, sizeof(json) - pos, "]}");
    ws_queue_message(ctx, json);
}

void ws_update_mitigation_status(ws_context_t *ctx, const ws_mitigation_status_t *s)
{
    if (!ctx || !s) return;
    
    char json[1024];
    snprintf(json, sizeof(json),
        "{\"type\":\"mitigation_status\",\"data\":{"
        "\"total_blocked\":%u,"
        "\"total_rate_limited\":%u,"
        "\"total_monitored\":%u,"
        "\"total_whitelisted\":%u,"
        "\"kernel_cache_hits\":%lu,"
        "\"kernel_cache_misses\":%lu,"
        "\"active_sdn_rules\":%u"
        "}}",
        s->total_blocked, s->total_rate_limited,
        s->total_monitored, s->total_whitelisted,
        (unsigned long)s->kernel_verdict_cache_hits,
        (unsigned long)s->kernel_verdict_cache_misses,
        s->active_sdn_rules);
    
    ws_queue_message(ctx, json);
}

uint32_t ws_get_client_count(const ws_context_t *ctx)
{
    return ctx ? ctx->client_count : 0;
}

uint64_t ws_get_messages_sent(const ws_context_t *ctx)
{
    return ctx ? ctx->messages_sent : 0;
}
