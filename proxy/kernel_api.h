/*
 * Sentinel DDoS Core - Kernel-Level Network Proxy API
 * Defines the communication protocol between kernel module and userspace
 * 
 * This header is shared between kernel module and userspace programs
 */

#ifndef SENTINEL_KERNEL_API_H
#define SENTINEL_KERNEL_API_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* ============================================================================
 * PACKET METADATA & DECISIONS
 * ============================================================================ */

/* Maximum payload size for packet metadata */
#define SENTINEL_PACKET_DATA_SIZE 256

/* Packet decision verdict from decision engine */
enum sentinel_verdict {
	SENTINEL_VERDICT_ALLOW = 0,      /* Allow packet to pass */
	SENTINEL_VERDICT_DROP = 1,       /* Drop packet */
	SENTINEL_VERDICT_REDIRECT = 2,   /* Redirect to proxy */
	SENTINEL_VERDICT_RATE_LIMIT = 3, /* Apply rate limiting */
	SENTINEL_VERDICT_QUARANTINE = 4  /* Isolate source */
};

/* Packet direction */
enum sentinel_direction {
	SENTINEL_DIRECTION_INBOUND = 0,
	SENTINEL_DIRECTION_OUTBOUND = 1
};

/* Transport protocol */
enum sentinel_protocol {
	SENTINEL_PROTO_TCP = 6,
	SENTINEL_PROTO_UDP = 17,
	SENTINEL_PROTO_ICMP = 1
};

/*
 * Packet metadata sent from kernel to userspace
 * Contains essential information for decision making
 */
struct sentinel_packet_metadata {
	__u32 packet_id;           /* Unique packet identifier */
	__u32 src_ip;              /* Source IP (network byte order) */
	__u32 dst_ip;              /* Destination IP (network byte order) */
	__u16 src_port;            /* Source port (network byte order) */
	__u16 dst_port;            /* Destination port (network byte order) */
	__u8 protocol;             /* Protocol (TCP/UDP/ICMP) */
	__u8 direction;            /* Inbound or outbound */
	__u16 payload_len;         /* Payload length */
	__u64 timestamp;           /* Kernel timestamp (ns) */
	__u32 interface_index;     /* Network interface index */
	__u32 uid;                 /* User ID (for local packets) */
	__u32 gid;                 /* Group ID (for local packets) */
	__u8 ttl;                  /* Time to live */
	__u8 _reserved[3];         /* Reserved for future use */
	__u8 payload[SENTINEL_PACKET_DATA_SIZE]; /* Packet payload (first N bytes) */
} __attribute__((packed));

/*
 * Decision sent from userspace to kernel
 * Tells kernel what to do with a packet
 */
struct sentinel_packet_decision {
	__u32 packet_id;           /* Packet ID to make decision for */
	__u32 verdict;             /* Decision (allow/drop/redirect/etc) */
	__u32 redirect_interface;  /* Interface to redirect to (if redirect verdict) */
	__u16 redirect_port;       /* Port to redirect to (network byte order) */
	__u32 redirect_ip;         /* IP to redirect to (network byte order) */
	__u32 rate_limit_pps;      /* Packets per second (if rate limit) */
	__u32 quarantine_duration; /* Duration in seconds (if quarantine) */
	__u16 action_flags;        /* Additional action flags */
	__u16 _reserved;           /* Reserved for future use */
} __attribute__((packed));

/* ============================================================================
 * IOCTL COMMANDS
 * ============================================================================ */

#define SENTINEL_IOCTL_MAGIC 'S'

/*
 * IOCTL to enable/disable packet filtering
 * arg: pointer to int (1 = enable, 0 = disable)
 */
#define SENTINEL_IOCTL_ENABLE_FILTERING \
	_IOW(SENTINEL_IOCTL_MAGIC, 1, int)

/*
 * IOCTL to configure filtering rules
 * arg: pointer to sentinel_filter_rule
 */
#define SENTINEL_IOCTL_ADD_FILTER_RULE \
	_IOW(SENTINEL_IOCTL_MAGIC, 2, struct sentinel_filter_rule)

/*
 * IOCTL to remove filtering rules
 * arg: pointer to sentinel_filter_rule
 */
#define SENTINEL_IOCTL_REMOVE_FILTER_RULE \
	_IOW(SENTINEL_IOCTL_MAGIC, 3, struct sentinel_filter_rule)

/*
 * IOCTL to set filtering mode
 * arg: pointer to int (filtering mode)
 */
#define SENTINEL_IOCTL_SET_FILTER_MODE \
	_IOW(SENTINEL_IOCTL_MAGIC, 4, int)

/*
 * IOCTL to get module statistics
 * arg: pointer to sentinel_module_stats
 */
#define SENTINEL_IOCTL_GET_STATS \
	_IOR(SENTINEL_IOCTL_MAGIC, 5, struct sentinel_module_stats)

/*
 * IOCTL to reset statistics
 * arg: NULL
 */
#define SENTINEL_IOCTL_RESET_STATS \
	_IO(SENTINEL_IOCTL_MAGIC, 6)

/*
 * IOCTL to cache a verdict for a source IP (kernel-level enforcement)
 * arg: pointer to sentinel_verdict_update
 */
#define SENTINEL_IOCTL_CACHE_VERDICT \
	_IOW(SENTINEL_IOCTL_MAGIC, 7, struct sentinel_verdict_update)

/*
 * IOCTL to flush the entire verdict cache
 * arg: NULL
 */
#define SENTINEL_IOCTL_FLUSH_VERDICT_CACHE \
	_IO(SENTINEL_IOCTL_MAGIC, 8)

/* ============================================================================
 * VERDICT CACHE UPDATE (sent from userspace to kernel)
 * ============================================================================ */

struct sentinel_verdict_update {
	__u32 src_ip;              /* Source IP to cache verdict for (NBO) */
	__u32 verdict;             /* sentinel_verdict value */
	__u32 rate_limit_pps;      /* PPS limit (for RATE_LIMIT verdict) */
	__u32 duration_sec;        /* How long to cache (seconds, 0=default 300) */
} __attribute__((packed));

/* ============================================================================
 * FILTER RULES
 * ============================================================================ */

#define SENTINEL_FILTER_RULE_SIZE 128

struct sentinel_filter_rule {
	__u32 rule_id;
	__u32 src_ip_mask;         /* 0 = any */
	__u32 dst_ip_mask;         /* 0 = any */
	__u16 src_port_min;        /* 0 = any */
	__u16 src_port_max;        /* 0 = any */
	__u16 dst_port_min;        /* 0 = any */
	__u16 dst_port_max;        /* 0 = any */
	__u8 protocol;             /* 0 = any */
	__u8 direction;            /* 0 = both */
	__u16 priority;            /* Lower = higher priority */
	__u32 action;              /* Verdict for matching packets */
	__u32 _reserved;
} __attribute__((packed));

/* ============================================================================
 * MODULE STATISTICS
 * ============================================================================ */

struct sentinel_module_stats {
	__u64 packets_processed;
	__u64 packets_allowed;
	__u64 packets_dropped;
	__u64 packets_redirected;
	__u64 packets_rate_limited;
	__u64 packets_quarantined;
	__u64 errors;
	__u32 active_flows;
	__u32 active_rules;
	__u64 last_update_timestamp;
} __attribute__((packed));

/* ============================================================================
 * NETLINK PROTOCOL
 * ============================================================================ */

/* Netlink message types */
enum sentinel_netlink_msg_type {
	SENTINEL_NL_PACKET_REPORT = 1,  /* Kernel reports packet for decision */
	SENTINEL_NL_DECISION = 2,       /* Userspace sends decision */
	SENTINEL_NL_CONFIG_REQUEST = 3, /* Userspace requests configuration */
	SENTINEL_NL_CONFIG_RESPONSE = 4 /* Kernel sends configuration */
};

/*
 * Netlink message header
 * Prepended to every message type
 */
struct sentinel_nl_msg_header {
	__u32 message_type;
	__u32 message_len;
	__u64 timestamp;
	__u32 sequence_num;
	__u32 _reserved;
} __attribute__((packed));

/* ============================================================================
 * FILTERING MODES
 * ============================================================================ */

enum sentinel_filter_mode {
	SENTINEL_MODE_DISABLED = 0,    /* No filtering */
	SENTINEL_MODE_LEARN = 1,       /* Learn mode - allow but report */
	SENTINEL_MODE_DETECT = 2,      /* Detect and report anomalies */
	SENTINEL_MODE_PROTECT = 3,     /* Actively filter threats */
	SENTINEL_MODE_QUARANTINE = 4   /* Strict mode - quarantine suspicious */
};

/* ============================================================================
 * DEVICE FILE INTERFACE
 * ============================================================================ */

#define SENTINEL_DEVICE_NAME "sentinel_proxy"
#define SENTINEL_DEVICE_PATH "/dev/sentinel_proxy"

/* Character device major/minor numbers */
#define SENTINEL_DEVICE_CLASS "sentinel"

/* ============================================================================
 * HELPER MACROS FOR USERSPACE
 * ============================================================================ */

#ifdef __KERNEL__
/* Kernel-only definitions */
#define SENTINEL_NETLINK_PROTOCOL 28 /* Custom netlink family */
#else
/* Userspace helper macros (only define if not already provided by system) */
#ifndef htons
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) __builtin_bswap16(x)
#else
#define htons(x) (x)
#endif
#endif
#ifndef htonl
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htonl(x) __builtin_bswap32(x)
#else
#define htonl(x) (x)
#endif
#endif
#ifndef ntohs
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ntohs(x) __builtin_bswap16(x)
#else
#define ntohs(x) (x)
#endif
#endif
#ifndef ntohl
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ntohl(x) __builtin_bswap32(x)
#else
#define ntohl(x) (x)
#endif
#endif
#endif

#endif /* SENTINEL_KERNEL_API_H */
