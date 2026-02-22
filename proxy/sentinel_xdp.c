/*
 * Sentinel DDoS Core - XDP eBPF Program
 *
 * Intercepts packets at the NIC driver before sk_buff allocation.
 * Whitelist: if source IP is in the whitelist map, XDP_PASS immediately (no userspace).
 * Otherwise redirects to AF_XDP for zero-copy inspection by the pipeline.
 * IPv4 and IPv6 both go to userspace; endian-safe protocol checks.
 */

#include <linux/bpf.h>

/* SEC macro to place elements in specific ELF sections */
#define SEC(NAME) __attribute__((section(NAME), used))

/* Baremetal BPF helpers */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_redirect_map)(void *map, int key, __u64 flags) = (void *) BPF_FUNC_redirect_map;

/* Endian-safe: packet is network byte order; normalize for comparison on any arch. */
#define BPF_NTOHS(x) ((__u16)(((x) >> 8) | ((x) << 8)))
#define ETH_P_IP    0x0800
#define ETH_P_8021Q 0x8100
#define ETH_P_IPV6  0x86DD

/* Minimal Ethernet + IPv4 for bounds-safe parsing */
struct ethhdr {
    __u8  h_dest[6];
    __u8  h_source[6];
    __u16 h_proto;
};
struct vlanhdr {
    __u16 tci;
    __u16 encap_proto;
};
struct iphdr {
    __u8  ihl:4, version:4;
    __u8  tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
};
/* Minimal IPv6 header for redirect (no whitelist for IPv6; userspace can drop). */
struct ip6_hdr {
    __u8  prio_flow[4];
    __u16 payload_len;
    __u8  nexthdr;
    __u8  hop_limit;
    __u8  saddr[16];
    __u8  daddr[16];
};

/*
 * Strict whitelist: IP -> 1. Userspace fills this; if src IP is present, XDP_PASS.
 */
struct {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
} whitelist_map SEC(".maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 4096,
};

/*
 * AF_XDP socket map. Userspace daemon registers UMEM sockets per queue.
 */
struct {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
} xsks_map SEC(".maps") = {
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 64,
};

#define MAX_VLAN_TAGS 4

/*
 * Main XDP hook: endian-safe protocol; IPv4 whitelist; IPv6 and IPv4 redirect to AF_XDP.
 */
SEC("xdp")
int sentinel_xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;
    struct ethhdr *eth = data;
    void *next = (void *)(eth + 1);
    __u16 proto_raw = eth->h_proto;
    __u16 proto = BPF_NTOHS(proto_raw);

    for (int vlan_depth = 0; vlan_depth < MAX_VLAN_TAGS && proto == ETH_P_8021Q; vlan_depth++) {
        if (next + sizeof(struct vlanhdr) + sizeof(struct iphdr) > data_end)
            return XDP_PASS;
        struct vlanhdr *vlan = (struct vlanhdr *)next;
        next = (void *)(vlan + 1);
        proto_raw = vlan->encap_proto;
        proto = BPF_NTOHS(proto_raw);
    }

    /* IPv4: whitelist then redirect; IPv6: redirect to userspace (no kernel bypass). */
    if (proto == ETH_P_IP) {
        if (next + sizeof(struct iphdr) > data_end)
            return XDP_DROP;
        struct iphdr *ip = (struct iphdr *)next;
        __u32 src_ip = ip->saddr;
        if (bpf_map_lookup_elem(&whitelist_map, &src_ip))
            return XDP_PASS;
    } else if (proto == ETH_P_IPV6) {
        if (next + sizeof(struct ip6_hdr) > data_end)
            return XDP_PASS;
        /* No whitelist for IPv6; send to userspace for mitigation/drop. */
    } else {
        return XDP_PASS;
    }

    int index = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
