/*
 * Sentinel DDoS Core - Kernel-Level Network Proxy Module
 * 
 * This module hooks into the kernel's netfilter infrastructure to intercept
 * network traffic and route it to userspace for decision making.
 * 
 * It uses netfilter hooks at the PRE_ROUTING and POST_ROUTING points to
 * capture both inbound and outbound traffic.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/time.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/list.h>
#include <net/net_namespace.h>

#include "kernel_api.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sentinel DDoS Core");
MODULE_DESCRIPTION("Kernel-level network proxy for DDoS mitigation");
MODULE_VERSION("1.0.0");

/* ============================================================================
 * MODULE PARAMETERS
 * ============================================================================ */

static bool enable_filtering = true;
module_param(enable_filtering, bool, 0644);
MODULE_PARM_DESC(enable_filtering, "Enable/disable packet filtering (default: true)");

static int filter_mode = SENTINEL_MODE_DETECT;
module_param(filter_mode, int, 0644);
MODULE_PARM_DESC(filter_mode, "Filtering mode: 0=disabled, 1=learn, 2=detect, 3=protect, 4=quarantine");

static bool enable_ipv6 = true;
module_param(enable_ipv6, bool, 0644);
MODULE_PARM_DESC(enable_ipv6, "Enable IPv6 filtering (default: true)");

static unsigned int decision_timeout_ms = 5000;
module_param(decision_timeout_ms, uint, 0644);
MODULE_PARM_DESC(decision_timeout_ms, "Decision timeout in milliseconds (default: 5000)");

/* ============================================================================
 * MODULE STATE & LOCKING
 * ============================================================================ */

static DEFINE_HASHTABLE(pending_packets, 8); /* Hash table for pending decisions */

static unsigned long module_state = 0;
#define MODULE_STATE_INITIALIZED 0
#define MODULE_STATE_FILTERING 1

/* ============================================================================
 * METADATA DELIVERY QUEUE (kernel -> userspace via /dev/sentinel_proxy)
 * ============================================================================ */

#define METADATA_QUEUE_MAX 4096

struct metadata_queue_entry {
	struct list_head list;
	struct sentinel_packet_metadata meta;
};

static LIST_HEAD(metadata_queue);
static DEFINE_SPINLOCK(metadata_queue_lock);
static int metadata_queue_count = 0;
static DECLARE_WAIT_QUEUE_HEAD(read_waitq);

/* ============================================================================
 * VERDICT CACHE (kernel-level enforcement in PROTECT mode)
 * ============================================================================ */

struct verdict_cache_entry {
	struct hlist_node node;
	__u32 src_ip;
	__u32 verdict;
	__u32 rate_limit_pps;
	unsigned long expires;
	atomic_t pkt_count;
	unsigned long last_reset;
};

static DEFINE_HASHTABLE(verdict_cache, 10); /* 1024 buckets */
static DEFINE_SPINLOCK(verdict_cache_lock);

/* ============================================================================
 * STATISTICS
 * ============================================================================ */

static struct {
	atomic64_t packets_processed;
	atomic64_t packets_allowed;
	atomic64_t packets_dropped;
	atomic64_t packets_redirected;
	atomic64_t packets_rate_limited;
	atomic64_t packets_quarantined;
	atomic64_t errors;
	atomic_t active_flows;
	atomic_t active_rules;
} module_stats = {
	.packets_processed = ATOMIC64_INIT(0),
	.packets_allowed = ATOMIC64_INIT(0),
	.packets_dropped = ATOMIC64_INIT(0),
	.packets_redirected = ATOMIC64_INIT(0),
	.packets_rate_limited = ATOMIC64_INIT(0),
	.packets_quarantined = ATOMIC64_INIT(0),
	.errors = ATOMIC64_INIT(0),
	.active_flows = ATOMIC_INIT(0),
	.active_rules = ATOMIC_INIT(0)
};

/* ============================================================================
 * PENDING PACKET TRACKING
 * ============================================================================ */

struct pending_packet {
	struct hlist_node node;
	__u32 packet_id;
	__u64 timestamp;
	struct sentinel_packet_metadata *metadata;
	unsigned long expires;
};

/* ============================================================================
 * DEVICE FILE INTERFACE
 * ============================================================================ */

static int device_open(struct inode *inode, struct file *file);
static int device_release(struct inode *inode, struct file *file);
static ssize_t device_read(struct file *file, char __user *buf, size_t len, loff_t *offset);
static ssize_t device_write(struct file *file, const char __user *buf, size_t len, loff_t *offset);
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static __poll_t device_poll(struct file *file, struct poll_table_struct *wait);

static const struct file_operations device_fops = {
	.open = device_open,
	.release = device_release,
	.read = device_read,
	.write = device_write,
	.unlocked_ioctl = device_ioctl,
	.compat_ioctl = device_ioctl,
	.poll = device_poll,
};

static struct miscdevice sentinel_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = SENTINEL_DEVICE_NAME,
	.fops = &device_fops,
};

/* ============================================================================
 * NETFILTER HOOK DECLARATIONS
 * ============================================================================ */

static unsigned int hook_ipv4_in(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state);
static unsigned int hook_ipv4_out(void *priv, struct sk_buff *skb,
				   const struct nf_hook_state *state);

#if IS_ENABLED(CONFIG_IPV6)
static unsigned int hook_ipv6_in(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state);
static unsigned int hook_ipv6_out(void *priv, struct sk_buff *skb,
				   const struct nf_hook_state *state);
#endif

/* ============================================================================
 * PACKET PROCESSING FUNCTIONS
 * ============================================================================ */

/*
 * Extract packet metadata from skb
 * Returns NULL on error, pointer to allocated metadata on success
 * Caller must free the returned pointer
 */
static struct sentinel_packet_metadata *
extract_packet_metadata(struct sk_buff *skb, enum sentinel_direction direction)
{
	struct sentinel_packet_metadata *metadata;
	struct iphdr *iph;
	struct ipv6hdr *ipv6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;
	unsigned int payload_len;
	const unsigned char *payload;

	metadata = kzalloc(sizeof(*metadata), GFP_ATOMIC);
	if (!metadata)
		return NULL;

	metadata->direction = direction;
	metadata->timestamp = ktime_get_ns();
	metadata->interface_index = skb->dev ? skb->dev->ifindex : 0;

	/* Extract IP header information */
	iph = ip_hdr(skb);
	if (iph->version == 4) {
		metadata->src_ip = iph->saddr;
		metadata->dst_ip = iph->daddr;
		metadata->protocol = iph->protocol;
		metadata->ttl = iph->ttl;

		/* Extract transport layer information */
		switch (iph->protocol) {
		case IPPROTO_TCP: {
			struct tcphdr _tcph;
			tcph = skb_header_pointer(skb, ip_hdrlen(skb),
						  sizeof(_tcph), &_tcph);
			if (tcph) {
				metadata->src_port = tcph->source;
				metadata->dst_port = tcph->dest;
			}
			break;
		}
		case IPPROTO_UDP: {
			struct udphdr _udph;
			udph = skb_header_pointer(skb, ip_hdrlen(skb),
						  sizeof(_udph), &_udph);
			if (udph) {
				metadata->src_port = udph->source;
				metadata->dst_port = udph->dest;
			}
			break;
		}
		case IPPROTO_ICMP: {
			struct icmphdr _icmph;
			icmph = skb_header_pointer(skb, ip_hdrlen(skb),
						   sizeof(_icmph), &_icmph);
			if (icmph) {
				metadata->src_port = (__u16)((icmph->type << 8) | icmph->code);
				metadata->dst_port = 0;
			}
			break;
		}
		}

		/* Extract payload (transport hdr + data, first N bytes after IP hdr) */
		if (skb->len > ip_hdrlen(skb)) {
			unsigned char _payload_buf[SENTINEL_PACKET_DATA_SIZE];
			payload_len = skb->len - ip_hdrlen(skb);
			if (payload_len > 0) {
				unsigned int copy_len = (payload_len < SENTINEL_PACKET_DATA_SIZE) ?
							 payload_len : SENTINEL_PACKET_DATA_SIZE;
				payload = skb_header_pointer(skb, ip_hdrlen(skb),
							     copy_len, _payload_buf);
				if (payload) {
					memcpy(metadata->payload, payload, copy_len);
					metadata->payload_len = copy_len;
				}
			}
		}

	} else if (iph->version == 6 && enable_ipv6) {
		ipv6h = ipv6_hdr(skb);
		/* IPv6 processing similar to IPv4, omitted for brevity */
		metadata->protocol = ipv6h->nexthdr;
	}

	return metadata;
}

/*
 * Generate a unique packet ID
 */
static atomic_t packet_id_counter = ATOMIC_INIT(0);

static __u32 generate_packet_id(void)
{
	return (__u32)atomic_inc_return(&packet_id_counter);
}

/* queue_packet_for_decision() removed — replaced by enqueue_metadata() */

/* ============================================================================
 * METADATA QUEUE HELPERS
 * ============================================================================ */

static void enqueue_metadata(const struct sentinel_packet_metadata *meta)
{
	struct metadata_queue_entry *entry;

	if (metadata_queue_count >= METADATA_QUEUE_MAX) {
		/* drop oldest to make room */
		struct metadata_queue_entry *oldest;
		spin_lock(&metadata_queue_lock);
		if (!list_empty(&metadata_queue)) {
			oldest = list_first_entry(&metadata_queue,
						  struct metadata_queue_entry, list);
			list_del(&oldest->list);
			metadata_queue_count--;
			kfree(oldest);
		}
		spin_unlock(&metadata_queue_lock);
	}

	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return;

	memcpy(&entry->meta, meta, sizeof(entry->meta));

	spin_lock(&metadata_queue_lock);
	list_add_tail(&entry->list, &metadata_queue);
	metadata_queue_count++;
	spin_unlock(&metadata_queue_lock);

	wake_up_interruptible(&read_waitq);
}

/* ============================================================================
 * VERDICT CACHE HELPERS
 * ============================================================================ */

static struct verdict_cache_entry *verdict_cache_lookup_locked(__u32 src_ip)
{
	struct verdict_cache_entry *vc;

	hash_for_each_possible(verdict_cache, vc, node, src_ip) {
		if (vc->src_ip == src_ip) {
			if (time_after(jiffies, vc->expires)) {
				hash_del(&vc->node);
				kfree(vc);
				return NULL;
			}
			return vc;
		}
	}
	return NULL;
}

static void verdict_cache_update(__u32 src_ip, __u32 verdict,
				 __u32 rate_limit_pps, __u32 duration_sec)
{
	struct verdict_cache_entry *vc;
	unsigned long expiry;

	if (duration_sec == 0)
		duration_sec = 300;
	expiry = jiffies + msecs_to_jiffies(duration_sec * 1000);

	spin_lock(&verdict_cache_lock);

	hash_for_each_possible(verdict_cache, vc, node, src_ip) {
		if (vc->src_ip == src_ip) {
			vc->verdict = verdict;
			vc->rate_limit_pps = rate_limit_pps;
			vc->expires = expiry;
			spin_unlock(&verdict_cache_lock);
			return;
		}
	}

	vc = kmalloc(sizeof(*vc), GFP_ATOMIC);
	if (vc) {
		vc->src_ip = src_ip;
		vc->verdict = verdict;
		vc->rate_limit_pps = rate_limit_pps;
		vc->expires = expiry;
		atomic_set(&vc->pkt_count, 0);
		vc->last_reset = jiffies;
		hash_add(verdict_cache, &vc->node, src_ip);
	}

	spin_unlock(&verdict_cache_lock);
}

static void verdict_cache_flush(void)
{
	struct verdict_cache_entry *vc;
	struct hlist_node *tmp;
	int bkt;

	spin_lock(&verdict_cache_lock);
	hash_for_each_safe(verdict_cache, bkt, tmp, vc, node) {
		hash_del(&vc->node);
		kfree(vc);
	}
	spin_unlock(&verdict_cache_lock);
}

static unsigned int apply_cached_verdict(struct verdict_cache_entry *vc)
{
	switch (vc->verdict) {
	case SENTINEL_VERDICT_DROP:
	case SENTINEL_VERDICT_QUARANTINE:
		atomic64_inc(&module_stats.packets_dropped);
		return NF_DROP;
	case SENTINEL_VERDICT_RATE_LIMIT:
		if (vc->rate_limit_pps > 0) {
			/* simple token bucket: reset count every second */
			if (time_after(jiffies, vc->last_reset + HZ)) {
				atomic_set(&vc->pkt_count, 0);
				vc->last_reset = jiffies;
			}
			if (atomic_inc_return(&vc->pkt_count) >
			    (int)vc->rate_limit_pps) {
				atomic64_inc(&module_stats.packets_rate_limited);
				return NF_DROP;
			}
		}
		return NF_ACCEPT;
	default:
		return NF_ACCEPT;
	}
}

/*
 * Main netfilter hook for IPv4 inbound traffic
 */
static unsigned int
hook_ipv4_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct sentinel_packet_metadata *metadata;
	struct iphdr *iph;
	struct verdict_cache_entry *vc;

	(void)priv; (void)state;

	if (!enable_filtering)
		return NF_ACCEPT;

	if (!skb || !skb->dev)
		return NF_ACCEPT;

	atomic64_inc(&module_stats.packets_processed);

	/* Check verdict cache for kernel-level enforcement (PROTECT mode) */
	iph = ip_hdr(skb);
	if (filter_mode >= SENTINEL_MODE_PROTECT) {
		spin_lock(&verdict_cache_lock);
		vc = verdict_cache_lookup_locked(iph->saddr);
		if (vc) {
			unsigned int result = apply_cached_verdict(vc);
			spin_unlock(&verdict_cache_lock);
			if (result == NF_DROP)
				return NF_DROP;
		} else {
			spin_unlock(&verdict_cache_lock);
		}
	}

	/* Extract metadata and queue for userspace analysis */
	metadata = extract_packet_metadata(skb, SENTINEL_DIRECTION_INBOUND);
	if (!metadata) {
		atomic64_inc(&module_stats.errors);
		atomic64_inc(&module_stats.packets_allowed);
		return NF_ACCEPT;
	}

	metadata->packet_id = generate_packet_id();
	enqueue_metadata(metadata);
	kfree(metadata);

	atomic64_inc(&module_stats.packets_allowed);
	return NF_ACCEPT;
}

/*
 * Main netfilter hook for IPv4 outbound traffic
 */
static unsigned int
hook_ipv4_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct sentinel_packet_metadata *metadata;
	struct iphdr *iph;
	struct verdict_cache_entry *vc;

	(void)priv; (void)state;

	if (!enable_filtering)
		return NF_ACCEPT;

	if (!skb || !skb->dev)
		return NF_ACCEPT;

	atomic64_inc(&module_stats.packets_processed);

	/* Check verdict cache (outbound: check dst IP) */
	iph = ip_hdr(skb);
	if (filter_mode >= SENTINEL_MODE_PROTECT) {
		spin_lock(&verdict_cache_lock);
		vc = verdict_cache_lookup_locked(iph->daddr);
		if (vc) {
			unsigned int result = apply_cached_verdict(vc);
			spin_unlock(&verdict_cache_lock);
			if (result == NF_DROP)
				return NF_DROP;
		} else {
			spin_unlock(&verdict_cache_lock);
		}
	}

	metadata = extract_packet_metadata(skb, SENTINEL_DIRECTION_OUTBOUND);
	if (!metadata) {
		atomic64_inc(&module_stats.errors);
		atomic64_inc(&module_stats.packets_allowed);
		return NF_ACCEPT;
	}

	metadata->packet_id = generate_packet_id();
	enqueue_metadata(metadata);
	kfree(metadata);

	atomic64_inc(&module_stats.packets_allowed);
	return NF_ACCEPT;
}

#if IS_ENABLED(CONFIG_IPV6)
static unsigned int
hook_ipv6_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return NF_ACCEPT; /* Placeholder for IPv6 */
}

static unsigned int
hook_ipv6_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return NF_ACCEPT; /* Placeholder for IPv6 */
}
#endif

/* ============================================================================
 * NETFILTER HOOK REGISTRATION
 * ============================================================================ */

static struct nf_hook_ops sentinel_hooks[] = {
	{
		.hook = hook_ipv4_in,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FILTER,
	},
	{
		.hook = hook_ipv4_out,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_FILTER,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook = hook_ipv6_in,
		.pf = PF_INET6,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP6_PRI_FILTER,
	},
	{
		.hook = hook_ipv6_out,
		.pf = PF_INET6,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP6_PRI_FILTER,
	},
#endif
};

/* ============================================================================
 * DEVICE FILE OPERATIONS
 * ============================================================================ */

static int device_open(struct inode *inode, struct file *file)
{
	pr_info("sentinel_proxy: device opened\n");
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	pr_info("sentinel_proxy: device released\n");
	return 0;
}

static ssize_t device_read(struct file *file, char __user *buf,
			   size_t len, loff_t *offset)
{
	struct metadata_queue_entry *entry;
	ssize_t ret;

	(void)offset;

	if (len < sizeof(struct sentinel_packet_metadata))
		return -EINVAL;

	/* If non-blocking and queue is empty, return EAGAIN */
	if (list_empty(&metadata_queue)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		/* Block until data available or signal */
		ret = wait_event_interruptible(read_waitq,
					       !list_empty(&metadata_queue));
		if (ret)
			return -ERESTARTSYS;
	}

	spin_lock(&metadata_queue_lock);
	if (list_empty(&metadata_queue)) {
		spin_unlock(&metadata_queue_lock);
		return -EAGAIN;
	}
	entry = list_first_entry(&metadata_queue,
				 struct metadata_queue_entry, list);
	list_del(&entry->list);
	metadata_queue_count--;
	spin_unlock(&metadata_queue_lock);

	if (copy_to_user(buf, &entry->meta, sizeof(entry->meta))) {
		kfree(entry);
		return -EFAULT;
	}

	ret = sizeof(entry->meta);
	kfree(entry);
	return ret;
}

static ssize_t device_write(struct file *file, const char __user *buf,
			    size_t len, loff_t *offset)
{
	struct sentinel_packet_decision dec;

	(void)file; (void)offset;

	if (len < sizeof(dec))
		return -EINVAL;

	if (copy_from_user(&dec, buf, sizeof(dec)))
		return -EFAULT;

	/* Update kernel statistics based on the verdict */
	switch (dec.verdict) {
	case SENTINEL_VERDICT_DROP:
		atomic64_inc(&module_stats.packets_dropped);
		break;
	case SENTINEL_VERDICT_RATE_LIMIT:
		atomic64_inc(&module_stats.packets_rate_limited);
		break;
	case SENTINEL_VERDICT_REDIRECT:
		atomic64_inc(&module_stats.packets_redirected);
		break;
	case SENTINEL_VERDICT_QUARANTINE:
		atomic64_inc(&module_stats.packets_quarantined);
		break;
	default:
		break;
	}

	return sizeof(dec);
}

static __poll_t device_poll(struct file *file, struct poll_table_struct *wait)
{
	__poll_t mask = 0;

	(void)file;

	poll_wait(file, &read_waitq, wait);

	spin_lock(&metadata_queue_lock);
	if (!list_empty(&metadata_queue))
		mask |= EPOLLIN | EPOLLRDNORM;
	spin_unlock(&metadata_queue_lock);

	/* Always writable */
	mask |= EPOLLOUT | EPOLLWRNORM;

	return mask;
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int value;
	struct sentinel_module_stats stats;

	switch (cmd) {
	case SENTINEL_IOCTL_ENABLE_FILTERING:
		if (copy_from_user(&value, (int __user *)arg, sizeof(int)))
			return -EFAULT;
		enable_filtering = !!value;
		pr_info("sentinel_proxy: filtering %s\n", 
			enable_filtering ? "enabled" : "disabled");
		return 0;

	case SENTINEL_IOCTL_SET_FILTER_MODE:
		if (copy_from_user(&value, (int __user *)arg, sizeof(int)))
			return -EFAULT;
		if (value >= 0 && value <= 4) {
			filter_mode = value;
			pr_info("sentinel_proxy: filter mode set to %d\n", filter_mode);
			return 0;
		}
		return -EINVAL;

	case SENTINEL_IOCTL_GET_STATS:
		stats.packets_processed = atomic64_read(&module_stats.packets_processed);
		stats.packets_allowed = atomic64_read(&module_stats.packets_allowed);
		stats.packets_dropped = atomic64_read(&module_stats.packets_dropped);
		stats.packets_redirected = atomic64_read(&module_stats.packets_redirected);
		stats.packets_rate_limited = atomic64_read(&module_stats.packets_rate_limited);
		stats.packets_quarantined = atomic64_read(&module_stats.packets_quarantined);
		stats.errors = atomic64_read(&module_stats.errors);
		stats.active_flows = atomic_read(&module_stats.active_flows);
		stats.active_rules = atomic_read(&module_stats.active_rules);
		stats.last_update_timestamp = ktime_get_ns();

		if (copy_to_user((struct sentinel_module_stats __user *)arg, 
				  &stats, sizeof(stats)))
			return -EFAULT;
		return 0;

	case SENTINEL_IOCTL_RESET_STATS:
		atomic64_set(&module_stats.packets_processed, 0);
		atomic64_set(&module_stats.packets_allowed, 0);
		atomic64_set(&module_stats.packets_dropped, 0);
		atomic64_set(&module_stats.packets_redirected, 0);
		atomic64_set(&module_stats.packets_rate_limited, 0);
		atomic64_set(&module_stats.packets_quarantined, 0);
		atomic64_set(&module_stats.errors, 0);
		pr_info("sentinel_proxy: statistics reset\n");
		return 0;

	case SENTINEL_IOCTL_CACHE_VERDICT: {
		struct sentinel_verdict_update vu;
		if (copy_from_user(&vu, (void __user *)arg, sizeof(vu)))
			return -EFAULT;
		verdict_cache_update(vu.src_ip, vu.verdict,
				     vu.rate_limit_pps, vu.duration_sec);
		return 0;
	}

	case SENTINEL_IOCTL_FLUSH_VERDICT_CACHE:
		verdict_cache_flush();
		pr_info("sentinel_proxy: verdict cache flushed\n");
		return 0;

	default:
		return -ENOTTY;
	}
}

/* ============================================================================
 * MODULE INIT & EXIT
 * ============================================================================ */

static int __init sentinel_proxy_init(void)
{
	int ret;

	pr_info("Sentinel DDoS Proxy Module Loading...\n");

	/* Register device file */
	ret = misc_register(&sentinel_device);
	if (ret) {
		pr_err("Failed to register device: %d\n", ret);
		return ret;
	}
	pr_info("Device registered: /dev/%s\n", SENTINEL_DEVICE_NAME);

	/* Register netfilter hooks */
	ret = nf_register_net_hooks(&init_net, sentinel_hooks,
				    ARRAY_SIZE(sentinel_hooks));
	if (ret) {
		pr_err("Failed to register netfilter hooks: %d\n", ret);
		misc_deregister(&sentinel_device);
		return ret;
	}
	pr_info("Netfilter hooks registered (%zu hooks)\n", ARRAY_SIZE(sentinel_hooks));

	/* Initialize hash table for pending packets */
	hash_init(pending_packets);

	/* Initialize state */
	set_bit(MODULE_STATE_INITIALIZED, &module_state);
	if (enable_filtering)
		set_bit(MODULE_STATE_FILTERING, &module_state);

	pr_info("Sentinel DDoS Proxy Module Loaded Successfully!\n");
	pr_info("  Filtering: %s\n", enable_filtering ? "ENABLED" : "DISABLED");
	pr_info("  Mode: %d\n", filter_mode);
	pr_info("  IPv6 Support: %s\n", enable_ipv6 ? "ENABLED" : "DISABLED");

	return 0;
}

static void __exit sentinel_proxy_exit(void)
{
	struct pending_packet *pp;
	struct hlist_node *tmp;
	int i;

	pr_info("Sentinel DDoS Proxy Module Unloading...\n");

	/* Unregister netfilter hooks */
	nf_unregister_net_hooks(&init_net, sentinel_hooks,
				ARRAY_SIZE(sentinel_hooks));
	pr_info("Netfilter hooks unregistered\n");

	/* Clean up pending packets */
	hash_for_each_safe(pending_packets, i, tmp, pp, node) {
		hash_del(&pp->node);
		kfree(pp->metadata);
		kfree(pp);
	}

	/* Clean up metadata queue */
	{
		struct metadata_queue_entry *mq, *mq_tmp;
		list_for_each_entry_safe(mq, mq_tmp, &metadata_queue, list) {
			list_del(&mq->list);
			kfree(mq);
		}
	}

	/* Clean up verdict cache */
	verdict_cache_flush();

	/* Unregister device */
	misc_deregister(&sentinel_device);
	pr_info("Device unregistered\n");

	/* Print final statistics */
	pr_info("Final Statistics:\n");
	pr_info("  Packets Processed: %lld\n", atomic64_read(&module_stats.packets_processed));
	pr_info("  Packets Allowed: %lld\n", atomic64_read(&module_stats.packets_allowed));
	pr_info("  Packets Dropped: %lld\n", atomic64_read(&module_stats.packets_dropped));
	pr_info("  Errors: %lld\n", atomic64_read(&module_stats.errors));

	pr_info("Sentinel DDoS Proxy Module Unloaded\n");
}

module_init(sentinel_proxy_init);
module_exit(sentinel_proxy_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Heath Knowles");
MODULE_DESCRIPTION("Sentinel DDoS Core Proxy Kernel Module");
MODULE_VERSION("1.0");
