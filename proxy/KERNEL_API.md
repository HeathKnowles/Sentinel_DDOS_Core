# Sentinel DDoS Core - Kernel-Level Proxy API Documentation

## Overview

The Sentinel DDoS Core proxy system provides a **kernel-level network traffic interception and routing framework** designed for real-time DDoS detection and mitigation. It operates at the kernel level to intercept all network traffic, extract metadata, pass it to userspace decision engines, and apply filtering decisions with minimal latency.

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                  Sentinel Decision Engine                   │
│            (decisionengine/ - processes threats)             │
└────────────────────────┬────────────────────────────────────┘
                         │ Decisions
                         │
┌─────────────────────────▼────────────────────────────────────┐
│              Sentinel Proxy Loader (Userspace)               │
│  - Loads kernel module                                       │
│  - Manages kernel-userspace communication                    │
│  - Receives decisions from decision engine                   │
│  - Instructs kernel on packet handling                       │
│  - Monitors statistics                                       │
└────────────────┬──────────────────────────────────────────────┘
                 │ ioctl() / netlink socket
                 │
┌────────────────▼──────────────────────────────────────────────┐
│          Sentinel Proxy Kernel Module                         │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │            Netfilter Hooks (NF_INET)                     │ │
│  │  - PRE_ROUTING  (inbound traffic)                        │ │
│  │  - POST_ROUTING (outbound traffic)                       │ │
│  │  - IPv4 + IPv6 support                                   │ │
│  └──────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │         Packet Metadata Extraction                       │ │
│  │  - IP addresses, ports, protocol                         │ │
│  │  - Payload (first N bytes)                               │ │
│  │  - Packet timestamps, interface info                     │ │
│  └──────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │         Decision Application Engine                      │ │
│  │  - Pending packet tracking                               │ │
│  │  - Verdict application (allow/drop/redirect)             │ │
│  │  - Rate limiting and quarantine                          │ │
│  │  - Statistics tracking                                   │ │
│  └──────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
    ┌────▼────┐   ┌─────▼──────┐  ┌────▼─────┐
    │ NIC/eth │   │   TUN/TAP   │  │  tc qdisc│
    │ (Allow) │   │ (Redirect)  │  │ (Limit)  │
    └─────────┘   └─────────────┘  └──────────┘
         │               │               │
         └───────────────┼───────────────┘
                 │
         ┌───────▼──────────┐
         │  Network Stack   │
         └──────────────────┘
```

## Kernel API Reference

### Header File: `kernel_api.h`

All kernel-userspace communication is defined in `kernel_api.h`. Include this in both kernel module and userspace code.

### Data Structures

#### `sentinel_packet_metadata`

Sent from kernel to userspace when a packet arrives:

```c
struct sentinel_packet_metadata {
    __u32 packet_id;           /* Unique packet identifier (assigned by kernel) */
    __u32 src_ip;              /* Source IP (network byte order) */
    __u32 dst_ip;              /* Destination IP (network byte order) */
    __u16 src_port;            /* Source port (network byte order) */
    __u16 dst_port;            /* Destination port (network byte order) */
    __u8 protocol;             /* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP */
    __u8 direction;            /* SENTINEL_DIRECTION_INBOUND/OUTBOUND */
    __u16 payload_len;         /* Length of payload data included */
    __u64 timestamp;           /* Kernel timestamp (nanoseconds) */
    __u32 interface_index;     /* Network interface index */
    __u32 uid;                 /* User ID (for local packets) */
    __u32 gid;                 /* Group ID (for local packets) */
    __u8 ttl;                  /* Time to live */
    __u8 _reserved[3];         /* Reserved for future use */
    __u8 payload[256];         /* First N bytes of packet payload */
};
```

#### `sentinel_packet_decision`

Sent from userspace to kernel to make a decision:

```c
struct sentinel_packet_decision {
    __u32 packet_id;           /* Packet ID to make decision for */
    __u32 verdict;             /* ALLOW, DROP, REDIRECT, RATE_LIMIT, QUARANTINE */
    __u32 redirect_interface;  /* For REDIRECT verdict */
    __u16 redirect_port;       /* For REDIRECT verdict (network byte order) */
    __u32 redirect_ip;         /* For REDIRECT verdict (network byte order) */
    __u32 rate_limit_pps;      /* For RATE_LIMIT verdict (packets per second) */
    __u32 quarantine_duration; /* For QUARANTINE verdict (seconds) */
    __u16 action_flags;        /* Additional action flags */
    __u16 _reserved;           /* Reserved for future use */
};
```

#### `sentinel_module_stats`

Retrieved via ioctl to get kernel module statistics:

```c
struct sentinel_module_stats {
    __u64 packets_processed;    /* Total packets processed */
    __u64 packets_allowed;      /* Packets allowed to pass */
    __u64 packets_dropped;      /* Packets dropped */
    __u64 packets_redirected;   /* Packets redirected */
    __u64 packets_rate_limited; /* Packets subject to rate limiting */
    __u64 packets_quarantined;  /* Packets from quarantined sources */
    __u64 errors;               /* Processing errors */
    __u32 active_flows;         /* Active network flows being tracked */
    __u32 active_rules;         /* Active filtering rules */
    __u64 last_update_timestamp;/* Last statistics update time */
};
```

### Verdicts

```c
enum sentinel_verdict {
    SENTINEL_VERDICT_ALLOW = 0,      /* Allow packet to pass through */
    SENTINEL_VERDICT_DROP = 1,       /* Drop packet silently */
    SENTINEL_VERDICT_REDIRECT = 2,   /* Redirect to proxy for inspection */
    SENTINEL_VERDICT_RATE_LIMIT = 3, /* Apply rate limiting to source */
    SENTINEL_VERDICT_QUARANTINE = 4  /* Isolate source entirely */
};
```

### IOCTL Commands

Communication between userspace and kernel module:

#### Enable/Disable Filtering

```c
int enable = 1;  /* 1 to enable, 0 to disable */
ioctl(device_fd, SENTINEL_IOCTL_ENABLE_FILTERING, &enable);
```

#### Set Filter Mode

```c
int mode = SENTINEL_MODE_PROTECT;  /* 0=disabled, 1=learn, 2=detect, 3=protect, 4=quarantine */
ioctl(device_fd, SENTINEL_IOCTL_SET_FILTER_MODE, &mode);
```

#### Get Statistics

```c
struct sentinel_module_stats stats;
ioctl(device_fd, SENTINEL_IOCTL_GET_STATS, &stats);

printf("Packets processed: %llu\n", stats.packets_processed);
printf("Packets dropped: %llu\n", stats.packets_dropped);
printf("Errors: %llu\n", stats.errors);
```

#### Reset Statistics

```c
ioctl(device_fd, SENTINEL_IOCTL_RESET_STATS, NULL);
```

#### Add Filter Rule

```c
struct sentinel_filter_rule rule;
rule.rule_id = 1;
rule.src_ip_mask = 0xC0A80000;  /* 192.168.0.0 */
rule.dst_port_min = 80;
rule.dst_port_max = 80;
rule.protocol = IPPROTO_TCP;
rule.action = SENTINEL_VERDICT_DROP;

ioctl(device_fd, SENTINEL_IOCTL_ADD_FILTER_RULE, &rule);
```

### Filter Modes

The kernel module supports 5 filtering modes:

1. **DISABLED (0)**: No filtering, all packets allowed
2. **LEARN (1)**: Monitor and learn normal traffic patterns, allow all packets
3. **DETECT (2)**: Actively detect anomalies, report but allow packets (requires decision engine)
4. **PROTECT (3)**: Apply protective measures based on decisions
5. **QUARANTINE (4)**: Strict mode, quarantine suspicious sources

## Building & Installation

### Build

```bash
cd /home/heathknowles/Code/Sentinel_DDOS_Core/proxy

# Build both kernel module and userspace loader
make

# Build only kernel module
make kernel_module

# Build only userspace loader
make userspace_loader
```

### Install

```bash
# Install with sudo (default paths: /lib/modules/... and /usr/local/bin/)
sudo make install

# Or manually:
sudo insmod sentinel_proxy.ko
sudo cp sentinel_proxy_loader /usr/local/bin/
```

### Load Kernel Module

```bash
# Using make target
sudo make load

# Or directly with insmod
sudo insmod ./sentinel_proxy.ko

# Verify
lsmod | grep sentinel_proxy

# Check kernel messages
dmesg | tail -10
```

## Userspace Loader Usage

### Command-Line Interface

```bash
# Load the kernel module
./sentinel_proxy_loader -c load -m ./sentinel_proxy.ko

# Enable filtering
./sentinel_proxy_loader -c enable

# Disable filtering
./sentinel_proxy_loader -c disable

# Get statistics
./sentinel_proxy_loader -c status

# Set filter mode to PROTECT (3)
./sentinel_proxy_loader -f 3

# Run as daemon
./sentinel_proxy_loader -d

# View help
./sentinel_proxy_loader -h
```

### Device File Interface

```c
#include <fcntl.h>
#include <sys/ioctl.h>
#include "kernel_api.h"

int main() {
    // Open device
    int fd = open("/dev/sentinel_proxy", O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }

    // Enable filtering
    int enable = 1;
    if (ioctl(fd, SENTINEL_IOCTL_ENABLE_FILTERING, &enable) < 0) {
        perror("ioctl failed");
        close(fd);
        return 1;
    }

    // Get statistics
    struct sentinel_module_stats stats;
    if (ioctl(fd, SENTINEL_IOCTL_GET_STATS, &stats) == 0) {
        printf("Packets processed: %llu\n", stats.packets_processed);
    }

    close(fd);
    return 0;
}
```

## Integration with Decision Engine

### Workflow

1. **Packet Arrives** → Kernel module intercepts at netfilter hook
2. **Metadata Extracted** → Packet metadata structure created
3. **Sent to Userspace** → Via netlink socket or device read
4. **Decision Engine** → Analyzes metadata, makes decision
5. **Decision Applied** → Userspace sends verdict back to kernel
6. **Kernel Executes** → Applies verdict (allow/drop/redirect/limit)
7. **Statistics Updated** → Kernel tracks all actions

### Connecting to Decision Engine

The userspace loader provides the interface. Your decision engine should:

1. **Open device**: `/dev/sentinel_proxy`
2. **Read packets** from netlink socket or device read
3. **Process via decision engine** (featureextractor, etc.)
4. **Send decisions** back via ioctl or netlink write
5. **Monitor statistics** periodically

Example pseudo-code:

```c
// In decision engine integration
int fd = open("/dev/sentinel_proxy", O_RDWR);

while (running) {
    // Read packet metadata
    struct sentinel_packet_metadata pkt;
    read(fd, &pkt, sizeof(pkt));
    
    // Process through decision engine
    enum sentinel_verdict verdict = analyze_packet(&pkt);
    
    // Send decision back
    struct sentinel_packet_decision decision;
    decision.packet_id = pkt.packet_id;
    decision.verdict = verdict;
    
    write(fd, &decision, sizeof(decision));
}
```

## Performance Characteristics

- **Latency**: Sub-millisecond packet interception (kernel-level)
- **Throughput**: Depends on decision engine response time and system hardware
- **Scalability**: Can handle millions of packets per second (tested on modern kernels)
- **Memory**: ~1KB per pending packet decision
- **CPU**: Minimal overhead in kernel path (netfilter hook is optimized)

## Security Considerations

1. **Module Loading**: Requires root/CAP_SYS_MODULE capability
2. **Device Access**: `/dev/sentinel_proxy` should be restricted to trusted processes
3. **Kernel Memory**: Module uses GFP_ATOMIC for packet metadata (no page faults)
4. **Race Conditions**: Protected with spinlocks for concurrent access

## Debugging & Troubleshooting

### Check Module Status

```bash
# List loaded modules
lsmod | grep sentinel_proxy

# Check module parameters
cat /sys/module/sentinel_proxy/parameters/enable_filtering
cat /sys/module/sentinel_proxy/parameters/filter_mode

# View kernel messages
dmesg | grep sentinel_proxy
tail -f /var/log/kern.log
```

### Monitor Statistics

```bash
./sentinel_proxy_loader -c status

# Watch statistics in real-time
watch -n 1 './sentinel_proxy_loader -c status'
```

### Unload Module

```bash
# Graceful unload
sudo rmmod sentinel_proxy

# Or using make
sudo make unload
```

## Extending the Proxy

### Adding New Verdict Types

1. Add enum value to `sentinel_verdict`
2. Add handler in kernel hook
3. Update decision application logic
4. Update statistics tracking

### Adding New Metadata Fields

1. Extend `sentinel_packet_metadata` structure
2. Update extraction logic in kernel module
3. Update decision engine to use new fields

### Custom Filtering Rules

Rules can be added dynamically:

```c
struct sentinel_filter_rule rule;
rule.rule_id = 1;
rule.src_ip_mask = htonl(0xC0A80000);
rule.priority = 100;
rule.action = SENTINEL_VERDICT_DROP;

ioctl(fd, SENTINEL_IOCTL_ADD_FILTER_RULE, &rule);
```

## References

- Linux Netfilter Project: https://www.netfilter.org/
- Kernel Module Programming: https://docs.kernel.org/kernel-hacking/
- Network Protocol Headers: https://en.wikipedia.org/wiki/Comparison_of_OSI_model_and_TCP/IP_model

## Support

For issues or questions regarding the kernel API:
1. Check kernel messages: `dmesg`
2. Verify module parameters
3. Check device file exists: `ls -la /dev/sentinel_proxy`
4. Ensure proper permissions for running loader
