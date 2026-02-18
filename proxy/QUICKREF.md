# Sentinel Kernel Proxy - Quick Reference

## Build & Load

```bash
# Build
cd /home/heathknowles/Code/Sentinel_DDOS_Core/proxy
make

# Load module
sudo make load

# Enable filtering
./sentinel_proxy_loader -c enable

# View statistics
./sentinel_proxy_loader -c status
```

## Core Structs (from kernel_api.h)

### Packet from Kernel to Userspace
```c
struct sentinel_packet_metadata {
    __u32 packet_id;        // Unique ID
    __u32 src_ip, dst_ip;   // IPs
    __u16 src_port, dst_port; // Ports
    __u8 protocol;          // TCP/UDP/ICMP
    __u8 direction;         // IN/OUT
    __u8 payload[256];      // First N bytes
    // ... more fields ...
};
```

### Decision from Userspace to Kernel
```c
struct sentinel_packet_decision {
    __u32 packet_id;        // Which packet
    __u32 verdict;          // ALLOW/DROP/REDIRECT/RATE_LIMIT/QUARANTINE
    __u32 rate_limit_pps;   // For RATE_LIMIT verdict
    // ... more fields ...
};
```

## Integration Loop

```c
#include "kernel_api.h"

int fd = open("/dev/sentinel_proxy", O_RDWR);

while (running) {
    // Read packet metadata from kernel
    struct sentinel_packet_metadata pkt;
    read(fd, &pkt, sizeof(pkt));
    
    // Make decision
    int verdict = analyze_with_your_engine(&pkt);
    
    // Send decision back
    struct sentinel_packet_decision decision;
    decision.packet_id = pkt.packet_id;
    decision.verdict = verdict;
    write(fd, &decision, sizeof(decision));
}

close(fd);
```

## IOCTL Commands

```c
int fd = open("/dev/sentinel_proxy", O_RDWR);

// Enable/disable filtering
int enable = 1;
ioctl(fd, SENTINEL_IOCTL_ENABLE_FILTERING, &enable);

// Set filter mode (0-4: disabled, learn, detect, protect, quarantine)
int mode = 3;  // PROTECT
ioctl(fd, SENTINEL_IOCTL_SET_FILTER_MODE, &mode);

// Get statistics
struct sentinel_module_stats stats;
ioctl(fd, SENTINEL_IOCTL_GET_STATS, &stats);
printf("Packets: %llu, Dropped: %llu\n", 
       stats.packets_processed, stats.packets_dropped);

// Reset statistics
ioctl(fd, SENTINEL_IOCTL_RESET_STATS, NULL);

close(fd);
```

## Command-Line Usage

```bash
# Load module
./sentinel_proxy_loader -c load -m ./sentinel_proxy.ko

# Enable filtering
./sentinel_proxy_loader -c enable

# Disable filtering
./sentinel_proxy_loader -c disable

# Get status
./sentinel_proxy_loader -c status

# Set filter mode (0=disabled, 1=learn, 2=detect, 3=protect, 4=quarantine)
./sentinel_proxy_loader -f 3

# Reset statistics
./sentinel_proxy_loader -c reset-stats

# Run as daemon
./sentinel_proxy_loader -d -f 3

# Unload module
./sentinel_proxy_loader -c unload

# Help
./sentinel_proxy_loader -h
```

## Verdict Types

```c
SENTINEL_VERDICT_ALLOW = 0;        // Let packet pass
SENTINEL_VERDICT_DROP = 1;         // Discard packet
SENTINEL_VERDICT_REDIRECT = 2;     // Route to proxy
SENTINEL_VERDICT_RATE_LIMIT = 3;   // Traffic shaping
SENTINEL_VERDICT_QUARANTINE = 4;   // Block source IP
```

## Filter Modes

| Mode | Value | Behavior |
|------|-------|----------|
| DISABLED | 0 | No filtering |
| LEARN | 1 | Monitor, allow all |
| DETECT | 2 | Report anomalies, allow |
| PROTECT | 3 | Active filtering (recommended) |
| QUARANTINE | 4 | Strict mode, block suspicious |

## Debugging

```bash
# View kernel messages
dmesg | tail -20

# Follow kernel messages live
dmesg -w | grep sentinel

# Check module is loaded
lsmod | grep sentinel_proxy

# Check device exists
ls -la /dev/sentinel_proxy

# Monitor statistics
watch -n 1 './sentinel_proxy_loader -c status'

# View module parameters
cat /sys/module/sentinel_proxy/parameters/enable_filtering
cat /sys/module/sentinel_proxy/parameters/filter_mode

# Monitor with tcpdump
sudo tcpdump -i any -n | head -20
```

## Unload

```bash
# Using make
sudo make unload

# Using loader
./sentinel_proxy_loader -c unload

# Direct
sudo rmmod sentinel_proxy
```

## Decision Engine Example

```c
#include "kernel_api.h"

enum sentinel_verdict analyze_packet(
    const struct sentinel_packet_metadata *pkt)
{
    // Example 1: Block SSH brute force
    if (pkt->dst_port == htons(22) && 
        pkt->protocol == IPPROTO_TCP) {
        // Check frequency, return DROP if high
    }
    
    // Example 2: Block large ICMP (ping of death)
    if (pkt->protocol == IPPROTO_ICMP && 
        pkt->payload_len > 512) {
        return SENTINEL_VERDICT_DROP;
    }
    
    // Example 3: Rate limit UDP (DNS amplification)
    if (pkt->protocol == IPPROTO_UDP && 
        pkt->dst_port == htons(53)) {
        return SENTINEL_VERDICT_RATE_LIMIT;
    }
    
    // Default: allow
    return SENTINEL_VERDICT_ALLOW;
}
```

## File Locations

| Component | Path |
|-----------|------|
| Header (API) | `/proxy/kernel_api.h` |
| Kernel Module | `/proxy/sentinel_proxy.c` |
| Userspace Loader | `/proxy/sentinel_loader.c` |
| Example Engine | `/proxy/sentinel_decision_engine_example.c` |
| Build System | `/proxy/Makefile` |
| Compiled .ko | `/proxy/sentinel_proxy.ko` |
| Compiled Binary | `/proxy/sentinel_proxy_loader` |
| Device File | `/dev/sentinel_proxy` |

## Compile & Run Example

```bash
# Build all
make

# Load kernel module
sudo make load

# Build example decision engine
gcc -o sentinel_decision_engine_example \
    sentinel_decision_engine_example.c

# Run example (will read/write packets)
sudo ./sentinel_decision_engine_example

# In another terminal, check stats
./sentinel_proxy_loader -c status
```

## Packet Flow

```
Network Interface
    ↓
Netfilter Hook (PRE_ROUTING)
    ↓
sentinel_proxy kernel module
    ↓
Extract metadata → Assign packet_id
    ↓
Write to /dev/sentinel_proxy queue
    ↓
Decision engine reads packet_id + metadata
    ↓
Makes decision (ALLOW/DROP/etc)
    ↓
Writes decision back with packet_id
    ↓
Kernel module applies verdict
    ↓
Update statistics
    ↓
Continue to next layer in network stack
```

## Performance Tuning

```bash
# Reduce decision timeout (faster but less analysis time)
insmod ./sentinel_proxy.ko decision_timeout_ms=1000

# Disable IPv6 for speed
insmod ./sentinel_proxy.ko enable_ipv6=0

# Pin loader to CPU core 0
taskset -p 0x1 $(pgrep sentinel_proxy_loader)

# Check active statistics
./sentinel_proxy_loader -c status
```

## Common Issues

| Issue | Solution |
|-------|----------|
| Module won't load | Check kernel headers: `ls /lib/modules/$(uname -r)/build/` |
| Device not found | Make sure module loaded: `lsmod \| grep sentinel_proxy` |
| No packets processed | Enable filtering: `./sentinel_proxy_loader -c enable` |
| High CPU usage | Check decision engine speed, reduce timeout |
| Permission denied | Run loader as root: `sudo ./sentinel_proxy_loader` |

## Environment Setup

```bash
# Install build tools (Ubuntu/Debian)
sudo apt-get install build-essential linux-headers-$(uname -r)

# Check kernel version
uname -r

# Check kernel config
cat /proc/config.gz | gunzip | grep NETFILTER

# Verify netfilter support
grep -i netfilter /boot/config-$(uname -r)
```

## Resources

- **Full API Docs**: Read `KERNEL_API.md`
- **Architecture**: Read `ARCHITECTURE.md`
- **Quick Start**: Read `README.md`
- **Integration Examples**: See `sentinel_decision_engine_example.c`
- **Inline Help**: `./sentinel_proxy_loader -h` or `make help`

---

**Last Updated:** 2026-02-18  
**Version:** 1.0.0
