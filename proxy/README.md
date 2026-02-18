# Sentinel DDoS Core - Proxy Component

**Kernel-level network traffic router for DDoS detection and mitigation**

## Quick Start

### 1. Build

```bash
cd /home/heathknowles/Code/Sentinel_DDOS_Core/proxy

# Build kernel module and userspace loader
make

# Or build individual components:
make kernel_module      # Builds sentinel_proxy.ko
make userspace_loader   # Builds sentinel_proxy_loader
```

### 2. Load Kernel Module

```bash
# Using make target (development)
sudo make load

# Or using the loader directly
./sentinel_proxy_loader -c load -m ./sentinel_proxy.ko

# Verify it loaded
lsmod | grep sentinel_proxy
dmesg | tail -5
```

### 3. Enable Filtering

```bash
# Enable packet filtering
./sentinel_proxy_loader -c enable

# Check status
./sentinel_proxy_loader -c status

# Set filter mode (0=disabled, 1=learn, 2=detect, 3=protect, 4=quarantine)
./sentinel_proxy_loader -f 3  # PROTECT mode
```

### 4. Run as Daemon (Optional)

```bash
# Run in background with logging
./sentinel_proxy_loader -d

# View logs
tail -f /var/log/syslog | grep sentinel-proxy
```

## Components

### Kernel Module (`sentinel_proxy.c`, `sentinel_proxy.ko`)

The core kernel-level packet interception engine:

- **Netfilter hooks** intercept IPv4/IPv6 traffic at PRE_ROUTING and POST_ROUTING
- **Packet metadata extraction** captures IP/port/protocol/payload info
- **Device file interface** (`/dev/sentinel_proxy`) for userspace communication
- **Statistics tracking** for all packet operations
- **Filter rules** for static packet filtering

Key features:
- Sub-millisecond interception latency
- Minimal kernel overhead (atomic operations, spinlocks)
- Support for TCP, UDP, ICMP protocols
- Both inbound and outbound traffic tracking
- Configurable decision timeout

### Userspace Loader (`sentinel_loader.c`, `sentinel_proxy_loader`)

The userspace management program:

- **Module loading/unloading** with insmod/rmmod
- **Device file communication** via ioctl
- **Statistics monitoring** with periodic updates
- **Configuration management** (filter modes, parameters)
- **Daemon mode** for production deployment
- **Decision interface** for integrating with decision engine

Key features:
- Command-line interface for all operations
- JSON-compatible statistics output
- Syslog integration for daemon mode
- Signal handling (SIGTERM, SIGINT, SIGHUP)
- Error recovery and logging

### Shared Kernel API (`kernel_api.h`)

Defines the kernel-userspace communication protocol:

```
Packet Metadata      - sentine_packet_metadata struct
Decision Verdicts    - enum sentinel_verdict
IOCTL Commands       - SENTINEL_IOCTL_* constants
Filter Rules         - sentinel_filter_rule struct
Statistics           - sentinel_module_stats struct
Modes & Direction    - enums for filtering modes and packet direction
```

## File Structure

```
proxy/
├── kernel_api.h              # Shared kernel API definitions
├── sentinel_proxy.c          # Kernel module (main)
├── sentinel_loader.c         # Userspace loader (main)
├── Makefile                  # Build configuration
├── README.md                 # This file
├── KERNEL_API.md             # Detailed API documentation
├── sentinel_proxy.ko         # Compiled kernel module (after build)
└── sentinel_proxy_loader     # Compiled userspace binary (after build)
```

## Usage Examples

### Check Kernel Module Status

```bash
# View kernel messages
dmesg | grep sentinel_proxy

# Check module is loaded
lsmod | grep sentinel_proxy

# View module parameters
cat /sys/module/sentinel_proxy/parameters/enable_filtering
cat /sys/module/sentinel_proxy/parameters/filter_mode

# Follow live kernel messages
dmesg -w | grep sentinel_proxy
```

### View Statistics

```bash
# Get current statistics
./sentinel_proxy_loader -c status

# Output:
# === Sentinel DDoS Proxy Statistics [2026-02-18 10:30:45] ===
# Packets Processed:    1234567
#   Allowed:            1200000
#   Dropped:            34567
#   Redirected:         0
#   Rate Limited:       0
#   Quarantined:        0
# Active Flows:         256
# Active Rules:         8
# Errors:               0
# ============================================
```

### Reset Statistics

```bash
./sentinel_proxy_loader -c reset-stats
```

### Disable/Re-enable Filtering

```bash
# Temporarily disable
./sentinel_proxy_loader -c disable

# Re-enable
./sentinel_proxy_loader -c enable
```

### Change Filter Mode

```bash
# Learn mode (monitor only)
./sentinel_proxy_loader -f 1

# Detect mode (report anomalies)
./sentinel_proxy_loader -f 2

# Protect mode (active filtering)
./sentinel_proxy_loader -f 3

# Quarantine mode (strict)
./sentinel_proxy_loader -f 4
```

### Unload Module

```bash
# Using make
sudo make unload

# Or using loader
./sentinel_proxy_loader -c unload

# Or directly
sudo rmmod sentinel_proxy
```

## Building from Source

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt-get install build-essential linux-headers-$(uname -r)

# RHEL/CentOS
sudo yum install gcc kernel-devel

# Check you have required headers
ls /lib/modules/$(uname -r)/build/
```

### Build Steps

```bash
cd /home/heathknowles/Code/Sentinel_DDOS_Core/proxy

# Clean previous builds
make clean

# Build
make

# View build info
make info

# Install (optional, system-wide)
sudo make install
```

## Integration with Decision Engine

The proxy module is designed to work with the Sentinel decision engine:

1. **Packet Flow**:
   - Kernel intercepts packet
   - Extracts metadata
   - Sends to userspace via device file/netlink

2. **Decision Processing**:
   - Userspace loader reads packet
   - Passes to decision engine
   - Decision engine analyzes (featureextractor, ML models, etc.)
   - Returns verdict (allow/drop/redirect/limit/quarantine)

3. **Action Application**:
   - Userspace sends decision back to kernel
   - Kernel applies verdict
   - Statistics updated

Example integration code (pseudocode):

```c
// In decision engine main loop
int fd = open("/dev/sentinel_proxy", O_RDWR);

while (running) {
    // Read pending packet
    struct sentinel_packet_metadata pkt;
    if (read(fd, &pkt, sizeof(pkt)) < 0) continue;
    
    // Analyze with decision engine
    decision = analyze_with_decision_engine(&pkt);
    
    // Send decision back
    struct sentinel_packet_decision result;
    result.packet_id = pkt.packet_id;
    result.verdict = decision.verdict;
    
    if (decision.verdict == SENTINEL_VERDICT_RATE_LIMIT) {
        result.rate_limit_pps = decision.limit_rate;
    }
    
    write(fd, &result, sizeof(result));
}

close(fd);
```

## Performance Tuning

### Kernel Module Parameters

Adjust via module parameters or `/sys/module/sentinel_proxy/parameters/`:

```bash
# Increase decision timeout (ms)
insmod ./sentinel_proxy.ko decision_timeout_ms=10000

# Disable IPv6 for faster processing
insmod ./sentinel_proxy.ko enable_ipv6=0

# View current parameters
cat /sys/module/sentinel_proxy/parameters/decision_timeout_ms
```

### Filter Mode Selection

- **LEARN (1)**: Best for establishing baseline (no filtering overhead)
- **DETECT (2)**: Good balance of detection and throughput
- **PROTECT (3)**: Production mode (depends on decision engine response time)
- **QUARANTINE (4)**: Strict security mode (highest overhead)

### Network Interface Optimization

The kernel module hooks at netfilter level. For best performance:

```bash
# Disable irqbalance if on single socket
sudo systemctl stop irqbalance

# Pin proxy loader to specific CPU
sudo taskset -p 1 $(pgrep sentinel_proxy_loader)

# Check NIC statistics
ethtool -S eth0

# Monitor CPU usage during filtering
top -p $(pgrep sentinel_proxy_loader)
```

## Troubleshooting

### Module Won't Load

```bash
# Check kernel version compatibility
uname -r

# Check for build errors
dmesg | grep sentinel_proxy

# Try verbose loading
insmod ./sentinel_proxy.ko -v

# Check kernel headers
ls /lib/modules/$(uname -r)/build/
```

### Device File Not Created

```bash
# Check if module loaded
lsmod | grep sentinel_proxy

# Device should be created automatically
ls -la /dev/sentinel_proxy

# If missing, manually create
sudo mknod /dev/sentinel_proxy c 10 $(grep sentinel_proxy /proc/misc | awk '{print $1}')
```

### No Packets Being Processed

```bash
# Check if filtering is enabled
cat /sys/module/sentinel_proxy/parameters/enable_filtering

# Enable it
echo 1 | sudo tee /sys/module/sentinel_proxy/parameters/enable_filtering

# Check filter mode
cat /sys/module/sentinel_proxy/parameters/filter_mode

# View hook registration in kernel
grep nf_register /proc/kallsyms | grep sentinel
```

### High CPU Usage

```bash
# Reduce decision timeout
insmod ./sentinel_proxy.ko decision_timeout_ms=1000

# Check active flows
./sentinel_proxy_loader -c status | grep "Active Flows"

# Reduce traffic if overwhelmed
# - Enable filter mode PROTECT instead of DETECT
# - Implement rate limiting rules
# - Check decision engine performance
```

## Security Notes

- **Module Loading**: Requires root or CAP_SYS_MODULE capability
- **Device Access**: Restrict `/dev/sentinel_proxy` to trusted processes (chmod 600)
- **Decision Engine Integration**: Use secure IPC (Unix sockets, SELinux)
- **Logging**: Sensitive data in packet payloads; consider privacy implications
- **Root Access**: Loader must run as root for netfilter hooks and device access

## Uninstalling

```bash
# Remove loadable components
sudo make uninstall

# Or manually
sudo rmmod sentinel_proxy
sudo rm /usr/local/bin/sentinel_proxy_loader
sudo rm /lib/modules/$(uname -r)/kernel/drivers/sentinel/sentinel_proxy.ko
sudo depmod -a
```

## Documentation

- **KERNEL_API.md** - Complete kernel API reference
- **Makefile** - Build system with helpful targets (`make help`)
- **kernel_api.h** - API header with comments

## Support & Development

### Common Development Tasks

```bash
# Build and load in one command
make clean && make && sudo make load

# Follow kernel debug messages
make dmesg-follow

# Reload (unload then load)
sudo make reload

# Clean all artifacts
make distclean
```

### Adding to Decision Engine

1. Include `kernel_api.h` in decision engine code
2. Open `/dev/sentinel_proxy`
3. Read packet metadata structures
4. Process with decision engine
5. Write decision back to device
6. Keep device file open for continuous operation

## Version History

- **1.0.0** (2026-02-18) - Initial release
  - Netfilter hook infrastructure
  - IPv4/IPv6 packet interception
  - Device file and ioctl interface
  - Userspace loader with CLI
  - Statistics tracking

## License

GPL v2 (Kernel Module)
