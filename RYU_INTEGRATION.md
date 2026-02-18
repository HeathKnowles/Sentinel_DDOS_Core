# Sentinel DDoS Core - Ryu Integration

## Quick Start

### 1. Start Ryu Controller
```bash
ryu-manager ryu.app.simple_switch_13 ryu.app.ofctl_rest
```

This starts Ryu with:
- `simple_switch_13`: Basic L2 learning switch (OpenFlow 1.3)
- `ofctl_rest`: REST API on port 8080

### 2. Start Mininet Topology
```bash
sudo mn --topo single,3 \
  --controller=remote,ip=127.0.0.1,port=6633 \
  --switch ovs,protocols=OpenFlow13
```

This creates:
- 1 OVS switch (dpid=1)
- 3 hosts (h1, h2, h3)
- OpenFlow 1.3 protocol

### 3. Test Ryu Integration
```bash
./test_ryu_integration.sh
```

This verifies:
- ✓ Ryu is reachable
- ✓ Flows can be pushed
- ✓ Flows can be deleted
- ✓ Cookie-based tracking works

### 4. Start Sentinel Pipeline
```bash
sudo ./start_with_ryu.sh
```

This will:
- Load `sentinel_proxy.ko` kernel module
- Start the pipeline with `--dpid 1`
- Connect to Ryu at `http://127.0.0.1:8080`

---

## Testing DDoS Detection

### From Mininet CLI

```bash
# Normal traffic (should work)
mininet> h1 ping -c 3 h2

# UDP flood (will be detected and blocked)
mininet> h1 hping3 -2 -i u1 -p 53 10.0.0.2

# SYN flood (will be detected and blocked)
mininet> h3 hping3 -S -i u1 -p 80 10.0.0.2
```

### Check Sentinel Flows in Ryu

```bash
# List all flows on switch 1
curl http://127.0.0.1:8080/stats/flow/1 | python3 -m json.tool

# Filter for Sentinel flows (cookie prefix 0x5E40000000000000)
curl -s http://127.0.0.1:8080/stats/flow/1 | \
  python3 -c "import sys,json; flows=json.load(sys.stdin)['1']; \
  [print(f) for f in flows if f['cookie'] > 6791418742620364800]"
```

### Monitor Sentinel Pipeline

```bash
# Send SIGUSR1 for stats
sudo killall -USR1 sentinel_pipeline

# Send SIGUSR2 to reset baselines
sudo killall -USR2 sentinel_pipeline
```

---

## Configuration

### Sentinel Pipeline Options

```
./sentinel_pipeline [OPTIONS]
  -d, --daemon           Daemonise
  -m, --mode MODE        Filter mode: learn/detect/protect (default protect)
  -c, --controller URL   Ryu REST URL (default http://127.0.0.1:8080)
  -n, --dpid DPID        Default switch dpid (default 1)
  -v, --verbose          Verbose logging
  -h, --help             This message
```

### Filter Modes

- **learn**: Passively observe traffic, build baselines (no blocking)
- **detect**: Detect attacks, log alerts (no blocking)
- **protect**: Detect attacks and push blocking rules to Ryu

---

## Architecture

```
┌─────────────┐
│   Mininet   │  h1, h2, h3
│   Topology  │  (10.0.0.1, 10.0.0.2, 10.0.0.3)
└──────┬──────┘
       │ OpenFlow
       ↓
┌─────────────┐
│  OVS Switch │  dpid=1
│   (s1)      │  OpenFlow 1.3
└──────┬──────┘
       │ OpenFlow 1.3
       ↓
┌─────────────────────┐
│   Ryu Controller    │  Port 6633 (OpenFlow)
│  - simple_switch_13 │  Port 8080 (REST API)
│  - ofctl_rest       │
└──────┬──────────────┘
       │ REST API (port 8080)
       ↓
┌──────────────────────────────────┐
│    Sentinel DDoS Core            │
│                                  │
│  ┌────────────────────────────┐  │
│  │  sentinel_proxy.ko         │  │  Intercepts packets
│  │  (kernel module)           │  │  via netfilter hooks
│  └────────┬───────────────────┘  │
│           │ /dev/sentinel_proxy  │
│           ↓                      │
│  ┌────────────────────────────┐  │
│  │  sentinel_pipeline         │  │  Feature extraction
│  │  (userspace daemon)        │  │  ML heuristics
│  │                            │  │  Decision engine
│  │  - Feature Extractor       │  │
│  │  - Decision Engine         │  │
│  │  - SDN Controller (Ryu)    │  │  Push flows via REST
│  │  - Feedback Loop           │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
```

---

## Flow Format (Ryu ofctl_rest)

Sentinel flows use a **cookie prefix** `0x5E40000000000000` for identification:

```json
{
  "dpid": 1,
  "cookie": 6791418742620373999,
  "cookie_mask": 18374686479671623680,
  "table_id": 0,
  "idle_timeout": 120,
  "hard_timeout": 300,
  "priority": 500,
  "match": {
    "dl_type": 2048,
    "nw_src": "10.0.0.1/32",
    "nw_proto": 17,
    "tp_src": 12345
  },
  "actions": []
}
```

- Empty `actions` = DROP
- `{"type": "OUTPUT", "port": "NORMAL"}` = ALLOW
- `{"type": "OUTPUT", "port": N}` = REDIRECT to port N

---

## Troubleshooting

### Ryu not reachable
```bash
# Check if Ryu is running
curl http://127.0.0.1:8080/stats/switches

# Restart Ryu
ryu-manager ryu.app.simple_switch_13 ryu.app.ofctl_rest
```

### Kernel module issues
```bash
# Check if loaded
lsmod | grep sentinel_proxy

# Check dmesg for errors
dmesg | tail -20

# Reload module
sudo rmmod sentinel_proxy
sudo insmod proxy/sentinel_proxy.ko
```

### Device not found
```bash
# Check device exists
ls -l /dev/sentinel_proxy

# Check kernel log
dmesg | grep sentinel
```

### No flows pushed
```bash
# Check Sentinel logs (verbose mode)
sudo ./sentinel_pipeline --verbose --dpid 1

# Verify Ryu is receiving requests
# (watch Ryu terminal for POST /stats/flowentry/add)
```

---

## Cleanup

```bash
# Stop Sentinel pipeline
sudo killall sentinel_pipeline

# Unload kernel module
sudo rmmod sentinel_proxy

# Stop Mininet
sudo mn -c

# Stop Ryu
# (Ctrl+C in Ryu terminal)
```
