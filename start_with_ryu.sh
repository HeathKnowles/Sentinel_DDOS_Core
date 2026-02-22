#!/bin/bash
#
# Start Sentinel DDoS Core with Mininet/Ryu
#
# Prerequisites:
#   - Mininet running: sudo mn --topo single,3 --controller=remote,ip=127.0.0.1,port=6633 --switch ovs,protocols=OpenFlow13
#   - Controller running via ./start_ryu.py (Ryu or OS-Ken with ofctl_rest)
#

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo $0)"
    exit 1
fi

echo "=== Starting Sentinel DDoS Core ==="

# Check if Ryu is running
echo "[1] Checking controller availability..."
if ! curl -sf http://127.0.0.1:8080/stats/switches > /dev/null 2>&1; then
    echo "[FAIL] Controller not reachable. Start it with:"
    echo "  python3 start_ryu.py"
    exit 1
fi
echo "[OK] Controller is running"

# Start pipeline
echo ""
echo "[2] Starting Sentinel pipeline..."
echo "  Ryu: http://127.0.0.1:8080"
echo "  DPID: 1"
echo ""
echo "If AF_XDP map is not available, load/pin XDP first:"
echo "  make kernel"
echo "  sudo ip link set dev eth0 xdp obj proxy/sentinel_xdp.o sec xdp"
echo "  sudo bpftool map pin name xsks_map /sys/fs/bpf/xsks_map"
echo ""
echo "Press Ctrl+C to stop. Use SIGUSR1 for stats and SIGUSR2 to reset baselines."
echo ""

exec ./sentinel_pipeline \
    -i eth0 \
    -q 0 \
    --controller http://127.0.0.1:8080 \
    --dpid 1 \
    --verbose
