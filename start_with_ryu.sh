#!/bin/bash
#
# Start Sentinel DDoS Core with Mininet/Ryu
#
# Prerequisites:
#   - Mininet running: sudo mn --topo single,3 --controller=remote,ip=127.0.0.1,port=6633 --switch ovs,protocols=OpenFlow13
#   - Ryu running: ryu-manager ryu.app.simple_switch_13 ryu.app.ofctl_rest
#

set -e

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (sudo $0)"
    exit 1
fi

echo "=== Starting Sentinel DDoS Core ==="

# Check if Ryu is running
echo "[1] Checking Ryu availability..."
if ! curl -sf http://127.0.0.1:8080/stats/switches > /dev/null 2>&1; then
    echo "✗ Ryu not reachable. Start it with:"
    echo "  ryu-manager ryu.app.simple_switch_13 ryu.app.ofctl_rest"
    exit 1
fi
echo "✓ Ryu is running"

# Check if kernel module is loaded
echo ""
echo "[2] Checking kernel module..."
if lsmod | grep -q sentinel_proxy; then
    echo "⚠ sentinel_proxy already loaded, reloading..."
    rmmod sentinel_proxy 2>/dev/null || true
fi

echo "  Loading sentinel_proxy.ko..."
insmod proxy/sentinel_proxy.ko
echo "✓ Kernel module loaded"

# Wait for device
sleep 1
if [ ! -c /dev/sentinel_proxy ]; then
    echo "✗ /dev/sentinel_proxy not found"
    exit 1
fi
echo "✓ Device /dev/sentinel_proxy ready"

# Start pipeline
echo ""
echo "[3] Starting Sentinel pipeline..."
echo "  Mode: protect"
echo "  Ryu: http://127.0.0.1:8080"
echo "  DPID: 1"
echo ""
echo "Press Ctrl+C to stop. Use SIGUSR1 for stats, SIGUSR2 to reset baselines."
echo ""

exec ./sentinel_pipeline \
    --mode protect \
    --controller http://127.0.0.1:8080 \
    --dpid 1 \
    --verbose
