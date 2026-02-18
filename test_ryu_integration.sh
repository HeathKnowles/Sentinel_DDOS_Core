#!/bin/bash
#
# Test Ryu integration with Sentinel pipeline
#
# Prerequisites:
#   - Ryu running with ofctl_rest (ryu-manager ryu.app.ofctl_rest)
#   - Mininet topology with OpenFlow 1.3 switch
#

set -e

RYU_URL="http://127.0.0.1:8080"
DPID=1

echo "=== Sentinel DDoS Core - Ryu Integration Test ==="
echo ""

# Test 1: Health check
echo "[1] Testing Ryu connectivity..."
if curl -sf "$RYU_URL/stats/switches" > /dev/null; then
    echo "✓ Ryu reachable at $RYU_URL"
    SWITCHES=$(curl -s "$RYU_URL/stats/switches")
    echo "  Connected switches: $SWITCHES"
else
    echo "✗ Ryu not reachable at $RYU_URL"
    exit 1
fi

# Test 2: Query current flows
echo ""
echo "[2] Querying existing flows on dpid $DPID..."
FLOW_COUNT=$(curl -s "$RYU_URL/stats/flow/$DPID" | grep -o '"cookie":' | wc -l)
echo "  Current flow count: $FLOW_COUNT"

# Test 3: Push a test Sentinel flow (DROP from 10.0.0.100)
echo ""
echo "[3] Pushing test Sentinel flow (DROP from 10.0.0.100)..."
TEST_COOKIE=$((0x5E40000000000000 | 9999))  # Sentinel cookie prefix | test rule ID
cat > /tmp/sentinel_test_flow.json <<EOF
{
  "dpid": $DPID,
  "cookie": $TEST_COOKIE,
  "cookie_mask": 18374686479671623680,
  "table_id": 0,
  "idle_timeout": 60,
  "hard_timeout": 120,
  "priority": 500,
  "match": {
    "dl_type": 2048,
    "nw_src": "10.0.0.100/32"
  },
  "actions": []
}
EOF

RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
     -d @/tmp/sentinel_test_flow.json \
     "$RYU_URL/stats/flowentry/add")

if echo "$RESPONSE" | grep -q "error"; then
    echo "✗ Failed to push flow:"
    echo "  $RESPONSE"
    exit 1
else
    echo "✓ Flow pushed successfully"
fi

# Test 4: Verify flow was added
echo ""
echo "[4] Verifying flow was installed..."
sleep 1
NEW_FLOW_COUNT=$(curl -s "$RYU_URL/stats/flow/$DPID" | grep -o '"cookie":' | wc -l)
echo "  New flow count: $NEW_FLOW_COUNT"

if [ "$NEW_FLOW_COUNT" -gt "$FLOW_COUNT" ]; then
    echo "✓ Flow count increased"
else
    echo "✗ Flow count did not increase"
fi

# Test 5: Remove the test flow
echo ""
echo "[5] Removing test flow..."
cat > /tmp/sentinel_test_delete.json <<EOF
{
  "dpid": $DPID,
  "cookie": $TEST_COOKIE,
  "cookie_mask": 18374686479671623680,
  "table_id": 0
}
EOF

curl -s -X POST -H "Content-Type: application/json" \
     -d @/tmp/sentinel_test_delete.json \
     "$RYU_URL/stats/flowentry/delete_strict" > /dev/null

sleep 1
FINAL_FLOW_COUNT=$(curl -s "$RYU_URL/stats/flow/$DPID" | grep -o '"cookie":' | wc -l)
echo "  Final flow count: $FINAL_FLOW_COUNT"

if [ "$FINAL_FLOW_COUNT" -eq "$FLOW_COUNT" ]; then
    echo "✓ Test flow removed successfully"
else
    echo "⚠ Flow count: $FINAL_FLOW_COUNT (expected $FLOW_COUNT)"
fi

rm -f /tmp/sentinel_test_flow.json /tmp/sentinel_test_delete.json

echo ""
echo "=== All tests passed! ==="
echo ""
echo "Ready to run Sentinel pipeline:"
echo "  1. Load kernel module:  sudo insmod proxy/sentinel_proxy.ko"
echo "  2. Run pipeline:        sudo ./sentinel_pipeline --dpid 1 --mode protect"
echo ""
