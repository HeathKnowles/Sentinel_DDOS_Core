#!/bin/bash
#
# Test Ryu integration with Sentinel pipeline
#
# Prerequisites:
#   - Controller running with ofctl_rest (python3 start_ryu.py)
#   - Mininet topology with OpenFlow 1.3 switch
#

set -e

RYU_URL="${RYU_URL:-http://127.0.0.1:8080}"
DPID=1

echo "=== Sentinel DDoS Core - Ryu Integration Test ==="
echo ""

# Test 1: Health check
echo "[1] Testing Ryu connectivity..."
if curl -sf "$RYU_URL/stats/switches" > /dev/null; then
    echo "[OK] Ryu reachable at $RYU_URL"
    SWITCHES=$(curl -s "$RYU_URL/stats/switches")
    echo "  Connected switches: $SWITCHES"
else
    if curl -sf "$RYU_URL" > /dev/null 2>&1; then
        echo "[FAIL] Controller is reachable but /stats REST endpoints are unavailable."
        echo "      This controller build does not include ofctl_rest."
    else
        echo "[FAIL] Ryu not reachable after startup attempts"
    fi
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
    echo "[FAIL] Failed to push flow:"
    echo "  $RESPONSE"
    exit 1
else
    echo "[OK] Flow pushed successfully"
fi

# Test 4: Verify flow was added
echo ""
echo "[4] Verifying flow was installed..."
sleep 1
FLOW_JSON_AFTER_ADD="/tmp/sentinel_test_flows_after_add.json"
curl -s "$RYU_URL/stats/flow/$DPID" > "$FLOW_JSON_AFTER_ADD"
NEW_FLOW_COUNT=$(grep -o '"cookie":' "$FLOW_JSON_AFTER_ADD" | wc -l)
echo "  New flow count: $NEW_FLOW_COUNT"

if grep -q "$TEST_COOKIE" "$FLOW_JSON_AFTER_ADD"; then
    echo "[OK] Test cookie is present on switch"
elif [ "$NEW_FLOW_COUNT" -gt "$FLOW_COUNT" ]; then
    echo "[OK] Flow count increased"
else
    echo "[FAIL] Flow count did not increase"
    exit 1
fi

# Test 5: Remove the test flow
echo ""
echo "[5] Removing test flow..."
cat > /tmp/sentinel_test_delete.json <<EOF
{
  "dpid": $DPID,
  "cookie": $TEST_COOKIE,
  "cookie_mask": 18446744073709551615
}
EOF

curl -s -X POST -H "Content-Type: application/json" \
     -d @/tmp/sentinel_test_delete.json \
     "$RYU_URL/stats/flowentry/delete" > /dev/null

sleep 1
FLOW_JSON_AFTER_DEL="/tmp/sentinel_test_flows_after_del.json"
curl -s "$RYU_URL/stats/flow/$DPID" > "$FLOW_JSON_AFTER_DEL"
FINAL_FLOW_COUNT=$(grep -o '"cookie":' "$FLOW_JSON_AFTER_DEL" | wc -l)
echo "  Final flow count: $FINAL_FLOW_COUNT"

if grep -q "$TEST_COOKIE" "$FLOW_JSON_AFTER_DEL"; then
    echo "[FAIL] Test flow cookie still present after delete"
    exit 1
elif [ "$FINAL_FLOW_COUNT" -le "$NEW_FLOW_COUNT" ]; then
    echo "[OK] Test flow removed successfully"
else
    echo "[WARN] Flow count changed due to concurrent controller activity"
fi

rm -f /tmp/sentinel_test_flow.json /tmp/sentinel_test_delete.json \
      "$FLOW_JSON_AFTER_ADD" "$FLOW_JSON_AFTER_DEL"

echo ""
echo "=== All tests passed! ==="
echo ""
echo "Ready to run Sentinel pipeline:"
echo "  1. Build binary:        make"
echo "  2. Run pipeline:        sudo ./sentinel_pipeline -i eth0 -q 0 --controller $RYU_URL --dpid 1 -v"
echo ""
