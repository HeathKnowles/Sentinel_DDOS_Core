# Sentinel DDoS Core Controller Integration

This document covers running Sentinel with a real OpenFlow controller endpoint that exposes `/stats/*` APIs.

## Supported Controller Runtime

Use `start_ryu.py` from this repository. It starts whichever runtime is available in this order:

1. local `.venv-controller/bin/ryu-manager`
2. system `ryu-manager`
3. system `osken-manager`
4. `python3 -m ryu.cmd.manager`
5. `python3 -m os_ken.cmd.manager`

Required app set:
- switch behavior: `simple_switch_13` (Ryu) or `ofp_handler` (OS-Ken equivalent)
- REST endpoints: `ofctl_rest`

## End-To-End Setup

Run these commands from `Sentinel_DDOS_Core/`.

### 1. Start controller

```bash
python3 start_ryu.py
```

Expected behavior:
- OpenFlow listener on `0.0.0.0:6633`
- REST listener on `0.0.0.0:8080`

Quick check:

```bash
curl -s http://127.0.0.1:8080/stats/switches
```

### 2. Start Mininet test topology

```bash
sudo mn --topo single,3 --controller=remote,ip=127.0.0.1,port=6633 --switch ovs,protocols=OpenFlow13
```

### 3. Verify controller REST flow operations

```bash
./test_ryu_integration.sh
```

What it validates:
- controller reachability
- flow add
- flow count increase
- strict flow delete

### 4. Start Sentinel pipeline against controller

```bash
sudo ./sentinel_pipeline -i eth0 -q 0 --controller http://127.0.0.1:8080 --dpid 1 -v
```

## Useful Runtime Checks

List switches:

```bash
curl -s http://127.0.0.1:8080/stats/switches
```

List flows on switch 1:

```bash
curl -s http://127.0.0.1:8080/stats/flow/1 | python3 -m json.tool
```

Send pipeline stats signal:

```bash
sudo killall -USR1 sentinel_pipeline
```

Reset runtime baselines:

```bash
sudo killall -USR2 sentinel_pipeline
```

## Troubleshooting

Controller endpoint not reachable:

```bash
curl -v http://127.0.0.1:8080/stats/switches
```

If `/stats/*` returns 404, controller is running without `ofctl_rest`.

No switch appears in `/stats/switches`:
- confirm Mininet started with `--switch ovs,protocols=OpenFlow13`
- confirm controller is listening on port `6633`
- confirm no local firewall blocks loopback or bridge traffic

Flow add fails:
- verify `dpid` value in Sentinel args matches topology switch DPID
- inspect controller stderr for rejected match/action payload

## Cleanup

```bash
sudo killall sentinel_pipeline 2>/dev/null || true
sudo mn -c
```
