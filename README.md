# Sentinel DDoS Core

AF_XDP-based DDoS detection and mitigation pipeline with:
- feature extraction
- decision engine (heuristic + ML)
- SDN controller integration (Ryu/OS-Ken `ofctl_rest`)
- WebSocket telemetry

## Prerequisites

- Linux with AF_XDP-capable kernel (WSL2 or native Linux for build/tests; native Linux recommended for packet path).
- `gcc`, `make`, `libcurl`, `pthread`, `openssl` development libraries.
- Optional SDN test stack: Mininet plus a controller runtime exposing `/stats/*`.

## Build And Test

From `Sentinel_DDOS_Core/`:

```bash
make
make test
```

Clean build artifacts:

```bash
make clean
```

## Run Pipeline

Basic run (with WebSocket telemetry):

```bash
sudo ./sentinel_pipeline -i eth0 -q 0 -w 8765
```

With SDN controller integration:

```bash
sudo ./sentinel_pipeline -i eth0 -q 0 --controller http://127.0.0.1:8080 --dpid 1 -v
```

## Reproduce SDN Flow Integration

1. Start controller:
```bash
python3 start_ryu.py
```
2. Start Mininet:
```bash
sudo mn --topo single,3 --controller=remote,ip=127.0.0.1,port=6633 --switch ovs,protocols=OpenFlow13
```
3. Run integration validation:
```bash
./test_ryu_integration.sh
```
4. Start pipeline:
```bash
sudo ./sentinel_pipeline -i eth0 -q 0 --controller http://127.0.0.1:8080 --dpid 1 -v
```

## Project Layout

- `featureextractor/`: packet/flow/source feature generation.
- `decisionengine/`: threat scoring and verdict logic.
- `sdncontrolplane/`: REST calls to controller flow/meter endpoints.
- `feedback/`: threshold adjustment signals from observed outcomes.
- `websocket/`: telemetry server and browser example client.
- `proxy/`: XDP/eBPF components and related docs.
- `tests/`: integration build/runtime checks.

## Security And Deployment Notes

- Controller REST and WebSocket ports are unauthenticated by default.
- Limit management ports to trusted networks or place behind authenticated TLS reverse proxy.
- Run with least privilege where possible; AF_XDP and BPF operations may require elevated capabilities.

## Related Docs

- `RYU_INTEGRATION.md`
- `WEBSOCKET_QUICKSTART.md`
- `websocket/README.md`
