# Sentinel WebSocket Telemetry

This module provides real-time telemetry streaming for the Sentinel pipeline.

## What It Does

- accepts WebSocket client connections
- broadcasts JSON telemetry messages
- decouples packet pipeline from socket I/O using an internal queue

## Build

From `Sentinel_DDOS_Core/`:

```bash
make
```

Or build only this module:

```bash
make -C websocket
```

## Run

Enable WebSocket when starting the pipeline:

```bash
sudo ./sentinel_pipeline -i eth0 -q 0 -w 8765
```

With SDN options:

```bash
sudo ./sentinel_pipeline -i eth0 -q 0 -w 8765 --controller http://127.0.0.1:8080 --dpid 1 -v
```

## Client Example

Use the provided dashboard sample:
- `websocket/example_client.html`

Simple JavaScript snippet:

```javascript
const ws = new WebSocket("ws://localhost:8765");
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log(message.type, message.data);
};
```

## Stream Types

- `metrics`
- `activity_logs`
- `blocked_ips`
- `rate_limited_ips`
- `monitored_ips`
- `whitelisted_ips`
- `traffic_rate`
- `protocol_distribution`
- `top_sources`
- `feature_importance`
- `active_connections`
- `mitigation_status`

Message envelope:

```json
{
  "type": "stream_name",
  "data": {}
}
```

## Operational Notes

- designed for low overhead telemetry, not an authenticated management plane
- default bind is `0.0.0.0`; restrict exposure in production
- use a reverse proxy for TLS termination and access control

## Troubleshooting

Port check:

```bash
ss -ltn | grep 8765
```

Process check:

```bash
ps aux | grep sentinel_pipeline
```

If clients connect but no updates arrive:
- confirm pipeline is processing traffic on selected interface/queue
- run with `-v` and inspect runtime logs
