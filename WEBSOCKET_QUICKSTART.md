# WebSocket Quickstart

Sentinel exposes live telemetry over WebSocket when `-w` or `--websocket` is set.

## 1. Build

From `Sentinel_DDOS_Core/`:

```bash
make
```

## 2. Start pipeline with WebSocket enabled

```bash
sudo ./sentinel_pipeline -i eth0 -q 0 -w 8765
```

With controller integration:

```bash
sudo ./sentinel_pipeline -i eth0 -q 0 -w 8765 --controller http://127.0.0.1:8080 --dpid 1 -v
```

## 3. Open the example dashboard

Open:
- `websocket/example_client.html`

The page connects to `ws://localhost:8765` by default.

## 4. Verify telemetry flow

- check terminal logs for packet processing and verdict activity
- generate traffic (for example ping/hping) and confirm dashboard updates

## Streams

The server publishes these stream types:
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

## Troubleshooting

Port already in use:

```bash
sudo lsof -i :8765
```

No client connection:

```bash
ss -ltn | grep 8765
```

No live data:
- run pipeline with `-v`
- verify traffic is reaching the monitored interface/queue
- check browser console for JSON parse or connection errors

## Security

Current transport is plain `ws://` and unauthenticated.

For production:
- terminate TLS (`wss://`) at a reverse proxy
- enforce authentication/authorization at the edge
- restrict network access to management endpoints
