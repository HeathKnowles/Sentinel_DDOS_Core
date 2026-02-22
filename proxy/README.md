# Proxy Dataplane (XDP)

This directory contains the eBPF/XDP dataplane program used by Sentinel AF_XDP mode.

## Files

- `sentinel_xdp.c`: XDP program source
- `Makefile`: builds `sentinel_xdp.o`
- `kernel_api.h`: shared structures/constants used across components

## Build

From `Sentinel_DDOS_Core/`:

```bash
make kernel
```

Or directly:

```bash
make -C proxy
```

This produces:
- `proxy/sentinel_xdp.o`

## Load On Interface

```bash
sudo ip link set dev eth0 xdp obj proxy/sentinel_xdp.o sec xdp
sudo bpftool map pin name xsks_map /sys/fs/bpf/xsks_map
```

Adjust `eth0` to your monitored interface.

## Unload

```bash
sudo ip link set dev eth0 xdp off
```

## Notes

- Sentinel pipeline expects the `xsks_map` to exist when running AF_XDP integration.
- If `xsks_map` is not found, the pipeline logs a warning and continues, but hardware redirect paths are unavailable.
