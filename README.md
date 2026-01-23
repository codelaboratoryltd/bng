# BNG (Broadband Network Gateway)

eBPF/XDP-accelerated BNG implementation for ISP edge deployments.

## Overview

This project implements a high-performance Broadband Network Gateway using eBPF/XDP for kernel-level packet processing. The BNG runs directly on OLT hardware at ISP edge locations, eliminating dedicated BNG appliances.

### Key Features

- **eBPF/XDP Fast Path**: Kernel-level DHCP processing for sub-100μs latency
- **Nexus Integration**: Centralized IP allocation via hashring (at RADIUS time, not DHCP)
- **Offline-First**: Edge sites continue operating during network partitions
- **Multi-ISP Support**: Per-subscriber routing to different upstream ISPs
- **Zero-Touch Provisioning**: OLTs self-register and pull config from central Nexus

## Architecture

### IP Allocation Model

**Critical Design Point**: IP allocation happens at **RADIUS authentication time**, not DHCP time.

```
1. Subscriber authenticates via RADIUS
2. RADIUS success → Nexus allocates IP (hashring-based, deterministic)
3. IP stored in subscriber record
4. DHCP is just a READ operation (lookup pre-allocated IP)
```

This means:
- No IP conflicts between distributed BNG nodes
- DHCP fast path can run entirely in eBPF (no userspace allocation)
- Subscriber always gets the same IP (hashring determinism)

### Two-Tier DHCP: Fast Path + Slow Path

```
DHCP Request arrives
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│                  XDP Fast Path (Kernel)                   │
│                                                           │
│  1. Parse Ethernet → IP → UDP → DHCP                     │
│  2. Extract client MAC                                    │
│  3. Lookup MAC in eBPF subscriber_pools map              │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ CACHE HIT?                                          │ │
│  │ ├─ YES: Generate DHCP OFFER/ACK in kernel          │ │
│  │ │       Return XDP_TX (~10μs latency)              │ │
│  │ └─ NO:  Return XDP_PASS → userspace                │ │
│  └─────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────┘
        │ XDP_PASS (cache miss)
        ▼
┌───────────────────────────────────────────────────────────┐
│                  Go Slow Path (Userspace)                 │
│                                                           │
│  1. Lookup subscriber in Nexus (by MAC)                  │
│  2. Get pre-allocated IP from subscriber record          │
│  3. Update eBPF cache for future fast path hits          │
│  4. Send DHCP response                                    │
└───────────────────────────────────────────────────────────┘
```

### Deployment Model

```
┌─────────────────────────────────────────────────────────────┐
│  CENTRAL (Kubernetes at NOC/POP)                            │
│  Control plane only - NO subscriber traffic                 │
│                                                             │
│  ├── Nexus: CLSet CRDT, hashring IP allocation, bootstrap  │
│  ├── Prometheus/Grafana: Monitoring                         │
│  └── ISP RADIUS: Authentication                             │
└─────────────────────────────┬───────────────────────────────┘
                              │ Config sync, metrics (NOT subscriber traffic)
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│  OLT-BNG #1   │     │  OLT-BNG #2   │     │  OLT-BNG #N   │
│  (Bare Metal) │     │  (Bare Metal) │     │  (Bare Metal) │
│               │     │               │     │               │
│  XDP + Go     │     │  XDP + Go     │     │  XDP + Go     │
│  1,500 subs   │     │  2,000 subs   │     │  1,800 subs   │
└───────┬───────┘     └───────┬───────┘     └───────┬───────┘
        │                     │                     │
   Subscriber            Subscriber            Subscriber
   traffic LOCAL         traffic LOCAL         traffic LOCAL
        │                     │                     │
        ▼                     ▼                     ▼
   Direct to ISP         Direct to ISP         Direct to ISP
```

## Quick Start

### Build

```bash
# Build BNG binary
go build -o bin/bng ./cmd/bng

# Build eBPF programs (requires Linux with clang)
make -C bpf
```

### Run

```bash
# Basic run with local pool (standalone mode)
sudo ./bin/bng run \
  --interface eth1 \
  --pool-network 10.0.1.0/24 \
  --pool-gateway 10.0.1.1 \
  --log-level info

# With Nexus integration (production mode)
sudo ./bin/bng run \
  --interface eth1 \
  --nexus-url http://nexus.internal:9000 \
  --radius-enabled \
  --radius-servers radius.isp.com:1812 \
  --radius-secret secret123
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--interface, -i` | Subscriber-facing network interface | `eth1` |
| `--bpf-path` | Path to compiled eBPF program | `bpf/dhcp_fastpath.bpf.o` |
| `--pool-network` | Fallback IP pool (CIDR) | `10.0.1.0/24` |
| `--pool-gateway` | Fallback pool gateway | `10.0.1.1` |
| `--metrics-addr` | Prometheus metrics endpoint | `:9090` |
| `--radius-enabled` | Enable RADIUS authentication | `false` |
| `--qos-enabled` | Enable QoS rate limiting | `false` |
| `--nat-enabled` | Enable NAT44/CGNAT | `false` |

## Project Structure

```
bng/
├── cmd/bng/              # Main BNG binary
│   └── main.go
├── pkg/
│   ├── ebpf/             # eBPF loader and map management
│   ├── dhcp/             # DHCP slow path server + pool management
│   ├── nexus/            # Nexus client (IP allocation, state sync)
│   ├── radius/           # RADIUS client + CoA + policy
│   ├── qos/              # QoS/rate limiting (TC eBPF)
│   ├── nat/              # NAT44/CGNAT (TC eBPF)
│   ├── pppoe/            # PPPoE server
│   ├── routing/          # BGP/FRR integration
│   ├── subscriber/       # Session management
│   └── metrics/          # Prometheus metrics
├── bpf/
│   ├── dhcp_fastpath.c   # XDP DHCP fast path
│   ├── qos_ratelimit.c   # TC QoS eBPF
│   ├── nat44.c           # TC NAT eBPF
│   ├── antispoof.c       # TC anti-spoofing eBPF
│   ├── maps.h            # Shared eBPF map definitions
│   └── Makefile
└── docs/
    ├── ARCHITECTURE.md
    ├── FEATURES.md
    └── TODO.md
```

## eBPF Maps

The fast path uses these eBPF maps (defined in `bpf/maps.h`):

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `subscriber_pools` | HASH | MAC (u64) | `pool_assignment` | Subscriber → allocated IP |
| `ip_pools` | HASH | pool_id (u32) | `ip_pool` | Pool metadata (gateway, DNS, lease) |
| `server_config` | ARRAY | 0 | `dhcp_server_config` | Server MAC/IP for replies |
| `stats_map` | ARRAY | 0 | `dhcp_stats` | Performance counters |

## IP Allocation Flow

### With Nexus (Production)

```
1. ONT powers on, subscriber connects
2. PPPoE/IPoE triggers RADIUS authentication
3. RADIUS → Nexus: AllocateIP(subscriber_id)
4. Nexus: Hash(subscriber_id) → deterministic IP from pool
5. IP stored in subscriber record, RADIUS returns success
6. DHCP DISCOVER arrives
7. BNG: Lookup subscriber by MAC in Nexus cache
8. BNG: Return pre-allocated IP in DHCP OFFER
9. Update eBPF map for future fast-path hits
```

### Without Nexus (Standalone/Fallback)

```
1. DHCP DISCOVER arrives
2. No Nexus → use local pool (--pool-network)
3. Allocate IP from local pool
4. Update eBPF map
5. Return DHCP OFFER
```

## Performance

| Metric | Target | Notes |
|--------|--------|-------|
| Fast Path Latency | <100μs P99 | XDP in kernel |
| Slow Path Latency | <10ms P99 | Userspace + Nexus lookup |
| Throughput | 50,000+ req/sec | Combined fast+slow |
| Cache Hit Rate | >95% | After warmup |
| Active Subscribers | 100,000+ | Per BNG node |

## Component Status

| Component | Status | Notes |
|-----------|--------|-------|
| eBPF Fast Path | ✅ Complete | XDP DHCP parser + reply generator |
| DHCP Slow Path | ✅ Complete | Full DORA cycle |
| Nexus Integration | ✅ Complete | Hashring IP allocation |
| RADIUS Client | ✅ Complete | Auth + accounting |
| QoS/Rate Limiting | ✅ Complete | TC eBPF |
| NAT44/CGNAT | ✅ Complete | TC eBPF + logging |
| PPPoE | ✅ Complete | Session management |
| BGP/Routing | ✅ Complete | FRR integration |
| Metrics | ✅ Complete | Prometheus |

## Requirements

- **OS**: Linux kernel 5.10+ (for eBPF/XDP)
- **Go**: 1.21+
- **eBPF Tools**: clang, llvm, libbpf-dev
- **Runtime**: Root privileges (CAP_BPF, CAP_NET_ADMIN)

## Why eBPF/XDP over VPP?

For edge deployments (10-40 Gbps per OLT):

| Aspect | eBPF/XDP | VPP |
|--------|----------|-----|
| Performance | 10-40 Gbps ✓ | 100+ Gbps (overkill) |
| Deployment | Standard Linux | DPDK, hugepages, dedicated NICs |
| Operations | systemd service | Complex dedicated hardware |
| Debugging | tcpdump, bpftool | Custom tools |

VPP is the right choice for core aggregation (100+ Gbps), but eBPF/XDP is simpler and sufficient for edge.

## Related Projects

- [Nexus](https://github.com/codelaboratoryltd/nexus) - Central coordination server (CLSet CRDT)
- [FRR](https://frrouting.org/) - Routing suite for BGP
- [cilium/ebpf](https://github.com/cilium/ebpf) - eBPF Go library

## License

BSL 1.1 (Business Source License) - see [LICENSE](LICENSE)

Converts to Apache 2.0 on January 1, 2030.
