# BNG (Broadband Network Gateway)

eBPF/XDP-accelerated BNG implementation for Kubernetes edge deployments.

## Project Overview

This project implements a cloud-native Broadband Network Gateway using eBPF/XDP for high-performance packet processing at ISP edge locations. The architecture runs BNG functions directly on OLT hardware, eliminating dedicated BNG appliances.

### Key Features

- **eBPF/XDP Fast Path**: Kernel-level packet processing for sub-millisecond latency
- **State Management**: In-memory store with CRDT-ready interface (CLSet integration planned)
- **Kubernetes Native**: Cilium CNI integration, GitOps deployment
- **Multi-ISP Support**: Policy-based routing with per-ISP routing tables
- **Zero-Touch Provisioning**: OLTs self-register and auto-configure
- **Offline-First**: Edge sites continue operating during network partitions
- **Structural Separation**: Supports NetCo/ISPCo model with subscriber portability

## Architecture

```
                                    INTERNET
                                        │
                    ┌───────────────────┼───────────────────┐
                    ▼                   ▼                   ▼
              ┌──────────┐        ┌──────────┐        ┌──────────┐
              │  ISP-A   │        │  ISP-B   │        │  ISP-C   │
              │ AS 64501 │        │ AS 64502 │        │ AS 64503 │
              └────┬─────┘        └────┬─────┘        └────┬─────┘
                   │ eBGP              │                   │
                   ▼                   ▼                   ▼
         ═══════════════════════════════════════════════════════
                    Core/Aggregation Network (L2/MPLS)
         ═══════════════════════════════════════════════════════
                   │                                   │
                   ▼                                   ▼
          ┌─────────────────┐                ┌─────────────────┐
          │   OLT-BNG #1    │                │   OLT-BNG #2    │
          │   (Edge Site)   │                │   (Edge Site)   │
          │   1,500 subs    │                │   2,000 subs    │
          └────────┬────────┘                └────────┬────────┘
                   │ PON                              │
                   ▼                                  ▼
            ┌──────────────┐                  ┌──────────────┐
            │  ONT   ONT   │                  │  ONT   ONT   │
            │  ONT   ONT   │                  │  ONT   ONT   │
            └──────────────┘                  └──────────────┘
```

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Complete system architecture with diagrams |
| [FEATURES.md](./FEATURES.md) | Comprehensive feature specification |
| [TODO.md](./TODO.md) | Implementation roadmap and task list |
| [CLAUDE.md](./CLAUDE.md) | Development guidelines for AI assistance |
| [ebpf-dhcp-architecture.md](./ebpf-dhcp-architecture.md) | eBPF/XDP DHCP design |

## Package Structure

```
pkg/
├── nexus/          # CLSet client - CRDT-based distributed state
├── pon/            # PON management - ONU discovery and provisioning
├── routing/        # Upstream routing - BGP/FRR, policy routing, ECMP
├── walledgarden/   # Captive portal - MAC-based subscriber quarantine
├── dhcp/           # DHCP server - IPv4 allocation
├── dhcpv6/         # DHCPv6 server - IPv6 allocation
├── nat/            # NAT44/CGNAT - carrier-grade NAT with logging
├── qos/            # QoS - HTB rate limiting, traffic shaping
├── radius/         # RADIUS client - multi-ISP authentication
├── pppoe/          # PPPoE server - session management
├── antispoof/      # Anti-spoofing - MAC/IP binding enforcement
├── slaac/          # SLAAC/RADVD - IPv6 autoconfiguration
├── ebpf/           # eBPF loader - XDP/TC program management
├── agent/          # Nexus agent - bootstrap and state sync
└── metrics/        # Prometheus metrics
```

## Key Components

### Routing (`pkg/routing/`)

Multi-ISP routing with BGP/FRR integration:

- **Static Routes**: Default gateway management
- **Policy Routing**: Source-based routing via `ip rule`
- **ECMP**: Load balancing across multiple upstreams
- **BGP Controller**: FRR integration via vtysh
- **Health Checking**: ICMP/BFD with hysteresis

```go
// Route subscriber to their ISP
manager.RouteSubscriberToISP(subscriberIP, ispTableID)

// Announce prefix via BGP
bgp.AnnouncePrefix(net.ParseCIDR("100.64.0.0/22"))
```

### Nexus (`pkg/nexus/`)

State management with CRDT-ready interface:

- **Typed Stores**: Subscribers, NTEs, ISPs, Pools, Devices
- **Watch Callbacks**: React to state changes
- **Local Cache**: In-memory with background sync
- **VLAN Allocation**: S-TAG/C-TAG assignment
- **Future**: CLSet CRDT backend for multi-region sync

### Walled Garden (`pkg/walledgarden/`)

Captive portal for unauthenticated subscribers:

- **MAC-Based State**: Unknown, WalledGarden, Provisioned, Blocked
- **eBPF Integration**: Kernel-level traffic redirection
- **Expiry Management**: Automatic cleanup of stale entries

## Technology Stack

| Layer | Technology |
|-------|------------|
| Packet Processing | eBPF/XDP |
| Control Plane | Go |
| Routing Daemon | FRR (bgpd, bfdd) |
| State Management | In-memory (CRDT-ready) |
| Container Platform | Kubernetes |
| CNI | Cilium |
| Observability | Prometheus, Hubble |

## Development

### Prerequisites

- Go 1.21+
- Linux kernel 5.10+ (for eBPF/XDP)
- clang/LLVM (for eBPF compilation)
- k3d (for local Kubernetes)
- FRR (for BGP integration testing)

### Build

```bash
# Build BNG binary
go build -o bin/bng ./cmd/bng

# Run tests
go test ./...

# Build eBPF programs
make -C bpf
```

### Local Development

```bash
# Create k3d cluster with Cilium
k3d cluster create -c clusters/local-tilt/k3d-config.yaml

# Start development environment
tilt up
```

## Status

**Active Development** - Core packages implemented, eBPF integration in progress.

| Component | Status |
|-----------|--------|
| Nexus State Client | ✅ Complete |
| PON Manager | ✅ Complete |
| Walled Garden | ✅ Complete |
| Routing/BGP | ✅ Complete |
| DHCP/DHCPv6 | ✅ Complete |
| NAT/CGNAT | ✅ Complete |
| QoS | ✅ Complete |
| RADIUS | ✅ Complete |
| PPPoE | ✅ Complete |
| Anti-Spoofing | ✅ Complete |
| Audit Logging | ✅ Complete |
| Lawful Intercept | ✅ Complete |
| DNS Services | ✅ Complete |
| Central State Store | ✅ Complete |
| Subscriber/Session | 🚧 In Progress |
| eBPF Fast Path | 📋 Planned |

## Why eBPF/XDP over VPP?

For edge deployment (10-40 Gbps), eBPF/XDP is preferred:

| Aspect | eBPF/XDP | VPP |
|--------|----------|-----|
| Performance | 10-40 Gbps (sufficient for edge) | 100+ Gbps |
| K8s Integration | Native (Cilium) | Requires privileged pods |
| Operations | Simple (standard Linux) | Complex (DPDK, hugepages) |
| Observability | Hubble | Custom instrumentation |
| Resource Sharing | Yes | Dedicated hardware |

VPP remains the right choice for core aggregation (100+ Gbps).

## Related Projects

- [Cilium](https://cilium.io/) - eBPF-based networking
- [FRR](https://frrouting.org/) - Open source routing suite
- [VPP](https://fd.io/) - Vector Packet Processing (for core)

## Author

Mark Gascoyne
Lead Software Engineer
## License

TBD
