# BNG (Broadband Network Gateway)

eBPF/XDP-accelerated BNG implementation for Kubernetes edge deployments.

## Project Overview

This project explores building a cloud-native Broadband Network Gateway using eBPF/XDP for high-performance packet processing at ISP edge locations. The design targets 10-40 Gbps throughput with native Kubernetes integration.

### Key Features

- **eBPF/XDP Fast Path**: Kernel-level DHCP processing for sub-millisecond latency
- **CRDT State Management**: Distributed state sync via Neelix for multi-region consistency
- **Kubernetes Native**: Cilium CNI integration, GitOps deployment
- **10x Performance**: 50k+ DHCP req/sec (vs 5k baseline)
- **Edge Optimized**: Designed for 10-40 Gbps edge PoPs (not core aggregation)

## Documentation

- [eBPF-DHCP Architecture](./ebpf-dhcp-architecture.md) - Complete technical design document

## Architecture Decision

This project uses **pure eBPF/XDP** instead of VPP for edge deployment because:
- Performance sufficient (10-40 Gbps covers edge scale)
- Native Kubernetes integration (Cilium CNI)
- Simpler operations (no DPDK, no hugepages)
- Superior observability (Hubble)
- Cost-effective (shared infrastructure)

See [Architecture Decision section](./ebpf-dhcp-architecture.md#architecture-decision-ebpf-vs-vpp) for VPP vs eBPF comparison.

## Use Cases

- ISP edge DHCP acceleration
- Subscriber IP allocation at scale (100k+ subscribers per edge)
- Multi-region state synchronization
- Future: Full BNG functionality (PPPoE/IPoE, CGNAT, QoS)

## Technology Stack

- **eBPF/XDP**: Kernel packet processing
- **Go**: Userspace control plane
- **Kubernetes**: Deployment platform
- **Cilium**: CNI and observability (Hubble)
- **NATS**: Distributed messaging
- **CRDT (Neelix)**: Conflict-free replicated state

## Status

**Design Phase** - Architecture document complete, implementation not started.

## Related Work

- [Cilium eBPF](https://cilium.io/)
- [VPP BNG](https://fd.io/) - Alternative approach for core aggregation (100+ Gbps)
- Brandon Spendlove's VPP-based BNG - Mature PPPoE implementation

## Author

Mark Gascoyne
Lead Software Engineer
Vitrifi (Telecoms/ISP)

## License

TBD
