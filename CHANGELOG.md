# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-01-22

### Added
- **PPPoE Stack**: Full LCP, PAP/CHAP authentication, IPCP/IPV6CP negotiation, keep-alive, and teardown (#35)
- **NAT44/CGNAT**: Port block allocation, logging, hairpinning, ALGs, and Endpoint-Independent Mapping (#41)
- **IPv6 Support**: DHCPv6 server and SLAAC with prefix delegation integration (#39, #49)
- **BGP/FRR Integration**: Subscriber route injection with BFD for fast failover (#38)
- **Device Authentication**: mTLS, PSK, and TPM-based device attestation (#34)
- **RADIUS Hardening**: Interim accounting updates, teardown accounting, CoA handling (#33)
- **Partition Resilience**: Pool exhaustion handling, conflict detection, RADIUS recovery (#36)
- **QinQ Support**: Double VLAN tagging for service provider deployments (#37)
- **RADIUS-less Mode**: Standalone operation without RADIUS server (#37)
- **WiFi Gateway Mode**: Support for WiFi access point integration (#37, #50)
- **Option 82 Circuit-ID**: Re-implemented with verifier-safe fixed-offset parsing (#56, #57)
- **DHCP Fast Path Improvements**: Variable options, L2 header handling (#40)
- **CLSet Store**: Read/write mode support for distributed state (#54)
- **CLSet Adapter**: Nexus distributed state integration (#44, #51)
- **Bitmap IP Allocator**: Efficient dual-indexed allocation store (#48)
- **Nexus Cluster Documentation**: Architecture and deployment guides (#45, #52)
- **ZTP Test Coverage**: Tests for ZTP client and bootstrap packages (#28)
- **golangci-lint**: Linting configuration and CI integration

### Fixed
- eBPF verifier errors in DHCP option parsing with fixed-offset approach (#31)
- BPF instruction count reduced for verifier compliance
- Header updates moved before adjust_tail for verifier safety
- 32-bit library support for nat44.c headers in CI
- Removed unused eBPF functions causing build issues (#55)
- Routing tests skip gracefully when CAP_NET_ADMIN unavailable
- Removed local clset dependency from go.mod

## [0.1.0] - 2026-01-16

### Added
- **Core BNG Functionality**: eBPF/XDP-accelerated DHCP fast path with ~10μs latency
- **Two-Tier DHCP**: Fast path (eBPF kernel) + slow path (Go userspace) architecture
- **Nexus Integration**: IP allocation via hashring at RADIUS authentication time
- **ZTP Client**: Automatic Nexus URL discovery via DHCP options
- **PON Manager**: NTE discovery and provisioning support
- **Walled Garden**: Captive portal manager for unauthenticated subscribers
- **Routing Package**: Subscriber route management
- **Audit Package**: Security event logging
- **Intercept Package**: Lawful intercept framework
- **DNS Package**: Local DNS handling
- **VLAN Allocator**: Dynamic VLAN assignment via Nexus
- **CLSet Client**: CRDT-based state synchronization with Nexus
- **State Management**: Subscriber state and SLAAC tracking
- **Metrics**: Prometheus metrics integration
- **Comprehensive Documentation**: Architecture, ZTP flow, session lifecycle, deployment model

### Changed
- License changed to BSL 1.1 (Business Source License)
- Renamed internal references from Neelix to Nexus

### Fixed
- eBPF DHCP fast path compilation issues
- Documentation inconsistencies across all docs
- IP allocation model clarified: hashring at RADIUS time, DHCP is read-only

## [0.0.1] - 2025-12-16

### Added
- Initial project structure
- Local development environment (k3d + Tilt + Cilium)
- eBPF development environment setup
- CLAUDE.md project guidance
- TODO and FEATURES specifications
- OLT/Walled Garden architecture documentation

[0.2.0]: https://github.com/codelaboratoryltd/bng/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/codelaboratoryltd/bng/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/codelaboratoryltd/bng/releases/tag/v0.0.1
