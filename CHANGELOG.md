# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-02-12

### Added
- **BGP Controller Wiring**: BGP controller integrated into main BNG run flow with CLI flags (#106)
- **Circuit-ID Monitoring**: Hash collision detection in eBPF loader with Prometheus metrics (#104)
- **HA TLS/mTLS**: TLS and mutual TLS support for HA peer synchronization (#103)
- **Nexus Pool Config**: Pull gateway and DNS settings from Nexus pool configuration (#99)

### Fixed
- **ARM64 Docker Build**: Make gcc-multilib conditional on amd64 architecture (#107)
- **Security**: Per-server RADIUS rate limiting to prevent amplification attacks (#91)
- **Security**: CAP_BPF capability check before eBPF loading (#88)
- **Security**: Option 82 buffer size constants aligned (#87)
- **Security**: Zero PPPoE password bytes after authentication (#89)
- **Security**: `--radius-secret-file` and `--auth-psk-file` to avoid secrets in ps output (#72)
- **Data Races**: Atomic operations for concurrent DHCP counter access (#109)
- **Lint**: Misspell, staticcheck, unconvert issues resolved (#108)
- Critical nil panic, IP overflow, SSE backoff, and peer shutdown bugs (#97)
- URL path injection and errors.Is() cleanup (#96)

### Changed
- Test coverage significantly improved: DHCP (76.9%), RADIUS (87.1%), NAT (74.4%), subscriber (100%), eBPF (45.6%)
- Replaced hand-rolled HTTP test handlers with httpmock (#94)

## [0.3.0] - 2026-02-01

### Added
- **HA Failover Controller**: Automatic active/standby failover with health monitoring (#62)
- **HA P2P State Sync**: Peer-to-peer state synchronization for HA pairs (#62)
- **ZTP Bootstrap Client**: Nexus registration for zero-touch provisioning (#25)
- **Walled Garden Mode**: Lookup-first logic for captive portal (#84)
- **Nexus Integration CLI**: HA flags for distributed IP allocation
- **Audit Logging**: Security audit event types and helpers (#59)
- **Agent TLS**: Certificate validation for ZTP client (#58)
- **DHCP Load Testing**: Load test suite and eBPF map tests (#8, #14)
- **Resilience Tests**: Chaos/partition tests for CRDT merge recovery
- **BPF Kernel Verification**: Verify eBPF programs against real kernel verifier (#93)

### Fixed
- Accept Nexus-allocated IPs in DHCP REQUEST
- Dockerfile updated for Go 1.25 and SSH mount
- errors.Is() used instead of == for error comparisons (#70)
- HTTPAllocator test failures and race conditions (#82, #83)
- Broken switch/else-if syntax in DHCP server

### Changed
- Comprehensive test coverage improvements across ebpf, nexus, nat, radius, pppoe, and fuzz tests

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

[0.4.0]: https://github.com/codelaboratoryltd/bng/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/codelaboratoryltd/bng/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/codelaboratoryltd/bng/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/codelaboratoryltd/bng/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/codelaboratoryltd/bng/releases/tag/v0.0.1
