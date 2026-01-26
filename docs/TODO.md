# BNG Project Roadmap

**Current Version**: v0.2.0 (released 2026-01-22)

**Status**: ✅ All core BNG functionality implemented. In production hardening phase.

---

## ✅ Completed Milestones

### v0.2.0 - Full BNG Feature Set (2026-01-22)
**What we shipped:**
- Full PPPoE stack (LCP, PAP/CHAP, IPCP/IPV6CP, keep-alive, teardown)
- NAT44/CGNAT with port blocks, ALGs, hairpinning
- IPv6 support (DHCPv6, SLAAC, prefix delegation)
- BGP/FRR integration with BFD failover
- Device authentication (mTLS, PSK, TPM attestation)
- RADIUS hardening (interim updates, CoA, teardown accounting)
- QinQ support, Option 82 parsing, partition resilience
- CLSet distributed state management

**Test Coverage**: 45.9% overall (package-specific coverage varies)

### v0.1.0 - Core BNG (2026-01-16)
**What we shipped:**
- eBPF/XDP DHCP fast path (~10μs latency, 50k req/sec target)
- Two-tier DHCP architecture (fast path + slow path)
- RADIUS integration with hashring IP allocation
- ZTP client, PON manager, walled garden captive portal
- CLSet client for CRDT state synchronization
- Prometheus metrics integration

### v0.0.1 - POC Foundation (2025-12-16)
**What we shipped:**
- Project structure and documentation
- Local dev environment (k3d + Tilt + Cilium)
- eBPF development toolchain
- Architecture documentation

---

## 🎯 Current Focus (v0.3.0 Development)

### Production Hardening & Performance
- [ ] Performance testing and optimization ([#XX to be created](https://github.com/codelaboratoryltd/bng/issues))
- [ ] eBPF ring buffer optimizations (see TODOs in `pkg/nat/manager.go`)
- [ ] Integration testing with real OLT hardware
- [ ] Benchmarking: 50k req/sec validation
- [ ] Latency measurement: P50/P95/P99 tracking

### Monitoring & Observability
- [ ] Deploy Prometheus ServiceMonitors for BNG ([#44 docs issue](https://github.com/codelaboratoryltd/bng-edge-infra/issues/44))
- [ ] Create Grafana dashboards for BNG metrics
- [ ] Add Prometheus alerting rules
- [ ] Implement log aggregation with Loki

### Bug Fixes & Security
- [ ] Fix HTTPAllocator thread-safety bug ([#71](https://github.com/codelaboratoryltd/bng/issues/71))
- [ ] Graceful shutdown for peer pool HTTP server ([#77](https://github.com/codelaboratoryltd/bng/issues/77))
- [ ] Remove secrets from CLI flags ([#72](https://github.com/codelaboratoryltd/bng/issues/72))
- [ ] Fix URL path injection vulnerability ([#69](https://github.com/codelaboratoryltd/bng/issues/69))
- [ ] Use `errors.Is()` for error comparisons ([#70](https://github.com/codelaboratoryltd/bng/issues/70))

### Testing Infrastructure
- [ ] Add unit tests for HTTPAllocator ([#75](https://github.com/codelaboratoryltd/bng/issues/75))
- [ ] Improve edge cases for pkg/ebpf/loader.go ([#80](https://github.com/codelaboratoryltd/bng/issues/80))
- [ ] Add tests for pkg/subscriber/manager.go ([#78](https://github.com/codelaboratoryltd/bng/issues/78))
- [ ] Add HA failover verification tests ([#39](https://github.com/codelaboratoryltd/bng-edge-infra/issues/39))
- [ ] Add BNG ↔ Nexus API integration tests ([#38](https://github.com/codelaboratoryltd/bng-edge-infra/issues/38))

### Documentation
- [ ] Create Prometheus metrics reference ([#44](https://github.com/codelaboratoryltd/bng-edge-infra/issues/44))
- [ ] Create configuration schema reference ([#43](https://github.com/codelaboratoryltd/bng-edge-infra/issues/43))
- [ ] Create troubleshooting guide ([#45](https://github.com/codelaboratoryltd/bng-edge-infra/issues/45))
- [ ] Update README demo status section ([#46](https://github.com/codelaboratoryltd/bng-edge-infra/issues/46))

---

## 📋 Next Milestones (v0.3.x → v1.0.0)

### v0.3.0 - Production Readiness
**Goal**: Stable, observable, performant BNG ready for pilot deployments

**Deliverables:**
- Performance validation at 50k req/sec
- Complete monitoring stack (Prometheus + Grafana + Alerts)
- All critical bugs fixed
- Security vulnerabilities addressed
- Integration tests automated in CI/CD

**Issues to complete:**
- All items under "Current Focus" above

### v0.4.0 - Scale & Reliability
**Goal**: Handle 100k+ subscribers, improved HA, operational tooling

**Potential features:**
- Horizontal scaling support
- Active-active HA with session sync
- Advanced QoS policies
- Enhanced DDoS protection
- Operational tooling and debug utilities

**Needs GitHub issues to be created**

### v1.0.0 - Production General Availability
**Goal**: Battle-tested BNG ready for wide production use

**Criteria:**
- 3+ months in production pilot
- 99.9% uptime demonstrated
- Complete operational runbooks
- Certified on major OLT hardware
- Performance validated at scale

---

## 🚀 Future Roadmap (Post v1.0)

These are high-level future directions, not committed features:

### Advanced Features
- **Machine Learning**: Intelligent pool allocation, anomaly detection
- **Advanced QoS**: Hierarchical QoS, application-aware shaping
- **5G Integration**: 5G core network integration (5GC BNG)
- **Segment Routing**: SRv6 support for traffic engineering
- **Analytics**: Subscriber behavior analytics and insights

### Multi-Tenancy & Cloud
- **Multi-tenancy**: Support for virtual BNG instances
- **Cloud Native**: Full Kubernetes operator with CRDs
- **Service Mesh**: Integration with Istio/Linkerd for advanced services
- **Edge Computing**: BNG as edge compute platform

### Ecosystem
- **Hardware Offload**: SmartNIC integration (Intel, Mellanox)
- **OSS Integration**: Integration with OpenStack, OpenDaylight
- **Standards**: Full compliance with MEF, BBF standards

---

## 📊 Development Metrics

**Current Test Coverage**: 45.9% (target: >60% for v1.0)
**Open Issues**: 13 bugs, 4 test coverage, 2 security
**Release Cadence**: ~1 week per minor version
**Contributors**: Core team + community

---

## 🏃‍♂️ How to Contribute

1. **Pick an open issue** from the lists above
2. **Check issue labels**: `good-first-issue`, `help-wanted`, `bug`
3. **Read contribution guidelines**: `CONTRIBUTING.md` (when created)
4. **Join discussions**: GitHub Discussions for architecture questions
5. **Submit PRs**: Follow conventional commits format

**Priority areas for contributors:**
- Test coverage improvements
- Bug fixes (good first issues)
- Documentation
- Performance optimizations

---

## 📚 References

- **Changelog**: [CHANGELOG.md](./CHANGELOG.md) for detailed version history
- **Architecture**: [docs/ebpf-dhcp-architecture.md](./docs/ebpf-dhcp-architecture.md)
- **Features**: [docs/FEATURES.md](./docs/FEATURES.md) for complete feature spec
- **GitHub Issues**: [codelaboratoryltd/bng/issues](https://github.com/codelaboratoryltd/bng/issues)
- **Deployment**: [bng-edge-infra repository](https://github.com/codelaboratoryltd/bng-edge-infra)

---

**Last Updated**: 2026-01-26
**Roadmap Owner**: @mgazza
**Status**: Active development - v0.2.0 in production hardening
