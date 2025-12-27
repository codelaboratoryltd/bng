# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is an eBPF-accelerated Broadband Network Gateway (BNG) implementation designed for **bare metal deployment on OLT hardware** at ISP edge locations. Each OLT-BNG serves 1,000-2,000 subscribers with 10-40 Gbps uplink capacity.

**Status**: Design phase, implementation starting

**Key Innovation**: Using eBPF/XDP for DHCP fast path instead of traditional userspace processing or VPP, achieving 10x performance improvement. The BNG runs directly on OLT hardware as a systemd service, eliminating dedicated BNG appliances.

## Architecture Overview

```
PRODUCTION (Bare Metal):
┌─────────────────────────────────────────────────────────────┐
│  Central Coordination (Kubernetes)                          │
│  ├── Nexus Server (CLSet CRDT, bootstrap API)              │
│  ├── Prometheus/Grafana (monitoring)                        │
│  └── Image Registry (OLT-BNG updates)                       │
└─────────────────────────────────────────────────────────────┘
        │ Control Plane Only (no subscriber traffic)
        ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ OLT-BNG Site 1  │  │ OLT-BNG Site 2  │  │ OLT-BNG Site N  │
│ (Bare Metal)    │  │ (Bare Metal)    │  │ (Bare Metal)    │
│ systemd service │  │ systemd service │  │ systemd service │
└─────────────────┘  └─────────────────┘  └─────────────────┘
        │                    │                    │
   Subscriber Traffic   Subscriber Traffic   Subscriber Traffic
   (stays local)        (stays local)        (stays local)

DEVELOPMENT (Kubernetes/k3d):
- k3d cluster with Cilium for testing
- Tilt for hot reload
- NOT production architecture
```

## Project Goals

1. **DHCP Acceleration**: 50,000+ req/sec (vs 5,000 baseline) with sub-millisecond latency
2. **Distributed Edge**: No central BNG - subscriber traffic stays local to OLT
3. **Edge-Optimized**: Designed for 10-40 Gbps edge scale (not 100+ Gbps core)
4. **Zero-Touch Provisioning**: OLTs self-register and pull config from central Nexus
5. **Offline-First**: Edge sites continue operating during network partitions

## Architecture Approach

### eBPF vs VPP Decision

**We chose eBPF/XDP over VPP for edge deployment** because:
- **Performance sufficient**: 10-40 Gbps covers edge scale (VPP's 100+ Gbps is overkill)
- **Simpler operations**: No DPDK, hugepages, or NIC binding (VPP requires all these)
- **Standard Linux**: Runs as systemd service on any modern Linux kernel
- **Better debugging**: Standard Linux tools (tcpdump, bpftool, perf)

See `docs/ebpf-dhcp-architecture.md` for full VPP vs eBPF comparison.

### Two-Tier Design: Fast Path + Slow Path

**Important**: IP allocation happens at RADIUS time (hashring-based), NOT during DHCP. DHCP is read-only.

```
RADIUS Authentication (happens first)
    ↓
  • Subscriber authenticates
  • Nexus allocates IP from hashring (deterministic, no conflicts)
  • IP stored in subscriber record
    ↓
DHCP Request (IP already allocated)
    ↓
eBPF/XDP (Kernel) - FAST PATH (95%+ of traffic)
  • Lookup MAC in eBPF map
  • Return pre-allocated IP
  • Reply in kernel (~10 μs latency)
  • NO USERSPACE!
    ↓ (cache miss - rare)
Go Userspace - SLOW PATH (<5% of traffic)
  • Query Nexus for subscriber's pre-allocated IP
  • NO allocation logic - just a read
  • Update eBPF cache for future requests
```

**Performance Target**: 50,000+ DHCP req/sec, <100μs P99 latency (fast path)

## Technology Stack

### Production (OLT-BNG - Bare Metal)

- **eBPF/XDP**: Kernel packet processing (bpf/*.c)
- **Go**: Userspace control plane (cmd/, pkg/)
- **FRR**: BGP/routing daemon
- **systemd**: Service management
- **Prometheus**: Metrics (scraped by central)

### Production (Central Coordination - Kubernetes)

- **Nexus Server**: CLSet CRDT, bootstrap API, config distribution
- **Prometheus/Grafana**: Central monitoring
- **Image Registry**: OLT-BNG binary/image distribution

### Development Tools (Local Testing)

- **Tilt**: Local development orchestration
- **k3d**: Local Kubernetes cluster for testing
- **Cilium/Hubble**: Network observability in dev
- **helmfile**: Helm chart management
- **Kustomize**: Kubernetes manifest overlays

### Dependencies (Go)

- `github.com/cilium/ebpf` - eBPF program loading and map management
- `github.com/insomniacslk/dhcp` - DHCP protocol library
- `github.com/prometheus/client_golang` - Metrics
- `github.com/spf13/cobra` - CLI framework
- `github.com/spf13/viper` - Configuration management

### Dependencies (eBPF)

- `clang/LLVM` - eBPF compilation
- `libbpf-dev` - eBPF library
- `bpftool` - eBPF debugging
- `linux-headers` - Kernel headers for compilation

## Project Structure

```
bng/
├── README.md                     # Project overview
├── CLAUDE.md                     # This file
├── docs/
│   ├── TODO.md                   # Phase-by-phase task list
│   ├── FEATURES.md               # Comprehensive feature specification
│   ├── ARCHITECTURE.md           # System architecture
│   └── ebpf-dhcp-architecture.md # Full architecture document
│
├── cmd/
│   └── bng/                      # Main BNG binary
│       └── main.go
│
├── pkg/
│   ├── ebpf/                     # eBPF map management
│   ├── dhcp/                     # DHCP protocol handling
│   ├── subscriber/               # Subscriber/session management
│   ├── state/                    # State store (stub for now)
│   └── metrics/                  # Prometheus metrics
│
├── bpf/
│   ├── dhcp_fastpath.c           # XDP program for DHCP
│   ├── maps.h                    # eBPF map definitions
│   └── Makefile                  # eBPF compilation
│
├── charts/
│   ├── helmfile.yaml             # Helm chart definitions
│   └── hydrate.sh                # Template generation script
│
├── clusters/
│   └── local-tilt/               # Local k3d cluster config
│       ├── k3d-config.yaml
│       └── kustomization.yaml
│
├── components/                   # Kustomize components
│   └── bng/                      # BNG deployment manifests
│
├── Tiltfile                      # Local development orchestration
├── Dockerfile                    # BNG application image
└── Dockerfile.ebpf-builder       # eBPF build environment
```

## Development Workflow

### Initial Setup (Not Yet Implemented)

```bash
# 1. Create k3d cluster with Cilium CNI
k3d cluster create -c clusters/local-tilt/k3d-config.yaml

# 2. Install Cilium + Hubble via helmfile
cd charts
./hydrate.sh
cd ..

# 3. Apply manifests
kubectl apply -k clusters/local-tilt

# 4. Start Tilt
tilt up

# 5. Access Hubble UI
http://localhost:10350  # Tilt dashboard
http://localhost:12000  # Hubble UI (when configured)
```

### eBPF Development

```bash
# Compile eBPF programs
cd bpf
make

# Load program manually (for testing)
sudo bpftool prog load dhcp_fastpath.o /sys/fs/bpf/dhcp_fastpath

# Attach to interface
sudo bpftool net attach xdp pinned /sys/fs/bpf/dhcp_fastpath dev eth1

# Inspect eBPF maps
sudo bpftool map show
sudo bpftool map dump name subscriber_pools
```

### Go Development

```bash
# Build BNG binary
go build -o bin/bng ./cmd/bng

# Run tests
go test ./...

# Run with hot reload (via Tilt)
tilt up
```

## Key Files and Their Purpose

### Architecture Documentation

- **`docs/ebpf-dhcp-architecture.md`**: Complete technical design
  - Problem statement and current challenges
  - Two-tier fast path/slow path architecture
  - VPP vs eBPF decision analysis with edge performance calculations
  - eBPF implementation details (maps, XDP program)
  - Integration with CRDT state management (Nexus - future)
  - Performance analysis and cost savings
  - Implementation roadmap (12 weeks, 5 phases)
  - Full code examples (eBPF C + Go integration)
  - Networking acronym glossary

### Planning Documents

- **`docs/TODO.md`**: Phase-by-phase development plan
  - Phase 0: Project setup ✅
  - Phase 1: Local dev environment (k3d, Cilium, Tilt) ← **CURRENT FOCUS**
  - Phase 2: eBPF development toolchain
  - Phase 3: DHCP fast path POC
  - Phase 4: Stub state management
  - Phase 5: Observability and metrics
  - Phase 6: BNG core features (QoS, NAT, RADIUS stubs)
  - Phase 7: Production readiness
  - Phase 8: Future enhancements (PPPoE, real Nexus integration)

- **`docs/FEATURES.md`**: Comprehensive BNG feature specification
  - 12 core BNG functions with detailed requirements
  - Performance targets for each feature
  - Configuration examples (YAML schemas)
  - Agent task template for delegating work
  - Covers: DHCP, RADIUS, QoS, NAT44, PPPoE/IPoE, routing, logging, monitoring

## Current Phase: Phase 1 - Local Development Environment

**PRIORITY TASKS** (from docs/TODO.md):

1. **Create k3d config for Cilium CNI**
   - Disable default Flannel: `--flannel-backend=none`
   - Disable default kube-proxy: `--disable=traefik`
   - Configure port mappings (80, 443, DHCP ports 67/68)
   - Set up local registry

2. **Set up helmfile for Cilium + Hubble**
   - Create `charts/helmfile.yaml` with Cilium chart
   - Add Hubble for observability
   - Add Prometheus + Grafana
   - Create `charts/hydrate.sh` (adapt from predbat-saas-infra)

3. **Create Tiltfile**
   - k3d cluster creation (local_resource)
   - Cilium installation trigger
   - k8s_yaml for kustomize manifests
   - Port forwarding
   - Live reload for Go development

4. **Test `tilt up` workflow**
   - Verify cluster creation
   - Verify Cilium installation
   - Verify Hubble UI accessible

**Reference Implementation**: `/Users/markgascoyne/go/src/github.com/codelaboratoryltd/predbat-saas-infra`
- k3d config: `clusters/local-tilt/k3d-config-registry.template`
- Helmfile: `charts/helmfile.yaml`
- Hydrate script: `charts/hydrate.sh`
- Tiltfile: `Tiltfile`

## Important Notes for k3d + Cilium

**k3d Requires Special Config for Cilium**:

k3d uses Flannel CNI by default. To use Cilium:

```yaml
apiVersion: k3d.io/v1alpha5
kind: Simple
metadata:
  name: tilt
servers: 1
agents: 1
options:
  k3s:
    extraArgs:
      - arg: --flannel-backend=none
        nodeFilters:
          - server:*
      - arg: --disable=traefik
        nodeFilters:
          - server:*
```

**Then install Cilium via helmfile** after cluster creation.

## Development Environment (k3d/Kubernetes)

**Note**: This section is for LOCAL DEVELOPMENT only. Production OLT-BNG runs on bare metal Linux.

### eBPF Program Deployment (Dev)

For testing eBPF in k3d, pods require:
- **Host network access**: To attach XDP to NICs
- **CAP_BPF + CAP_NET_ADMIN**: Security context
- **Pinned BPF filesystem**: `/sys/fs/bpf` mounted

Example pod spec (dev only):
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bng
spec:
  hostNetwork: true
  containers:
  - name: bng
    image: ghcr.io/codelaboratoryltd/bng:latest
    securityContext:
      capabilities:
        add: [BPF, NET_ADMIN, SYS_RESOURCE]
    volumeMounts:
    - name: bpffs
      mountPath: /sys/fs/bpf
  volumes:
  - name: bpffs
    hostPath:
      path: /sys/fs/bpf
```

### DHCP Port Requirements (Dev)

In k3d, expose DHCP ports:
```yaml
ports:
  - port: 6767:67/udp  # Host 6767 → Container 67
  - port: 6768:68/udp
```

### Production Deployment

In production, OLT-BNG runs as a systemd service:
```bash
# /etc/systemd/system/olt-bng.service
[Unit]
Description=OLT-BNG Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/olt-bng run --config /etc/olt-bng/config.yaml
Restart=always

[Install]
WantedBy=multi-user.target
```

## State Management Strategy

### IP Allocation Model

**IP allocation happens at RADIUS time**, not DHCP time:
1. Subscriber authenticates via RADIUS
2. Nexus allocates IP from hashring (deterministic, no conflicts)
3. DHCP is just a read operation (lookup pre-allocated IP)
4. Leases are essentially static after initial allocation

### POC Phase (Current)

**Simple in-memory state store** (`pkg/nexus/`):
- In-memory subscriber database with CLSet-ready interface
- Local cache for offline operation
- Focus on proving eBPF fast path works

### Production (Post-POC)

**CLSet CRDT Backend**:
- Full CLSet integration for distributed state
- Multi-region state synchronization
- Hashring-based IP allocation (no conflicts)
- Session roaming support

See `docs/ebpf-dhcp-architecture.md` and `docs/ARCHITECTURE.md` for full details.

## Performance Targets and Metrics

### DHCP Performance

| Metric | Target | Measurement |
|--------|--------|-------------|
| Fast Path Throughput | 45,000 req/sec | eBPF counters |
| Slow Path Throughput | 5,000 req/sec | Go metrics |
| Total Throughput | 50,000 req/sec | Combined |
| Fast Path Latency | <100 μs | P99, eBPF histogram |
| Slow Path Latency | <10 ms | P99, Prometheus |
| Cache Hit Rate | >95% | Fast path / total |

### System Resources

| Metric | Target | Notes |
|--------|--------|-------|
| CPU Usage | <50% | At 50k req/sec |
| Memory Usage | <4 GB | eBPF maps + userspace |
| Active Leases | 100,000+ | eBPF map capacity |
| Concurrent Sessions | 100,000+ | Session tracking |

### Prometheus Metrics to Implement

```go
// DHCP metrics
dhcp_requests_total{path="fast|slow", result="success|error"}
dhcp_request_duration_seconds{path="fast|slow", quantile="0.5|0.95|0.99"}
dhcp_cache_hit_rate
dhcp_cache_entries_total

// Session metrics
bng_active_sessions_total
bng_session_duration_seconds

// Pool metrics
dhcp_pool_utilization_percent{pool_id}
dhcp_pool_available_ips{pool_id}

// System metrics
bng_ebpf_map_entries{map_name}
bng_ebpf_program_attached{program="dhcp_fastpath"}
```

## Testing Strategy

### Unit Tests

- Go package tests: `go test ./...`
- Mock eBPF maps for testing
- DHCP protocol parsing tests
- State store CRUD tests

### Integration Tests

- Real DHCP client (dhclient or similar)
- End-to-end DHCP flow (DISCOVER → OFFER → REQUEST → ACK)
- Lease renewal testing
- Cache invalidation testing

### Load Testing

- Tool: `dhcperf` or custom Go tool
- Target: 50,000 req/sec sustained
- Measure: Latency distribution, error rate, cache hit rate
- Run on local k3d cluster

### eBPF Testing

- BPF verifier validation
- XDP test mode (XDP_DRV vs XDP_SKB)
- Packet capture and analysis (tcpdump)
- bpftool for map inspection

## Observability

### Hubble CLI Examples

```bash
# Watch all DHCP traffic
hubble observe --protocol dhcp

# See fast path replies (XDP_TX verdict)
hubble observe --verdict XDP_TX

# See slow path handoff (XDP_PASS verdict)
hubble observe --verdict XDP_PASS

# Per-subscriber traffic
hubble observe --from-pod bng --to-ip 10.0.1.100
```

### Grafana Dashboards

**BNG Overview**:
- DHCP requests/sec (fast path, slow path, total)
- Latency graphs (P50, P95, P99)
- Cache hit rate over time
- Active sessions and leases
- Error rate

**Pool Utilization**:
- Per-pool utilization percentage
- Available IPs per pool
- Allocation rate
- Alerts on >80% utilization

**Performance**:
- CPU and memory usage
- eBPF map sizes
- Packet processing rate
- Drop counters

## Common Development Commands

```bash
# Build eBPF programs
make -C bpf

# Build Go binary
go build -o bin/bng ./cmd/bng

# Run tests
go test ./... -v

# Format code
go fmt ./...
gofmt -s -w .

# Lint (if golangci-lint installed)
golangci-lint run

# Start local environment
tilt up

# View Tilt logs
tilt logs -f bng

# Access Hubble UI
kubectl port-forward -n kube-system svc/hubble-ui 12000:80

# Check eBPF programs loaded
sudo bpftool prog show

# Dump eBPF map
sudo bpftool map dump name subscriber_pools | head -20

# Test DHCP allocation
sudo dhclient -v eth1
```

## Troubleshooting

### eBPF Program Won't Load

**Check kernel version**:
```bash
uname -r  # Need 5.10+ for XDP
```

**Check BPF filesystem mounted**:
```bash
mount | grep bpf
# Should see: bpffs on /sys/fs/bpf type bpf
```

**Verify with bpftool**:
```bash
sudo bpftool prog load bpf/dhcp_fastpath.o /sys/fs/bpf/test
# Check verifier output for errors
```

### Cilium Not Installing in k3d

**Verify Flannel disabled**:
```bash
kubectl get pods -n kube-system | grep flannel
# Should be empty
```

**Check k3s args**:
```bash
k3d cluster list
k3d cluster edit tilt  # Check --flannel-backend=none
```

**Install Cilium manually**:
```bash
helm repo add cilium https://helm.cilium.io/
helm install cilium cilium/cilium --namespace kube-system
```

### DHCP Not Working

**Check XDP program attached**:
```bash
sudo bpftool net show dev eth1
# Should see XDP program
```

**Check DHCP packets arriving**:
```bash
sudo tcpdump -i eth1 port 67 or port 68 -vv
```

**Check eBPF map populated**:
```bash
sudo bpftool map dump name subscriber_pools
# Should see MAC → IP mappings
```

**Check Hubble flow**:
```bash
hubble observe --protocol dhcp --last 10
```

## References and Resources

### eBPF Learning

- [Cilium eBPF Documentation](https://docs.cilium.io/en/latest/bpf/)
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [eBPF Go Library](https://github.com/cilium/ebpf)
- [Kernel Documentation](https://docs.kernel.org/bpf/)

### BNG and Networking

- [BNG Overview](https://www.juniper.net/documentation/us/en/software/junos/subscriber-mgmt/topics/concept/bng-overview.html)
- [DHCP RFC 2131](https://datatracker.ietf.org/doc/html/rfc2131)
- [RADIUS RFC 2865](https://datatracker.ietf.org/doc/html/rfc2865)
- [CGNAT RFC 6888](https://datatracker.ietf.org/doc/html/rfc6888)

### Related Projects

- [VPP (Vector Packet Processing)](https://fd.io/)
- [Brandon Spendlove's VPP BNG](https://www.linkedin.com/in/brandonspendlove/) - LinkedIn posts
- [Cilium](https://cilium.io/)
- [Hubble](https://github.com/cilium/hubble)

### Internal References

- Architecture doc: `docs/ebpf-dhcp-architecture.md`
- Task list: `docs/TODO.md`
- Feature spec: `docs/FEATURES.md`

## Project Context

### Why This Project Exists

This project was created to:
1. Explore eBPF/XDP for high-performance ISP infrastructure
2. Validate cloud-native BNG approach (vs traditional hardware appliances)
3. Compare eBPF vs VPP for edge deployment scenarios
4. Build portfolio project demonstrating deep technical expertise
5. Potentially use in production ISP deployments

### Target Audience

- ISPs deploying edge infrastructure
- Platform engineers interested in eBPF
- Network engineers evaluating BNG solutions
- Kubernetes operators running network workloads

### Success Criteria

**POC Success**:
- Achieve 50,000+ DHCP req/sec on commodity hardware
- Demonstrate <100μs fast path latency
- Prove eBPF approach viable for BNG
- Validate Kubernetes deployment model

**Production Readiness** (Future):
- Session persistence across restarts
- Multi-region state sync (Nexus integration)
- QoS and NAT working in production
- 99.9% uptime SLA

## Getting Help

### Documentation

1. Start with `README.md` for project overview
2. Read `docs/ebpf-dhcp-architecture.md` for technical deep dive
3. Check `docs/TODO.md` for current phase and tasks
4. Review `docs/FEATURES.md` for feature requirements

### Debugging

1. Check Tilt logs: `tilt logs -f bng`
2. Check Kubernetes events: `kubectl describe pod bng`
3. Check eBPF program: `sudo bpftool prog show`
4. Check Hubble flows: `hubble observe --protocol dhcp`
5. Check Prometheus metrics: `curl localhost:9090/metrics`

### External Help

- Cilium Slack: https://cilium.io/slack
- eBPF Discussions: https://github.com/iovisor/bcc/discussions
- r/networking: https://reddit.com/r/networking

---

**Author**: Mark Gascoyne
**Email**: [Contact via GitHub]
**Status**: Design phase, starting Phase 1 implementation
**Last Updated**: 16 Dec 2025
