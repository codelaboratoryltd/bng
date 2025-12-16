# BNG Project TODO

Development task list for eBPF-accelerated Broadband Network Gateway.

---

## Phase 0: Project Setup ✅

- [x] Create project structure
- [x] Write architecture document
- [x] Initialize git repository
- [ ] Create GitHub repository
- [ ] Set up project documentation

---

## Phase 1: Local Development Environment (Week 1-2)

### k3d Cluster Setup

- [ ] Create k3d config for Cilium CNI
  - [ ] Disable default Flannel CNI (`--flannel-backend=none`)
  - [ ] Disable default kube-proxy (`--disable=traefik`)
  - [ ] Configure port mappings (80, 443, DHCP ports)
  - [ ] Set up local registry for image builds
- [ ] Test k3d cluster creation
- [ ] Verify Cilium installation works with k3d

### Helmfile + Hydrate Setup

- [ ] Create `charts/` directory structure
- [ ] Create `charts/helmfile.yaml` with base charts:
  - [ ] Cilium (CNI)
  - [ ] Hubble (observability)
  - [ ] Prometheus (metrics)
  - [ ] Grafana (dashboards)
- [ ] Create `charts/hydrate.sh` script (adapt from predbat-saas-infra)
- [ ] Test helmfile template generation

### Kustomize Structure

- [ ] Create `clusters/local-tilt/` directory
- [ ] Create base kustomization.yaml
- [ ] Create `components/` directory for BNG components
- [ ] Test kustomize build

### Tiltfile

- [ ] Create Tiltfile with:
  - [ ] k3d cluster creation (via local_resource)
  - [ ] Cilium installation trigger
  - [ ] k8s_yaml for kustomize manifests
  - [ ] Port forwarding for services
  - [ ] Live reload for development
- [ ] Test `tilt up` workflow
- [ ] Verify Hubble UI accessible

---

## Phase 2: eBPF Development Environment (Week 2-3)

### eBPF Toolchain Setup

- [ ] Create Dockerfile for eBPF build environment:
  - [ ] clang/LLVM for eBPF compilation
  - [ ] libbpf-dev
  - [ ] bpftool
  - [ ] linux-headers
- [ ] Set up `bpf/` directory for eBPF programs
- [ ] Create Makefile for eBPF compilation
- [ ] Test eBPF program compilation

### Go Development Setup

- [ ] Create `cmd/bng/` for main BNG binary
- [ ] Create `pkg/` for Go packages:
  - [ ] `pkg/ebpf/` - eBPF map management
  - [ ] `pkg/dhcp/` - DHCP protocol handling
  - [ ] `pkg/subscriber/` - Subscriber management
- [ ] Set up go.mod with dependencies:
  - [ ] github.com/cilium/ebpf
  - [ ] github.com/insomniacslk/dhcp
  - [ ] github.com/prometheus/client_golang
- [ ] Create Dockerfile for BNG application

### Docker Build Integration

- [ ] Add docker_build to Tiltfile for BNG image
- [ ] Set up live_update for Go development
- [ ] Test hot reload workflow

---

## Phase 3: DHCP Fast Path POC (Week 3-5)

### eBPF Program: DHCP Parser

- [ ] Write XDP program skeleton (`bpf/dhcp_fastpath.c`)
- [ ] Implement packet parsing:
  - [ ] Ethernet header parsing
  - [ ] IP header parsing
  - [ ] UDP header parsing
  - [ ] DHCP packet validation
- [ ] Add eBPF verifier-safe bounds checking
- [ ] Test with bpftool

### eBPF Maps

- [ ] Define subscriber_pools map (MAC → pool assignment)
- [ ] Define ip_pools map (pool_id → pool metadata)
- [ ] Define active_leases map (IP → lease info)
- [ ] Implement map pinning for persistence
- [ ] Test map operations from userspace

### DHCP Reply Generation (eBPF)

- [ ] Implement DHCP OFFER generation in kernel
- [ ] Implement DHCP ACK generation in kernel
- [ ] Add DHCP options encoding:
  - [ ] Subnet mask
  - [ ] Router (gateway)
  - [ ] DNS servers
  - [ ] Lease time
- [ ] Packet checksum calculation
- [ ] MAC/IP address swapping for reply
- [ ] Test with real DHCP client

### Go Userspace Integration

- [ ] Load eBPF program from Go (cilium/ebpf)
- [ ] Attach XDP program to network interface
- [ ] Implement eBPF map CRUD operations
- [ ] Create DHCP slow path handler
- [ ] Implement IP pool management
- [ ] Add metrics collection (Prometheus)

### Testing

- [ ] Unit tests for Go code
- [ ] Integration test with real DHCP client
- [ ] Load testing (target: 10k+ req/sec)
- [ ] Verify fast path vs slow path behavior

---

## Phase 4: Stub State Management (Week 5-6)

**Note:** Neelix/Brushtail integration deferred - use simple stubs for POC

### In-Memory State Store

- [ ] Create `pkg/state/` package
- [ ] Implement simple in-memory subscriber database
- [ ] Add lease expiry tracking
- [ ] Implement pool allocation logic
- [ ] Add state persistence (optional: BoltDB/SQLite)

### Pool Management

- [ ] Define IP pool configuration (YAML)
- [ ] Implement pool CRUD operations
- [ ] Add client classification logic (residential/business)
- [ ] Implement IP allocation/deallocation

### Integration with eBPF Cache

- [ ] Sync state store → eBPF maps on allocation
- [ ] Implement cache invalidation on lease expiry
- [ ] Add cache warming on startup
- [ ] Test state consistency

---

## Phase 5: Observability & Metrics (Week 6-7)

### Prometheus Metrics

- [ ] DHCP request counters (fast path, slow path)
- [ ] Latency histograms (P50, P95, P99)
- [ ] Cache hit rate
- [ ] Active leases count
- [ ] Pool utilization
- [ ] Error counters

### Grafana Dashboard

- [ ] Create BNG overview dashboard
- [ ] DHCP performance metrics
- [ ] Pool utilization graphs
- [ ] Cache performance
- [ ] Error rate tracking

### Hubble Integration

- [ ] Test Hubble observability for DHCP traffic
- [ ] Create Hubble CLI examples
- [ ] Document XDP verdict tracking (XDP_TX vs XDP_PASS)

### Logging

- [ ] Structured logging (JSON)
- [ ] Log levels (debug, info, warn, error)
- [ ] Request tracing
- [ ] Audit log for allocations

---

## Phase 6: BNG Core Features (Week 7-10)

**Note:** Beyond DHCP - basic BNG functionality

### Session Management

- [ ] Implement subscriber session tracking
- [ ] Add session state machine
- [ ] Session timeout handling
- [ ] Graceful session termination

### Basic QoS (Rate Limiting)

- [ ] Implement per-subscriber rate limiting (eBPF)
- [ ] Token bucket algorithm
- [ ] Upload/download limits
- [ ] QoS policy configuration

### RADIUS Integration (Stub)

- [ ] Create RADIUS client stub
- [ ] Authentication request/response
- [ ] Accounting start/interim/stop
- [ ] Integration with DHCP flow

### NAT44 (Basic CGNAT)

- [ ] Implement port allocation
- [ ] NAT session tracking
- [ ] Port exhaustion handling
- [ ] NAT pool management

---

## Phase 7: Production Readiness (Week 10-12)

### Configuration Management

- [ ] YAML configuration file
- [ ] Environment variable overrides
- [ ] Configuration validation
- [ ] Hot reload support

### Health Checks

- [ ] Liveness probe endpoint
- [ ] Readiness probe endpoint
- [ ] eBPF program health check
- [ ] Interface status monitoring

### Security

- [ ] Drop capabilities (if not needed)
- [ ] Read-only root filesystem
- [ ] Resource limits (CPU, memory)
- [ ] Network policy enforcement

### Documentation

- [ ] Deployment guide
- [ ] Operations runbook
- [ ] Troubleshooting guide
- [ ] API documentation

### Performance Tuning

- [ ] CPU affinity optimization
- [ ] Memory allocation tuning
- [ ] eBPF map size optimization
- [ ] XDP performance profiling

---

## Phase 8: Future Enhancements (Post-POC)

### PPPoE Support

- [ ] Research PPPoE protocol requirements
- [ ] Evaluate VPP vs eBPF for PPPoE
- [ ] Design PPPoE session management
- [ ] Implement PPPoE in XDP

### IPoE Support

- [ ] DHCP-based subscriber authentication
- [ ] Integration with RADIUS
- [ ] MAC-based session tracking

### Neelix Integration (CRDT)

- [ ] Replace stub state store with Neelix client
- [ ] Implement CRDT conflict resolution
- [ ] Multi-region state sync
- [ ] Handle network partitions

### Brushtail Integration

- [ ] Integrate existing Brushtail DHCP server
- [ ] Use eBPF as fast path only
- [ ] Delegate complex logic to Brushtail

### Advanced Features

- [ ] DHCPv6 support
- [ ] IPv6 routing
- [ ] DDoS protection (XDP rate limiting)
- [ ] Machine learning-based pool selection

---

## Infrastructure Tasks

### CI/CD

- [ ] GitHub Actions workflow for:
  - [ ] Go tests
  - [ ] eBPF compilation
  - [ ] Docker image build
  - [ ] Push to GHCR
- [ ] Automated testing on PR
- [ ] Release automation

### Container Registry

- [ ] Push images to GHCR:
  - [ ] ghcr.io/codelaboratoryltd/bng
  - [ ] ghcr.io/codelaboratoryltd/bng-ebpf-builder

---

## Documentation Tasks

- [ ] Write CONTRIBUTING.md
- [ ] Write DEVELOPMENT.md
- [ ] Create architecture diagrams (draw.io)
- [ ] Write blog post series:
  - [ ] Part 1: eBPF for DHCP acceleration
  - [ ] Part 2: VPP vs eBPF decision
  - [ ] Part 3: Building cloud-native BNG
- [ ] Create demo video
- [ ] Update README with getting started guide

---

## Current Focus

**PRIORITY: Phase 1 - Local Development Environment**

Next actions:
1. Create k3d config with Cilium support
2. Set up helmfile for Cilium + Hubble
3. Create basic Tiltfile
4. Test `tilt up` workflow

---

**Status**: Design phase complete, starting implementation
**Last Updated**: 16 Dec 2025
