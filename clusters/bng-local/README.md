# BNG Local Development Cluster

k3d-based local Kubernetes cluster with Cilium CNI for BNG development.

## Cluster Configuration

- **Cluster name**: `k3d-bng`
- **CNI**: Cilium (Flannel disabled)
- **Nodes**: 1 server, 2 agents
- **Registry**: `localhost:5555` (k3d-bng-registry)
- **k3s version**: v1.28.5

## Port Mappings

| Service | Host Port | Container Port | Protocol |
|---------|-----------|----------------|----------|
| HTTP | 80 | 80 | TCP |
| HTTPS | 443 | 443 | TCP |
| DHCP Server | 6767 | 67 | UDP |
| DHCP Client | 6768 | 68 | UDP |
| Hubble UI | 12000 | 80 | TCP (via Tilt) |
| Prometheus | 9090 | 9090 | TCP (via Tilt) |
| Grafana | 3000 | 3000 | TCP (via Tilt) |
| Tilt UI | 10350 | 10350 | TCP |

## Quick Start

### Prerequisites

- Docker Desktop or Podman
- k3d (v5.6.0+)
- kubectl
- Tilt (v0.33.0+)
- helmfile
- Cilium CLI (optional, for debugging)

### Install Prerequisites (macOS)

```bash
brew install k3d kubectl tilt-dev/tap/tilt helmfile

# Optional: Cilium CLI
brew install cilium-cli
```

### Start Development Environment

```bash
# From repository root
tilt up --context k3d-bng
```

This will:
1. Create k3d cluster with Cilium CNI
2. Install Cilium, Hubble, Prometheus, Grafana
3. Apply BNG components (when implemented)
4. Open Tilt UI at http://localhost:10350

### Verify Cluster

```bash
# Check nodes
kubectl get nodes

# Check Cilium
cilium status

# Check all pods
kubectl get pods -A
```

### Access Services

- **Tilt UI**: http://localhost:10350
- **Hubble UI**: http://localhost:12000
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/admin)

### Hubble CLI Examples

```bash
# Watch all network flows
hubble observe

# Watch DHCP traffic
hubble observe --protocol dhcp

# Watch from specific pod
hubble observe --from-pod bng

# Watch XDP verdicts
hubble observe --verdict XDP_TX
```

## Cluster Management

### Stop Development Environment

```bash
# Graceful shutdown (preserves cluster)
tilt down

# Delete cluster completely
k3d cluster delete bng
```

### Restart Cluster

```bash
k3d cluster start bng
tilt up --context k3d-bng
```

### Rebuild from Scratch

```bash
k3d cluster delete bng
tilt up --context k3d-bng
```

## Troubleshooting

### Cilium Not Installing

Check that Flannel is disabled:
```bash
kubectl get pods -n kube-system | grep flannel
# Should be empty
```

Manually install Cilium:
```bash
cilium install --context k3d-bng
cilium status
```

### Local Registry Not Working

Check registry is running:
```bash
docker ps | grep k3d-bng-registry
```

Test registry:
```bash
curl http://localhost:5555/v2/_catalog
```

### Pods Stuck in Pending

Check node resources:
```bash
kubectl describe nodes
kubectl top nodes  # Requires metrics-server
```

Check pod events:
```bash
kubectl describe pod <pod-name>
```

### Can't Connect to Cluster

```bash
# Update kubeconfig
k3d kubeconfig merge bng --kubeconfig-switch-context

# Verify context
kubectl config current-context
# Should show: k3d-bng
```

## Cilium Configuration

Cilium is configured with:
- **Hubble**: Network observability enabled
- **kube-proxy replacement**: eBPF-based (no iptables)
- **Bandwidth Manager**: Enabled for QoS
- **BPF Masquerading**: Enabled for NAT
- **Prometheus metrics**: Enabled

See `charts/helmfile.yaml` for full configuration.

## Development Workflow

### Phase 1: Infrastructure Setup ✓

- [x] k3d cluster with Cilium
- [x] Helmfile for chart management
- [x] Tilt for development orchestration
- [x] Observability stack (Hubble, Prometheus, Grafana)

### Phase 2: eBPF Development (Next)

- [ ] eBPF build environment (Dockerfile.ebpf-builder)
- [ ] eBPF program skeleton (bpf/dhcp_fastpath.c)
- [ ] BNG Go application (cmd/bng/)
- [ ] Docker build integration with Tilt

### Phase 3: DHCP POC

- [ ] DHCP fast path implementation
- [ ] DHCP slow path implementation
- [ ] Testing with real DHCP client

## Notes

- **Cluster name changed**: Uses `bng` instead of `tilt` to avoid conflicts with other projects
- **Registry port**: 5555 (different from predbat-saas-infra)
- **DHCP ports**: Mapped to 6767/6768 on host (not standard 67/68 to avoid conflicts)
- **No Traefik**: Disabled, may install via Helm later if needed
- **No ServiceLB**: Cilium provides LoadBalancer support

## References

- k3d documentation: https://k3d.io
- Cilium documentation: https://docs.cilium.io
- Hubble documentation: https://docs.cilium.io/en/stable/gettingstarted/hubble/
- Tilt documentation: https://docs.tilt.dev
