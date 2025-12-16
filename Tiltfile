# BNG Tiltfile - Local Development with k3d + Cilium
#
# Usage:
#   tilt up --context k3d-bng
#
# This will:
#   1. Create k3d cluster with Cilium CNI (no Flannel)
#   2. Install Cilium, Hubble, Prometheus, Grafana via helmfile
#   3. Deploy BNG components (when implemented)
#   4. Enable live reload for Go development

print("""
-----------------------------------------------------------------
🚀 BNG - eBPF-Accelerated Broadband Network Gateway
   Local Development Environment
-----------------------------------------------------------------
""".strip())

# Only allow k3d-bng context
allow_k8s_contexts('k3d-bng')

# Enable secret support
secret_settings(True)

# Docker prune settings to avoid disk space issues
docker_prune_settings(
    disable=False,
    max_age_mins=120,    # Prune after 2 hours
    num_builds=5,        # Also prune after 5 builds
    interval_hrs=1,      # Check every hour
    keep_recent=2        # Always keep 2 most recent
)

# -----------------------------------------------------------------------------
# k3d Cluster Creation
# -----------------------------------------------------------------------------

local_resource(
    'k3d-cluster',
    cmd='k3d cluster create -c clusters/bng-local/k3d-config.yaml || true',
    deps=['clusters/bng-local/k3d-config.yaml'],
    labels=['infrastructure'],
)

# Wait for k3d cluster to be ready
local_resource(
    'k3d-wait',
    cmd='kubectl wait --for=condition=ready node --all --timeout=120s',
    resource_deps=['k3d-cluster'],
    labels=['infrastructure'],
)

# -----------------------------------------------------------------------------
# Helmfile - Generate Helm Charts
# -----------------------------------------------------------------------------

local_resource(
    'helmfile-hydrate',
    cmd='cd charts && ./hydrate.sh',
    deps=['charts/helmfile.yaml', 'charts/hydrate.sh'],
    resource_deps=['k3d-wait'],
    labels=['infrastructure'],
)

# -----------------------------------------------------------------------------
# Kubernetes Resources
# -----------------------------------------------------------------------------

# Apply all manifests via kustomize
k8s_yaml(kustomize('clusters/bng-local'))

# Wait for Cilium to be ready
k8s_resource(
    'cilium-operator',
    resource_deps=['helmfile-hydrate'],
    labels=['cilium'],
)

k8s_resource(
    new_name='cilium-agent',
    objects=['cilium:DaemonSet:kube-system'],
    resource_deps=['helmfile-hydrate'],
    labels=['cilium'],
)

# Hubble UI
k8s_resource(
    'hubble-ui',
    port_forwards='12000:80',
    resource_deps=['cilium-operator'],
    labels=['observability'],
)

k8s_resource(
    'hubble-relay',
    resource_deps=['cilium-operator'],
    labels=['observability'],
)

# Prometheus
k8s_resource(
    'prometheus-server',
    new_name='prometheus',
    port_forwards='9090:9090',
    resource_deps=['helmfile-hydrate'],
    labels=['observability'],
)

# Grafana
k8s_resource(
    'grafana',
    port_forwards='3000:3000',
    resource_deps=['prometheus'],
    labels=['observability'],
)

# -----------------------------------------------------------------------------
# BNG Application
# -----------------------------------------------------------------------------

# Build BNG Docker image with live reload
docker_build(
    'localhost:5555/bng',  # Push to local k3d registry
    '.',
    dockerfile='Dockerfile',
    # Note: Live reload disabled for now due to eBPF compilation complexity
    # Will enable in Phase 3 when we have full eBPF integration
)

# TODO Phase 3: Add BNG Kubernetes deployment
# - Create components/bng/deployment.yaml
# - Add to clusters/bng-local/kustomization.yaml
# - Uncomment k8s_resource below
#
# k8s_resource(
#     'bng',
#     port_forwards=['8080:8080', '9090:9090'],  # HTTP API, Prometheus metrics
#     resource_deps=['cilium-agent'],
#     labels=['bng'],
# )

# -----------------------------------------------------------------------------
# Helper Commands
# -----------------------------------------------------------------------------

print("""
✓ Tiltfile loaded successfully

Next steps:
  1. Run: tilt up
  2. Wait for all resources to be ready (green)
  3. Access services:
     - Tilt UI:    http://localhost:10350
     - Hubble UI:  http://localhost:12000
     - Prometheus: http://localhost:9090
     - Grafana:    http://localhost:3000 (admin/admin)

Useful commands:
  - View Hubble flows: hubble observe --protocol dhcp
  - Check Cilium:      cilium status
  - Logs:              tilt logs -f <resource-name>

To delete cluster:
  k3d cluster delete bng
""".strip())
