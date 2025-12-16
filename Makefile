.PHONY: help cluster-create cluster-delete cluster-start cluster-stop tilt-up tilt-down hydrate clean test lint build

# Default target
help:
	@echo "BNG Development Makefile"
	@echo ""
	@echo "Cluster Management:"
	@echo "  make cluster-create    - Create k3d cluster with Cilium"
	@echo "  make cluster-delete    - Delete k3d cluster"
	@echo "  make cluster-start     - Start existing cluster"
	@echo "  make cluster-stop      - Stop cluster (preserves state)"
	@echo "  make cluster-restart   - Restart cluster"
	@echo ""
	@echo "Development:"
	@echo "  make tilt-up           - Start Tilt development environment"
	@echo "  make tilt-down         - Stop Tilt (keeps cluster running)"
	@echo "  make hydrate           - Regenerate Helm templates"
	@echo ""
	@echo "Build & Test:"
	@echo "  make build             - Build BNG binary (TODO)"
	@echo "  make test              - Run Go tests (TODO)"
	@echo "  make lint              - Run linters (TODO)"
	@echo "  make build-ebpf        - Build eBPF programs (TODO)"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean             - Remove build artifacts"
	@echo ""

# -----------------------------------------------------------------------------
# Cluster Management
# -----------------------------------------------------------------------------

cluster-create:
	@echo "Creating k3d cluster 'bng'..."
	k3d cluster create -c clusters/bng-local/k3d-config.yaml

cluster-delete:
	@echo "Deleting k3d cluster 'bng'..."
	k3d cluster delete bng

cluster-start:
	@echo "Starting k3d cluster 'bng'..."
	k3d cluster start bng

cluster-stop:
	@echo "Stopping k3d cluster 'bng'..."
	k3d cluster stop bng

cluster-restart: cluster-stop cluster-start
	@echo "Cluster restarted"

# -----------------------------------------------------------------------------
# Development
# -----------------------------------------------------------------------------

tilt-up:
	@echo "Starting Tilt development environment..."
	@echo "This will create the cluster if it doesn't exist"
	tilt up --context k3d-bng

tilt-down:
	@echo "Stopping Tilt (cluster will remain running)..."
	tilt down

hydrate:
	@echo "Regenerating Helm templates via helmfile..."
	cd charts && ./hydrate.sh

# -----------------------------------------------------------------------------
# Build & Test (TODO - Phase 2)
# -----------------------------------------------------------------------------

build:
	@echo "TODO: Build BNG binary"
	# go build -o bin/bng ./cmd/bng

test:
	@echo "TODO: Run Go tests"
	# go test ./... -v

lint:
	@echo "TODO: Run linters"
	# golangci-lint run

build-ebpf:
	@echo "TODO: Build eBPF programs"
	# cd bpf && make

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------

clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -rf bpf/*.o
	rm -rf charts/cilium charts/prometheus charts/grafana
	@echo "✓ Cleaned"

# -----------------------------------------------------------------------------
# Convenience Targets
# -----------------------------------------------------------------------------

# Fresh start - delete everything and rebuild
fresh: cluster-delete tilt-up
	@echo "✓ Fresh environment created"

# Quick restart without deleting cluster
restart: tilt-down tilt-up
	@echo "✓ Development environment restarted"
