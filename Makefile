.PHONY: help clean test lint build build-ebpf build-docker tidy demo

# Default target
help:
	@echo "BNG Makefile"
	@echo ""
	@echo "Build & Test:"
	@echo "  make build             - Build BNG binary (includes eBPF)"
	@echo "  make build-ebpf        - Build eBPF programs only"
	@echo "  make build-docker      - Build BNG Docker image"
	@echo "  make test              - Run Go tests"
	@echo "  make lint              - Run linters"
	@echo "  make tidy              - Tidy Go modules"
	@echo ""
	@echo "Demo:"
	@echo "  make demo              - Run demo with 10 subscribers"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean             - Remove build artifacts"
	@echo ""
	@echo "For local development with k3d/Tilt, use bng-edge-infra repo."
	@echo ""

# -----------------------------------------------------------------------------
# Build & Test
# -----------------------------------------------------------------------------

build-ebpf:
	@echo "Building eBPF programs..."
	cd bpf && $(MAKE)

build: build-ebpf
	@echo "Building BNG binary..."
	go build -o bin/bng ./cmd/bng
	@echo "Binary built: bin/bng"

build-docker:
	@echo "Building BNG Docker image..."
	docker build -t ghcr.io/codelaboratoryltd/bng:latest .
	@echo "Docker image built"

test:
	@echo "Running Go tests..."
	go test ./... -v

lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, skipping"; \
		echo "Install: brew install golangci-lint"; \
	fi

tidy:
	@echo "Tidying Go modules..."
	go mod tidy
	@echo "Go modules tidied"

# -----------------------------------------------------------------------------
# Demo
# -----------------------------------------------------------------------------

demo: build
	@echo "Running BNG demo..."
	./bin/bng demo --subscribers=10 --duration=30s

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------

clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -rf bpf/*.o
	@echo "Cleaned"
