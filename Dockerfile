# BNG Application Dockerfile
# Multi-stage build: eBPF compilation + Go build

# Stage 1: Build eBPF programs
FROM ubuntu:22.04 AS ebpf-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang-14 \
    llvm-14 \
    libbpf-dev \
    linux-headers-generic \
    gcc-multilib \
    make \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 100

WORKDIR /build/bpf

COPY bpf/ .

RUN make clean && make

# Stage 2: Build Go application
FROM golang:1.25-alpine AS go-builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN --mount=type=ssh go mod download

# Copy source code
COPY cmd/ cmd/
COPY pkg/ pkg/

# Copy compiled eBPF programs from stage 1
COPY --from=ebpf-builder /build/bpf/*.bpf.o bpf/

# Build Go binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o /bng \
    ./cmd/bng

# Stage 2b: Build BPF kernel verifier binary
FROM go-builder AS verify

# go:embed paths are relative to the source file, so place .bpf.o files
# alongside the verify-bpf command source.
RUN mkdir -p cmd/verify-bpf/bpf && cp bpf/*.bpf.o cmd/verify-bpf/bpf/

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /verify-bpf \
    ./cmd/verify-bpf

# Stage 3: Runtime image
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    iproute2

# Create non-root user (but BNG needs CAP_BPF)
RUN addgroup -g 1000 bng && \
    adduser -D -u 1000 -G bng bng

WORKDIR /app

# Copy binary and eBPF programs
COPY --from=go-builder /bng /app/bng
COPY --from=ebpf-builder /build/bpf/*.bpf.o /app/bpf/

# BNG runs as root (needs CAP_BPF, CAP_NET_ADMIN)
# Kubernetes securityContext will grant capabilities

ENTRYPOINT ["/app/bng"]
CMD ["run"]
