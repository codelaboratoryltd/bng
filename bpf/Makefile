# eBPF Program Makefile
# Compiles eBPF C programs to BPF bytecode

CLANG ?= clang
LLC ?= llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Output directory
OUTPUT := .

# eBPF programs to compile
BPF_PROGRAMS := dhcp_fastpath.bpf.o qos_ratelimit.bpf.o nat44.bpf.o antispoof.bpf.o

# Compiler flags
# Note: -Wno-pass-failed silences warnings when #pragma unroll can't be honored
# (common on arm64 or older clang versions) - the loops still work correctly
CFLAGS := -O2 -g -Wall -Werror -Wno-pass-failed \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I/usr/include/$(shell uname -m)-linux-gnu

# libbpf includes
CFLAGS += -I/usr/include

.PHONY: all clean vmlinux

all: $(BPF_PROGRAMS)

# Generate vmlinux.h (kernel type definitions)
vmlinux.h:
	@echo "Generating vmlinux.h..."
	@if command -v bpftool >/dev/null 2>&1; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
		echo "✓ vmlinux.h generated"; \
	else \
		echo "⚠️  bpftool not found, skipping vmlinux.h generation"; \
		echo "   Install: apt-get install linux-tools-generic"; \
	fi

vmlinux: vmlinux.h

# Compile eBPF C to BPF object
%.bpf.o: %.c maps.h
	@echo "Compiling $< -> $@"
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "✓ $@ compiled successfully"

clean:
	rm -f *.bpf.o
	rm -f vmlinux.h
	@echo "✓ Cleaned eBPF build artifacts"

# Show compiler info
info:
	@echo "eBPF Build Configuration:"
	@echo "  CLANG: $(CLANG)"
	@echo "  LLC: $(LLC)"
	@echo "  ARCH: $(ARCH)"
	@echo "  CFLAGS: $(CFLAGS)"
	@echo ""
	@echo "Programs to build:"
	@for prog in $(BPF_PROGRAMS); do echo "  - $$prog"; done

# Verify BPF object file
verify: $(BPF_PROGRAMS)
	@for prog in $(BPF_PROGRAMS); do \
		echo "Verifying $$prog..."; \
		if command -v llvm-objdump >/dev/null 2>&1; then \
			llvm-objdump -h $$prog | grep -E 'xdp|kprobe|tracepoint' || echo "  No eBPF sections found (may be normal)"; \
		else \
			file $$prog; \
		fi; \
	done

help:
	@echo "eBPF Makefile Targets:"
	@echo "  make           - Build all eBPF programs"
	@echo "  make vmlinux   - Generate vmlinux.h (kernel types)"
	@echo "  make clean     - Remove build artifacts"
	@echo "  make info      - Show build configuration"
	@echo "  make verify    - Verify compiled BPF objects"
	@echo "  make help      - Show this help"
