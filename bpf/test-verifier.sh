#!/bin/bash
# Test BPF verifier acceptance
# Run this on a Linux system with BPF support

set -e

echo "=== BPF Verifier Test ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (need CAP_BPF)"
    exit 1
fi

# Check if bpftool is available
if ! command -v bpftool &> /dev/null; then
    echo "Error: bpftool not found. Install with: apt-get install linux-tools-generic"
    exit 1
fi

# Build the BPF programs
echo "Building BPF programs..."
make clean
make

echo ""
echo "=== Testing BPF Verifier ==="
echo ""

# Test each program
PROGRAMS="dhcp_fastpath.bpf.o qos_ratelimit.bpf.o nat44.bpf.o antispoof.bpf.o"
PASSED=0
FAILED=0

for prog in $PROGRAMS; do
    if [ ! -f "$prog" ]; then
        echo "SKIP: $prog (not built)"
        continue
    fi

    echo -n "Testing $prog... "

    # Try to load the program (dry-run style - load and immediately unload)
    # Use a temporary pinned path
    PINPATH="/sys/fs/bpf/test_$$_$(basename $prog .bpf.o)"

    # Load the program
    if bpftool prog load "$prog" "$PINPATH" 2>/tmp/bpf_err_$$.txt; then
        echo "PASS (verifier accepted)"
        # Unload by removing the pin
        rm -f "$PINPATH"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL (verifier rejected)"
        echo "--- Verifier output (last 20 lines) ---"
        tail -20 /tmp/bpf_err_$$.txt
        echo "---"
        FAILED=$((FAILED + 1))
    fi
    rm -f /tmp/bpf_err_$$.txt
done

echo ""
echo "=== Results ==="
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ $FAILED -gt 0 ]; then
    exit 1
fi

echo ""
echo "All BPF programs passed verifier!"
