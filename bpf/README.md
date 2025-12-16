# eBPF Programs

XDP programs for high-performance DHCP packet processing.

## Files

- **dhcp_fastpath.c**: Main XDP program for DHCP fast path
- **maps.h**: eBPF map definitions (subscriber_pools, ip_pools, stats_map)
- **Makefile**: Compilation rules for eBPF programs

## Compilation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)

# macOS (for development only, run in Docker for actual eBPF)
brew install llvm
```

### Build

```bash
make        # Compile all eBPF programs
make info   # Show build configuration
make verify # Verify compiled objects
make clean  # Remove build artifacts
```

### Output

Compiled programs:
- `dhcp_fastpath.bpf.o` - XDP program bytecode

## eBPF Maps

### subscriber_pools
- **Type**: BPF_MAP_TYPE_HASH
- **Key**: MAC address (u64, 6 bytes padded)
- **Value**: pool_assignment struct
- **Max Entries**: 1,000,000
- **Purpose**: Cache subscriber → IP allocation

### ip_pools
- **Type**: BPF_MAP_TYPE_HASH
- **Key**: pool_id (u32)
- **Value**: ip_pool struct
- **Max Entries**: 10,000
- **Purpose**: IP pool metadata (network, gateway, DNS, lease time)

### stats_map
- **Type**: BPF_MAP_TYPE_ARRAY
- **Key**: 0 (single entry)
- **Value**: dhcp_stats struct
- **Purpose**: Performance counters (requests, hits, misses, errors)

## Program Flow

```
Packet arrives → XDP hook
   ↓
Parse: Ethernet → IP → UDP → DHCP
   ↓
Lookup MAC in subscriber_pools
   ↓
   ├─ Cache MISS → XDP_PASS (userspace)
   ↓
   ├─ Lease EXPIRED → XDP_PASS (userspace)
   ↓
   └─ Cache HIT → Generate reply → XDP_TX (kernel fast path)
```

## Development Status

**Phase 2 (Current)**: Skeleton implementation
- [x] Map definitions
- [x] Packet parsing (bounds checking)
- [x] Cache lookup logic
- [x] Statistics counters
- [ ] DHCP reply generation (Phase 3)

**Phase 3 (Next)**: Full DHCP fast path
- [ ] DHCP OFFER generation in kernel
- [ ] DHCP ACK generation in kernel
- [ ] DHCP options encoding
- [ ] Checksum recalculation
- [ ] Packet rewriting (MAC/IP swap)

## Debugging

### Load program manually

```bash
# Compile
make

# Load
sudo bpftool prog load dhcp_fastpath.bpf.o /sys/fs/bpf/dhcp_fastpath

# Attach to interface
sudo ip link set dev eth1 xdp pinned /sys/fs/bpf/dhcp_fastpath

# Check attached
sudo bpftool net show dev eth1
```

### Inspect maps

```bash
# Show all maps
sudo bpftool map show

# Dump subscriber_pools
sudo bpftool map dump name subscriber_pools

# Get stats
sudo bpftool map lookup name stats_map key 0
```

### Remove program

```bash
sudo ip link set dev eth1 xdp off
sudo rm /sys/fs/bpf/dhcp_fastpath
```

## Testing

### Unit tests (TODO)

```bash
# Test eBPF program loading
go test ./pkg/ebpf -v

# Test map operations
go test ./pkg/ebpf/maps -v
```

### Integration tests (TODO)

```bash
# Test with real DHCP client
sudo dhclient -v eth1

# Monitor with bpftool
sudo bpftool prog tracelog
```

## References

- [eBPF Documentation](https://docs.kernel.org/bpf/)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
