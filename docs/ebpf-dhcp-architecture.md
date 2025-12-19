# eBPF-Accelerated DHCP with Distributed State (CRDT)

**Architecture design for high-performance ISP DHCP at the edge**

---

## Executive Summary

This document outlines an architecture for accelerating ISP DHCP services using eBPF/XDP while maintaining distributed state consistency through CRDT. The design achieves 10x throughput improvement (5k → 50k requests/sec) and enables edge deployment with sub-millisecond response times.

**Key Technologies:**
- eBPF/XDP (kernel-level packet processing)
- CLSet/CRDT (Conflict-free Replicated Data Types via Nexus)
- Kubernetes (cloud-native deployment)

**Target Use Case:**
ISP subscriber IP address allocation at edge locations with multi-region state synchronisation.

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Current Architecture](#current-architecture)
3. [Proposed Solution](#proposed-solution)
4. [Architecture Decision: eBPF vs VPP](#architecture-decision-ebpf-vs-vpp)
5. [System Architecture](#system-architecture)
6. [eBPF Implementation](#ebpf-implementation)
7. [Integration with Nexus (CRDT)](#integration-with-nexus-crdt)
8. [Performance Analysis](#performance-analysis)
9. [Implementation Roadmap](#implementation-roadmap)
10. [Code Examples](#code-examples)

---

## Problem Statement

### Current Challenges

**Scale Limitations:**
- Traditional DHCP servers handle ~5,000 requests/sec per instance
- Every request requires userspace processing and database queries
- High CPU usage due to context switching (kernel ↔ userspace)

**Edge Deployment Constraints:**
- Centralized DHCP creates latency for edge subscribers
- Database dependency makes edge deployment complex
- Multi-region state synchronisation is challenging

**ISP-Specific Requirements:**
- Support 100k+ subscribers per edge location
- Sub-millisecond DHCP response times
- Dynamic IP pool management
- Client classification (residential, business, etc.)
- Multi-region consistency for subscriber roaming

---

## Current Architecture

### DHCP Server

```
┌─────────────────────────────────────────────────┐
│  Subscriber                                      │
└─────────────────┬───────────────────────────────┘
                  │ DHCP DISCOVER
                  ↓
┌─────────────────────────────────────────────────┐
│  DHCP Server (Userspace Go)                       │
│                                                  │
│  1. Parse DHCP packet                           │
│  2. Client classification                       │
│  3. Pool selection                              │
│  4. Query Nexus/Postgres for available IP      │
│     ↑ Database query = 5-10ms                   │
│  5. Allocate lease                              │
│  6. Generate DHCP OFFER                         │
│  7. Update Nexus with allocation               │
│                                                  │
└─────────────────┬───────────────────────────────┘
                  │ DHCP OFFER
                  ↓
┌─────────────────────────────────────────────────┐
│  Subscriber                                      │
└─────────────────────────────────────────────────┘
```

**Performance Characteristics:**
- Throughput: ~5,000 requests/sec
- Latency: 10-15ms average
- CPU: High (100% at peak)
- Context switches: ~10,000/sec

**Bottlenecks:**
1. Every packet goes through userspace
2. Database query per allocation
3. Context switching overhead
4. No request caching

---

## Proposed Solution

### Two-Tier Architecture: Fast Path + Slow Path

```
┌─────────────────────────────────────────────────┐
│  DHCP Request                                    │
└─────────────────┬───────────────────────────────┘
                  │
                  ↓
┌─────────────────────────────────────────────────┐
│  eBPF/XDP (Kernel Space) - FAST PATH            │
│                                                  │
│  • Parse DHCP packet                            │
│  • Lookup MAC in eBPF map                       │
│  • Cache hit? → Generate reply in kernel        │
│  • Return packet (NO USERSPACE!)                │
│                                                  │
│  Latency: ~10 microseconds                      │
│  Handles: 80% of traffic (renewals, known MACs) │
└─────────────────┬───────────────────────────────┘
                  │ Cache miss?
                  ↓
┌─────────────────────────────────────────────────┐
│  DHCP Server (Userspace) - SLOW PATH              │
│                                                  │
│  • Client classification                        │
│  • Pool selection                               │
│  • Query Nexus (CRDT) for IP                   │
│  • Allocate lease                               │
│  • Update eBPF maps (cache for future)          │
│  • Generate DHCP OFFER                          │
│                                                  │
│  Latency: ~10 milliseconds                      │
│  Handles: 20% of traffic (new allocations)      │
└─────────────────┬───────────────────────────────┘
                  │
                  ↓
┌─────────────────────────────────────────────────┐
│  Nexus (CRDT State Store)                      │
│  • Distributed IP allocation table              │
│  • Multi-region synchronisation                 │
│  • Eventual consistency                         │
└─────────────────────────────────────────────────┘
```

---

## Architecture Decision: eBPF vs VPP

### Edge Deployment Performance Requirements

Before selecting a packet processing technology, let's calculate realistic edge traffic requirements:

**Edge PoP serving 1,000 subscribers:**
```
Assumptions:
- Average broadband: 100 Mbps down, 20 Mbps up
- Peak usage (6-11pm): 30% concurrent active users
- Oversubscription ratio: 20:1 (typical for residential)

Peak traffic calculation:
= (1000 subscribers × 100 Mbps × 0.3 active) / 20 oversubscription
= 30,000 Mbps / 20
= 1.5 Gbps actual uplink usage

Even with 2,000 subscribers:
= 3 Gbps actual uplink usage
```

**Realistic edge uplink:** 10 Gbps or 40 Gbps fiber to core network

**You'd need 100+ Gbps only if:**
- Central PoP aggregating 10+ edge locations (core, not edge)
- Serving 10,000+ business customers with guaranteed bandwidth
- National-level aggregation point

**Conclusion:** Edge deployment needs 10-40 Gbps, NOT 100+ Gbps

---

### VPP Overview (Vector Packet Processing)

**What is VPP?**
- Framework from FD.io (Fast Data I/O) project (originally Cisco)
- Userspace packet processing bypassing the kernel
- Built on DPDK (Data Plane Development Kit)
- Processes packets in **batches** (vectors) instead of one-by-one

**VPP Performance:**
- **Throughput:** 10-100+ Gbps on commodity hardware
- **Latency:** ~10 μs packet processing
- **Use cases:** BNG (Broadband Network Gateway), high-throughput routers, NFV

**VPP in Kubernetes:**
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: vpp-bng
spec:
  template:
    spec:
      hostNetwork: true        # Required for DPDK
      containers:
      - name: vpp
        image: ligato/vpp-agent
        securityContext:
          privileged: true      # Required for NIC binding
        volumeMounts:
        - name: hugepages
          mountPath: /dev/hugepages  # DPDK requirement
        env:
        - name: DPDK_NICS
          value: "0000:03:00.0"  # PCI address of subscriber NIC
```

**How VPP works in K8s:**
1. Runs as privileged DaemonSet with `hostNetwork: true`
2. DPDK binds physical NICs directly to VPP (steals them from kernel)
3. Control plane (Go) communicates via VPP API (localhost)
4. VPP handles data plane (PPPoE, CGNAT, QoS, forwarding)
5. **Separate** from Kubernetes CNI (doesn't integrate with pod networking)

**VPP Projects:**
- **Ligato:** Framework for building VPP-based network functions in containers
- **Contiv-VPP:** (archived) VPP-based Kubernetes CNI

**VPP Operational Complexity:**
- Hugepages configuration required
- NIC binding removes NICs from kernel control
- Dedicated hardware per VPP instance
- Separate telemetry/observability stack
- Special configuration vs standard Kubernetes deployments

---

### eBPF/XDP Overview

**What is eBPF?**
- Extended Berkeley Packet Filter
- In-kernel programmable packet processing
- Programs run inside Linux kernel (no userspace context switch)
- Verified for safety by kernel (no crashes possible)

**XDP (eXpress Data Path):**
- eBPF programs that run at NIC driver level (before kernel networking)
- Fastest possible packet processing in Linux
- **Still in kernel** - NICs remain under kernel control

**eBPF/XDP Performance:**
- **Throughput:** 10-50 Gbps sustained (single core: 24 Mpps)
- **Latency:** ~20 μs packet processing
- **At 1500-byte packets:** ~288 Gbps theoretical
- **With realistic state lookups:** 10-50 Gbps sustained

**eBPF in Kubernetes:**
- **Cilium CNI:** eBPF-based Kubernetes networking (replaces kube-proxy/iptables)
- **Hubble:** Network observability using eBPF (zero instrumentation)
- **Standard deployments:** No privileged containers required for many use cases
- **NIC access:** NICs stay in kernel control, shareable with other services

**DHCP Fast Path Performance (XDP):**
```
Small DHCP packets (~342 bytes):
- Lookup subscriber in eBPF map: ~100ns
- Generate DHCP reply: ~500ns
- Throughput: 1-2 million DHCP req/sec
- Bandwidth equivalent: ~2.7 Gbps of DHCP traffic

Subscriber traffic (kernel stack after DHCP):
- Normal routing/NAT via kernel
- 10-40 Gbps achievable
- Bottleneck: uplink capacity, NOT CPU
```

**eBPF Operational Simplicity:**
- No hugepages configuration
- No NIC binding (NICs remain available to kernel)
- Can run alongside other K8s workloads
- Standard K8s deployments (some use cases need privileges, others don't)
- Integrates with existing monitoring (Prometheus, Grafana)

---

### VPP vs eBPF Comparison

| Aspect | VPP | eBPF/XDP | Edge Winner |
|--------|-----|----------|-------------|
| **Throughput** | 100+ Gbps | 10-50 Gbps | **eBPF** (10G sufficient) |
| **Latency** | ~10 μs | ~20 μs | **VPP** (negligible difference) |
| **K8s Integration** | Separate, privileged pods | Native (Cilium CNI) | **eBPF** ✓ |
| **NIC Control** | DPDK steals NICs from kernel | NICs stay in kernel | **eBPF** ✓ |
| **Observability** | VPP telemetry (separate) | Hubble (built-in) | **eBPF** ✓ |
| **Operational Complexity** | High (hugepages, NIC binding) | Low (standard K8s) | **eBPF** ✓ |
| **Resource Sharing** | Dedicated hardware | Share node with other pods | **eBPF** ✓ |
| **PPPoE Support** | Mature, production-ready | Would need implementation | **VPP** ✓ |
| **Development Effort** | Control plane + VPP config | C (eBPF) + Go control | Similar |
| **Container Mode** | Privileged + hostNetwork | Standard pods (for many uses) | **eBPF** ✓ |
| **Cloud-Native** | Adapted for containers | Designed for K8s | **eBPF** ✓ |
| **Deployment Model** | Snowflake configuration | GitOps-friendly | **eBPF** ✓ |

---

### Decision Rationale: Pure eBPF for Edge Deployment

**Why eBPF wins for edge deployment:**

#### 1. Performance is Sufficient
- 10-40 Gbps covers any realistic edge deployment
- XDP can saturate a 40G NIC before CPU bottleneck
- VPP's 100+ Gbps capability is overkill for edge scale

#### 2. Simpler Operations
- No DPDK (no hugepages configuration, no NIC binding)
- No privileged containers for many eBPF use cases
- Can run alongside other K8s workloads on same nodes
- Standard Kubernetes deployments

#### 3. Superior Observability
- **Hubble** gives pod-to-pod + BNG traffic visibility in one place
- eBPF metrics integrate naturally with Prometheus/Grafana
- Zero-instrumentation observability (eBPF sees everything)
- VPP requires separate telemetry stack

#### 4. Cost Savings
- **Don't need dedicated BNG hardware**
- Can share K8s nodes with other edge services:
  - DHCP server
  - RADIUS authentication
  - Monitoring stack
  - Other edge applications
- VPP requires dedicated nodes (DPDK steals NICs)

#### 5. Cloud-Native Architecture
- Fits **GitOps deployment model** (ArgoCD)
- Scales horizontally (add more K8s nodes)
- No special snowflake VPP configuration
- Standard K8s YAML manifests

#### 6. Kubernetes Integration
- **Cilium CNI** handles K8s pod networking
- BNG functions integrate with same eBPF datapath
- Single observability plane (Hubble)
- VPP runs **separate** from K8s networking

---

### When to Consider VPP Instead

**Use VPP if you need:**

1. **Central PoP aggregation** (100+ Gbps)
   - Aggregating 10+ edge sites
   - National-level traffic concentration
   - 10,000+ business customers with guaranteed bandwidth

2. **Mandatory PPPoE support**
   - VPP has mature, production-grade PPPoE implementation
   - eBPF would require implementing PPPoE from scratch
   - If PPPoE is non-negotiable and you need it NOW

3. **Dedicated BNG appliance model**
   - Not sharing infrastructure with other services
   - Willing to dedicate hardware to BNG only
   - Traditional network appliance approach

4. **Existing VPP expertise**
   - Team already knows VPP
   - Existing VPP infrastructure
   - Lower learning curve than eBPF

**Brandon Spendlove's VPP-based BNG:**
- Targets **service provider core** (100+ Gbps aggregation)
- Mature PPPoE support (critical for legacy networks)
- Likely dedicated hardware deployment model
- Different use case than **edge deployment**

---

### Hybrid Approach (Best of Both?)

**Potential hybrid architecture:**

```
┌─────────────────────────────────────────┐
│ Edge K8s Node                            │
│                                          │
│  ┌────────────────────────────────┐     │
│  │ Cilium CNI (eBPF)              │     │
│  │  - K8s pod networking           │     │
│  │  - Hubble observability         │     │
│  └────────────────────────────────┘     │
│                                          │
│  ┌────────────────────────────────┐     │
│  │ DHCP/Basic Filtering (eBPF/XDP)│     │
│  │  - DHCP fast path               │     │
│  │  - DDoS protection              │     │
│  └────────────────────────────────┘     │
│                                          │
│  ┌────────────────────────────────┐     │
│  │ Control Plane Pods (Go)        │     │
│  │  - DHCP               │     │
│  │  - RADIUS client                │     │
│  │  - Nexus CRDT sync             │     │
│  └────────────────────────────────┘     │
└─────────────────────────────────────────┘
          ↓ 10-40 Gbps uplink
┌─────────────────────────────────────────┐
│ Core PoP (IF 100+ Gbps needed)          │
│                                          │
│  ┌────────────────────────────────┐     │
│  │ VPP BNG Aggregation            │     │
│  │  - Aggregates 10+ edge sites    │     │
│  │  - PPPoE termination            │     │
│  │  - CGNAT                        │     │
│  │  - 100+ Gbps throughput         │     │
│  └────────────────────────────────┘     │
└─────────────────────────────────────────┘
```

**Hybrid strategy:**
- **Edge:** eBPF for DHCP, K8s integration, observability
- **Core:** VPP for aggregation IF 100+ Gbps needed
- **Best of both:** Cloud-native edge + high-performance core

---

### Recommended Architecture: Pure eBPF

**For edge deployment, use pure eBPF:**

```
┌─────────────────────────────────────────┐
│ Edge K8s Node (Shared Infrastructure)   │
│                                          │
│  ┌────────────────────────────────┐     │
│  │ Cilium CNI (eBPF)              │     │
│  │  - K8s pod networking           │     │
│  │  - Hubble observability         │     │
│  └────────────────────────────────┘     │
│            ▲                             │
│  ┌─────────┴──────────────────────┐     │
│  │ BNG Functions (eBPF/XDP)       │     │
│  │  - XDP on eth1 (subscribers)    │     │
│  │  - DHCP fast path               │     │
│  │  - Basic filtering/QoS          │     │
│  └────────────────────────────────┘     │
│                                          │
│  ┌────────────────────────────────┐     │
│  │ DHCP (Go pod)        │     │
│  │  - Slow path DHCP               │     │
│  │  - Nexus CRDT integration      │     │
│  └────────────────────────────────┘     │
│                                          │
│  ┌────────────────────────────────┐     │
│  │ Other Edge Services            │     │
│  │  - RADIUS, monitoring, etc      │     │
│  └────────────────────────────────┘     │
└─────────────────────────────────────────┘

Subscriber NIC: 10G or 40G (eBPF/XDP)
Uplink NIC:     10G or 40G (standard routing)
```

**Performance target:**
- 10-40 Gbps edge uplink (saturated by eBPF before CPU limit)
- 50,000+ DHCP req/sec per pod
- Sub-millisecond DHCP latency (fast path)
- 100k+ subscribers per edge location

**Why this works:**
- eBPF provides sufficient performance for edge scale
- Simpler operations than VPP (no DPDK, no hugepages)
- Native K8s integration (Cilium + Hubble)
- Cost-effective (shared infrastructure)
- Cloud-native deployment model (GitOps-friendly)

---

### Key Networking Acronyms

**BNG Technologies:**
- **BNG:** Broadband Network Gateway (subscriber gateway at ISP edge)
- **PPPoE:** Point-to-Point Protocol over Ethernet (traditional subscriber auth)
- **IPoE:** IP over Ethernet (newer, simpler than PPPoE)
- **CGNAT:** Carrier-Grade NAT (many private IPs → few public IPs)
- **NAT44:** IPv4-to-IPv4 NAT
- **QoS:** Quality of Service (per-subscriber rate limiting)
- **RADIUS:** Remote Authentication Dial-In User Service (auth protocol)

**Packet Processing:**
- **VPP:** Vector Packet Processing (userspace packet batching)
- **DPDK:** Data Plane Development Kit (userspace packet I/O)
- **eBPF:** Extended Berkeley Packet Filter (in-kernel programmable processing)
- **XDP:** eXpress Data Path (eBPF at NIC driver level)

**Kubernetes Networking:**
- **CNI:** Container Network Interface (K8s networking plugin API)
- **Cilium:** eBPF-based Kubernetes CNI
- **Hubble:** Network observability built on Cilium

**Network Infrastructure:**
- **FRR:** Free Range Routing (open-source BGP/OSPF daemon)
- **VLAN:** Virtual Local Area Network (network segmentation)
- **NIC:** Network Interface Card
- **PoP:** Point of Presence (ISP facility where customer connections terminate)

**DHCP:**
- **DUID:** DHCP Unique Identifier (DHCPv6 client identifier)
- **Lease:** How long a DHCP-allocated IP is valid

---

## System Architecture

### Component Interaction

```
┌───────────────────────────────────────────────────────────┐
│  Edge Location A (Kubernetes Cluster)                     │
│                                                            │
│  ┌──────────────────────────────────────────────────┐    │
│  │ DHCP Server Pod                                     │    │
│  │                                                    │    │
│  │  ┌──────────────────────────────────────────┐    │    │
│  │  │ eBPF/XDP Programs (Kernel)               │    │    │
│  │  │ - Fast DHCP response                     │    │    │
│  │  │ - Local cache (eBPF maps)                │    │    │
│  │  └──────────────────────────────────────────┘    │    │
│  │                    ↕                               │    │
│  │  ┌──────────────────────────────────────────┐    │    │
│  │  │ Userspace (Go)                           │    │    │
│  │  │ - Client classification                  │    │    │
│  │  │ - Complex allocation logic               │    │    │
│  │  │ - eBPF map management                    │    │    │
│  │  │ - Nexus integration                     │    │    │
│  │  └──────────────────────────────────────────┘    │    │
│  └──────────────────────────────────────────────────┘    │
│                          ↕                                 │
│  ┌──────────────────────────────────────────────────┐    │
│  │ Nexus (Local instance)                          │    │
│  │ - Local CRDT replica                             │    │
│  │ - Stores IP allocations                          │    │
│  └──────────────────────────────────────────────────┘    │
└───────────────────────────────────────────────────────────┘
                          ↕
                    (CLSet Sync)
                          ↕
┌───────────────────────────────────────────────────────────┐
│  Nexus Cluster (Distributed State)                       │
│  - Multi-region CRDT consensus                            │
│  - IP allocation conflict resolution                      │
│  - Subscriber → IP mapping                                │
└───────────────────────────────────────────────────────────┘
                          ↕
                    (CLSet Sync)
                          ↕
┌───────────────────────────────────────────────────────────┐
│  Edge Location B (Kubernetes Cluster)                     │
│  [Same structure as Location A]                           │
└───────────────────────────────────────────────────────────┘
```

### Data Flow: New Subscriber

**Step 1: Initial DHCP DISCOVER**
```
1. Subscriber sends DHCP DISCOVER
2. eBPF/XDP receives packet at NIC
3. Lookup MAC in eBPF map → MISS (new subscriber)
4. Pass to userspace DHCP Server
```

**Step 2: Userspace Processing**
```
5. DHCP Server classifies client (residential/business)
6. Selects IP pool based on classification
7. Queries Nexus for available IP
8. Nexus allocates IP (CRDT operation)
9. DHCP Server generates DHCP OFFER
10. DHCP Server updates eBPF map (cache allocation)
```

**Step 3: CRDT Synchronisation**
```
11. Nexus broadcasts allocation to other regions (CLSet)
12. Nexus instances at other edge locations receive update
13. Other DHCP Server instances update their eBPF maps
```

**Step 4: Subsequent Requests (Fast Path)**
```
14. Subscriber sends DHCP REQUEST (renewal)
15. eBPF/XDP receives packet
16. Lookup MAC in eBPF map → HIT (cached)
17. Generate DHCP ACK in kernel
18. Reply directly (NO USERSPACE!)
    Latency: ~10 microseconds
```

---

## eBPF Implementation

### eBPF Maps (Kernel Data Structures)

#### 1. Subscriber → Pool Assignment Map
```c
// Maps MAC address to pool assignment
struct bpf_map_def SEC("maps") subscriber_pools = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),              // MAC address (6 bytes padded)
    .value_size = sizeof(struct pool_assignment),
    .max_entries = 1000000,               // Support 1M subscribers
};

struct pool_assignment {
    u32 pool_id;          // Which IP pool
    u32 allocated_ip;     // Currently assigned IP
    u32 vlan_id;          // VLAN tag for subscriber
    u8 client_class;      // Residential=1, Business=2, etc.
    u64 lease_expiry;     // Unix timestamp (for cleanup)
    u8 flags;             // Static IP, etc.
};
```

#### 2. IP Pool Metadata Map
```c
// IP pool configuration and state
struct bpf_map_def SEC("maps") ip_pools = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),              // pool_id
    .value_size = sizeof(struct ip_pool),
    .max_entries = 10000,                 // Support 10k pools
};

struct ip_pool {
    u32 network;          // Network address (e.g., 10.0.0.0)
    u8 prefix_len;        // CIDR prefix (e.g., 24 for /24)
    u32 gateway;          // Default gateway for pool
    u32 dns_primary;      // Primary DNS server
    u32 dns_secondary;    // Secondary DNS server
    u32 lease_time;       // Default lease duration (seconds)
};
```

#### 3. Active Leases Map
```c
// Track all active leases
struct bpf_map_def SEC("maps") active_leases = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),              // IP address
    .value_size = sizeof(struct lease),
    .max_entries = 1000000,               // 1M concurrent leases
};

struct lease {
    u64 mac_addr;         // Subscriber MAC
    u64 lease_start;      // Allocation timestamp
    u64 lease_expiry;     // Expiry timestamp
    u32 pool_id;          // Which pool
    u8 state;             // OFFERED=1, ACKED=2, RELEASED=3
};
```

### eBPF Program (XDP)

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

// DHCP message types
#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_ACK      5

SEC("xdp")
int brushtail_dhcp_fastpath(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Only process UDP
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Parse UDP header
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // Check if DHCP (port 67/68)
    if (udp->dest != htons(67) && udp->dest != htons(68))
        return XDP_PASS;

    // Parse DHCP packet
    struct dhcp_packet *dhcp = (void *)(udp + 1);
    if ((void *)(dhcp + 1) > data_end)
        return XDP_PASS;

    // Extract client MAC address
    u64 mac_addr = 0;
    __builtin_memcpy(&mac_addr, dhcp->chaddr, 6);

    // Lookup subscriber in pool assignment map
    struct pool_assignment *assignment =
        bpf_map_lookup_elem(&subscriber_pools, &mac_addr);

    if (!assignment) {
        // Unknown subscriber → SLOW PATH (pass to userspace)
        return XDP_PASS;
    }

    // Get DHCP message type from options
    u8 msg_type = parse_dhcp_message_type(dhcp, data_end);

    if (msg_type == DHCP_DISCOVER || msg_type == DHCP_REQUEST) {
        // FAST PATH: We have cached allocation

        // Lookup pool metadata
        struct ip_pool *pool =
            bpf_map_lookup_elem(&ip_pools, &assignment->pool_id);

        if (!pool) {
            return XDP_PASS;  // Safety: fall back to userspace
        }

        // Check if lease is still valid
        u64 now = bpf_ktime_get_ns() / 1000000000;  // Convert to seconds
        if (now > assignment->lease_expiry) {
            // Lease expired → SLOW PATH (need reallocation)
            return XDP_PASS;
        }

        // Generate DHCP OFFER/ACK in-kernel
        generate_dhcp_reply(
            ctx,
            msg_type == DHCP_DISCOVER ? DHCP_OFFER : DHCP_ACK,
            assignment->allocated_ip,
            pool->gateway,
            pool->dns_primary,
            pool->dns_secondary,
            pool->lease_time
        );

        // Update metrics
        __sync_fetch_and_add(&dhcp_fastpath_counter, 1);

        // Send reply packet directly
        return XDP_TX;
    }

    // Other DHCP messages → pass to userspace
    return XDP_PASS;
}

// Helper function to generate DHCP reply
static __always_inline void generate_dhcp_reply(
    struct xdp_md *ctx,
    u8 msg_type,
    u32 your_ip,
    u32 gateway,
    u32 dns1,
    u32 dns2,
    u32 lease_time
) {
    // Swap MAC addresses (destination ← source)
    // Swap IP addresses
    // Construct DHCP reply with options:
    //   - Message Type (OFFER/ACK)
    //   - Your IP Address
    //   - Subnet Mask
    //   - Router (gateway)
    //   - DNS Servers
    //   - Lease Time

    // Implementation details omitted for brevity
    // Full implementation would be ~100 lines
}
```

---

## Integration with Nexus (CRDT)

### Nexus Role

Nexus provides **distributed state synchronisation** across edge locations:

1. **IP Allocation Conflict Resolution**
   - Two edge locations try to allocate same IP → CRDT resolves
   - Last-write-wins with vector clocks

2. **Multi-Region Consistency**
   - Subscriber allocation in Region A syncs to Region B
   - Enables subscriber roaming

3. **State Recovery**
   - eBPF maps are volatile (lost on pod restart)
   - Nexus provides persistent state
   - On startup, DHCP Server repopulates eBPF maps from Nexus

### Data Flow: Nexus ↔ DHCP Server

```go
// DHCP Server userspace code
package main

import (
    "github.com/cilium/ebpf"
    "nexus-client" // Hypothetical Nexus Go client
)

type DHCPServer struct {
    // eBPF maps
    subscriberPools *ebpf.Map
    ipPools         *ebpf.Map
    activeLeases    *ebpf.Map

    // Nexus client
    nexus *nexus.Client
}

// Handle new allocation (slow path)
func (s *DHCPServer) AllocateLease(mac uint64, clientClass string) (net.IP, error) {
    // 1. Query Nexus for available IP
    ip, err := s.nexus.AllocateIP(mac, clientClass)
    if err != nil {
        return nil, err
    }

    // 2. Update eBPF map (cache for fast path)
    assignment := PoolAssignment{
        PoolID:      poolID,
        AllocatedIP: ip,
        VlanID:      vlan,
        ClientClass: classID,
        LeaseExpiry: time.Now().Add(24 * time.Hour).Unix(),
    }

    if err := s.subscriberPools.Put(mac, assignment); err != nil {
        log.Error("Failed to update eBPF map", err)
        // Don't fail DHCP, eBPF cache is best-effort
    }

    // 3. Nexus broadcasts allocation to other regions (CRDT)
    // This happens automatically in Nexus via CLSet sync

    return ip, nil
}

// Handle Nexus updates from other regions
func (s *DHCPServer) WatchNexusUpdates() {
    updates := s.nexus.Watch("ip-allocations")

    for update := range updates {
        // Another region allocated IP
        // Update our local eBPF cache

        mac := update.MAC
        assignment := PoolAssignment{
            PoolID:      update.PoolID,
            AllocatedIP: update.IP,
            VlanID:      update.Vlan,
            LeaseExpiry: update.LeaseExpiry,
        }

        if err := s.subscriberPools.Put(mac, assignment); err != nil {
            log.Error("Failed to sync eBPF map from Nexus", err)
        }
    }
}

// Populate eBPF maps on startup from Nexus
func (s *DHCPServer) Initialize() error {
    // Fetch all active leases from Nexus
    leases, err := s.nexus.GetActiveLeases()
    if err != nil {
        return err
    }

    // Populate eBPF maps
    for _, lease := range leases {
        assignment := PoolAssignment{
            PoolID:      lease.PoolID,
            AllocatedIP: lease.IP,
            VlanID:      lease.Vlan,
            LeaseExpiry: lease.Expiry,
        }

        if err := s.subscriberPools.Put(lease.MAC, assignment); err != nil {
            log.Warn("Failed to populate eBPF map", err)
            // Continue populating others
        }
    }

    log.Info("Populated eBPF maps with %d leases from Nexus", len(leases))
    return nil
}
```

### CRDT Conflict Resolution Example

**Scenario:** Two edge locations allocate same IP simultaneously

```
Time T0:
  Edge A: Subscriber 1 requests IP
  Edge B: Subscriber 2 requests IP

Time T1:
  Edge A: Allocates 10.0.1.100 to Subscriber 1
  Edge B: Allocates 10.0.1.100 to Subscriber 2
  (Both write to local Nexus replica)

Time T2:
  CLSet propagates both allocations
  Nexus CRDT detects conflict

Time T3:
  CRDT resolution (vector clock comparison):
    - Edge A timestamp: 2025-12-09T12:00:01.500Z
    - Edge B timestamp: 2025-12-09T12:00:01.750Z

  Edge B wins (later timestamp)

Time T4:
  Edge A receives CRDT merge:
    - 10.0.1.100 → Subscriber 2 (Edge B allocation)
    - Edge A must revoke Subscriber 1's lease
    - Edge A sends DHCP NAK to Subscriber 1
    - Subscriber 1 gets different IP on next request
```

**Why this works:**
- DHCP leases are soft state (clients retry)
- Conflict resolution is rare (IP pools are large)
- CRDT ensures eventual consistency

---

## Performance Analysis

### Baseline (Current DHCP Server)

| Metric | Value | Notes |
|--------|-------|-------|
| Throughput | 5,000 req/sec | Per pod |
| Avg Latency | 12ms | Includes DB query |
| P95 Latency | 25ms | Under load |
| P99 Latency | 50ms | Database contention |
| CPU Usage | 3.5 cores | At 5k req/sec |
| Context Switches | 10,000/sec | Userspace processing |

### With eBPF Fast Path

| Metric | Fast Path | Slow Path | Weighted Avg |
|--------|-----------|-----------|--------------|
| Throughput | 45,000 req/sec | 5,000 req/sec | 50,000 req/sec |
| Latency | 10 μs | 12 ms | 2.4 ms |
| CPU Usage | 0.2 cores | 0.7 cores | 0.9 cores |
| Context Switches | 0 | 2,000/sec | 2,000/sec |

**Assumptions:**
- 80% of requests are renewals (fast path)
- 20% of requests are new allocations (slow path)

**Weighted Average Calculation:**
```
Latency = 0.8 × 10μs + 0.2 × 12ms = 2.4ms
CPU = 0.8 × 0.2 cores + 0.2 × 3.5 cores = 0.9 cores
```

### Cost Savings

**Without eBPF:**
- 100k subscribers = 20 DHCP Server pods (5k subscribers/pod)
- 20 pods × 4 cores = 80 cores
- AWS cost: ~$2,000/month

**With eBPF:**
- 100k subscribers = 2 DHCP Server pods (50k subscribers/pod)
- 2 pods × 1 core = 2 cores
- AWS cost: ~$50/month

**Savings: $1,950/month per edge location**

---

## Implementation Roadmap

### Phase 1: eBPF Prototype (2 weeks)

**Goal:** Prove eBPF can accelerate DHCP

**Tasks:**
1. Write eBPF program for DHCP packet parsing
2. Implement basic subscriber map (MAC → IP)
3. Generate DHCP OFFER in kernel
4. Benchmark latency (target: <100μs)

**Success Criteria:**
- eBPF program loads and attaches to NIC
- Can reply to DHCP DISCOVER from cache
- Latency < 100μs for cached requests

---

### Phase 2: Integration with DHCP Server (3 weeks)

**Goal:** Integrate eBPF with existing DHCP Server code

**Tasks:**
1. Load eBPF program from Go code (cilium/ebpf library)
2. Populate eBPF maps from DHCP Server allocations
3. Implement slow path fallback (eBPF → userspace)
4. Add metrics (fast path hit rate, latency)

**Success Criteria:**
- DHCP Server pod loads eBPF on startup
- Fast path handles renewals
- Slow path handles new allocations
- Hit rate > 70%

---

### Phase 3: Nexus Integration (3 weeks)

**Goal:** Sync eBPF cache with Nexus CRDT state

**Tasks:**
1. Watch Nexus for allocation updates
2. Update eBPF maps when Nexus syncs from other regions
3. Repopulate eBPF maps from Nexus on pod restart
4. Handle CRDT conflicts (revoke leases if needed)

**Success Criteria:**
- eBPF cache stays in sync with Nexus
- Multi-region allocations propagate correctly
- Pod restart recovers eBPF state from Nexus

---

### Phase 4: Production Testing (4 weeks)

**Goal:** Validate in production-like environment

**Tasks:**
1. Deploy to staging cluster
2. Load testing (target: 50k req/sec)
3. Chaos testing (pod restarts, network partitions)
4. Validate CRDT conflict resolution
5. Performance tuning

**Success Criteria:**
- Sustain 50k req/sec
- P99 latency < 5ms
- No allocation conflicts
- Graceful degradation on failures

---

### Phase 5: Production Rollout (2 weeks)

**Goal:** Deploy to production edge locations

**Tasks:**
1. Canary deployment (10% traffic)
2. Metrics validation
3. Gradual rollout (25% → 50% → 100%)
4. Documentation and runbooks

**Success Criteria:**
- Zero subscriber impact
- Metrics match staging
- Cost savings realised

---

## Code Examples

### Complete DHCP Server Integration

#### main.go
```go
package main

import (
    "context"
    "log"
    "net"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    dhcp "github.com/insomniacslk/dhcp/dhcpv4"
)

type DHCPServer struct {
    // Existing DHCP Server components
    allocator Allocator
    classifier *ClientClassifier

    // NEW: eBPF components
    xdpProg         *ebpf.Program
    xdpLink         link.Link
    subscriberPools *ebpf.Map
    ipPools         *ebpf.Map
    activeLeases    *ebpf.Map

    // Nexus client
    nexus *NexusClient
}

func NewDHCPServer(iface string) (*DHCPServer, error) {
    // Load eBPF program
    spec, err := ebpf.LoadCollectionSpec("brushtail_ebpf.o")
    if err != nil {
        return nil, fmt.Errorf("load eBPF spec: %w", err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        return nil, fmt.Errorf("create eBPF collection: %w", err)
    }

    // Attach XDP program to network interface
    iface, err := net.InterfaceByName(iface)
    if err != nil {
        return nil, fmt.Errorf("get interface: %w", err)
    }

    xdpLink, err := link.AttachXDP(link.XDPOptions{
        Program:   coll.Programs["brushtail_dhcp_fastpath"],
        Interface: iface.Index,
    })
    if err != nil {
        return nil, fmt.Errorf("attach XDP: %w", err)
    }

    s := &DHCPServer{
        xdpProg:         coll.Programs["brushtail_dhcp_fastpath"],
        xdpLink:         xdpLink,
        subscriberPools: coll.Maps["subscriber_pools"],
        ipPools:         coll.Maps["ip_pools"],
        activeLeases:    coll.Maps["active_leases"],
    }

    // Initialize from Nexus
    if err := s.initializeFromNexus(); err != nil {
        return nil, fmt.Errorf("initialize from Nexus: %w", err)
    }

    // Start watching Nexus updates
    go s.watchNexusUpdates()

    return s, nil
}

func (s *DHCPServer) initializeFromNexus() error {
    ctx := context.Background()

    // Fetch all active leases from Nexus
    leases, err := s.nexus.GetActiveLeases(ctx)
    if err != nil {
        return err
    }

    log.Printf("Populating eBPF maps with %d leases from Nexus", len(leases))

    // Populate eBPF maps
    for i, lease := range leases {
        mac := lease.MAC // uint64

        assignment := PoolAssignment{
            PoolID:      lease.PoolID,
            AllocatedIP: ip2uint32(lease.IP),
            VlanID:      lease.VlanID,
            ClientClass: lease.ClientClass,
            LeaseExpiry: lease.Expiry.Unix(),
        }

        if err := s.subscriberPools.Put(mac, assignment); err != nil {
            log.Printf("Warning: failed to populate eBPF map entry %d: %v", i, err)
            continue
        }

        if i%1000 == 0 {
            log.Printf("Populated %d/%d leases", i, len(leases))
        }
    }

    log.Printf("eBPF maps populated successfully")
    return nil
}

func (s *DHCPServer) watchNexusUpdates() {
    ctx := context.Background()
    updates := s.nexus.WatchAllocations(ctx)

    for update := range updates {
        mac := update.MAC

        assignment := PoolAssignment{
            PoolID:      update.PoolID,
            AllocatedIP: ip2uint32(update.IP),
            VlanID:      update.VlanID,
            ClientClass: update.ClientClass,
            LeaseExpiry: update.Expiry.Unix(),
        }

        if err := s.subscriberPools.Put(mac, assignment); err != nil {
            log.Printf("Failed to update eBPF map from Nexus: %v", err)
        } else {
            log.Printf("Synced allocation from Nexus: MAC=%x IP=%s", mac, update.IP)
        }
    }
}

func (s *DHCPServer) HandleDHCP(pkt *dhcp.DHCPv4) (*dhcp.DHCPv4, error) {
    // NOTE: This is SLOW PATH only
    // Fast path (renewals) handled entirely in eBPF kernel space
    // This function only called for cache misses

    mac := macToUint64(pkt.ClientHWAddr)

    log.Printf("SLOW PATH: Handling DHCP request for MAC=%x", mac)

    // Client classification
    clientClass := s.classifier.Classify(pkt)

    // Pool selection based on client class
    pool, err := s.selectPool(clientClass)
    if err != nil {
        return nil, err
    }

    // Allocate IP from Nexus (CRDT)
    ip, err := s.nexus.AllocateIP(context.Background(), mac, pool.ID)
    if err != nil {
        return nil, err
    }

    // Update eBPF cache for future requests (FAST PATH)
    assignment := PoolAssignment{
        PoolID:      pool.ID,
        AllocatedIP: ip2uint32(ip),
        VlanID:      pool.VlanID,
        ClientClass: clientClass,
        LeaseExpiry: time.Now().Add(24 * time.Hour).Unix(),
    }

    if err := s.subscriberPools.Put(mac, assignment); err != nil {
        log.Printf("Warning: failed to cache allocation in eBPF: %v", err)
        // Don't fail DHCP, eBPF cache is best-effort
    } else {
        log.Printf("Cached allocation in eBPF for MAC=%x IP=%s", mac, ip)
    }

    // Generate DHCP OFFER/ACK
    reply := dhcp.NewReplyFromRequest(pkt)
    reply.YourIPAddr = ip
    reply.Options.Update(dhcp.OptServerIdentifier(s.serverIP))
    reply.Options.Update(dhcp.OptIPAddressLeaseTime(24 * time.Hour))
    reply.Options.Update(dhcp.OptRouter(pool.Gateway))
    reply.Options.Update(dhcp.OptDNS(pool.DNS...))

    return reply, nil
}

func (s *DHCPServer) Close() error {
    // Detach XDP program
    if s.xdpLink != nil {
        s.xdpLink.Close()
    }

    // Close eBPF maps
    if s.subscriberPools != nil {
        s.subscriberPools.Close()
    }
    if s.ipPools != nil {
        s.ipPools.Close()
    }
    if s.activeLeases != nil {
        s.activeLeases.Close()
    }

    return nil
}

func macToUint64(mac net.HardwareAddr) uint64 {
    if len(mac) != 6 {
        return 0
    }
    return uint64(mac[0])<<40 | uint64(mac[1])<<32 |
           uint64(mac[2])<<24 | uint64(mac[3])<<16 |
           uint64(mac[4])<<8 | uint64(mac[5])
}

func ip2uint32(ip net.IP) uint32 {
    ip = ip.To4()
    return uint32(ip[0])<<24 | uint32(ip[1])<<16 |
           uint32(ip[2])<<8 | uint32(ip[3])
}
```

---

## Observability

### Metrics

**eBPF Fast Path:**
```
dhcp_fastpath_requests_total{result="success"}
dhcp_fastpath_requests_total{result="cache_miss"}
dhcp_fastpath_latency_microseconds{quantile="0.5"}
dhcp_fastpath_latency_microseconds{quantile="0.95"}
dhcp_fastpath_latency_microseconds{quantile="0.99"}
```

**Userspace Slow Path:**
```
dhcp_slowpath_requests_total{result="success"}
dhcp_slowpath_requests_total{result="error"}
dhcp_slowpath_latency_milliseconds{quantile="0.5"}
dhcp_slowpath_latency_milliseconds{quantile="0.95"}
```

**Cache Performance:**
```
dhcp_cache_hit_rate
dhcp_cache_size_bytes
dhcp_cache_entries_total
```

**Nexus Integration:**
```
nexus_sync_events_total{type="allocation"}
nexus_sync_events_total{type="release"}
nexus_conflicts_total
nexus_sync_latency_milliseconds
```

### Hubble Observability

```bash
# Watch all DHCP traffic
$ hubble observe --protocol dhcp --namespace brushtail

TIMESTAMP             SOURCE                 DEST                   VERDICT
12:00:01.000          subscriber-1           brushtail-pod-1        FORWARDED
12:00:01.010          brushtail-pod-1        subscriber-1           FORWARDED (XDP)

# See fast path vs slow path
$ hubble observe --verdict XDP
12:00:01.010  brushtail-pod-1  subscriber-1  XDP_TX (fast path reply)

$ hubble observe --verdict PASS
12:00:02.100  brushtail-pod-1  subscriber-2  XDP_PASS (slow path to userspace)
```

---

## Security Considerations

### eBPF Verifier Safety

eBPF programs are verified by the kernel before loading:
- No unbounded loops
- No out-of-bounds memory access
- No kernel crashes possible

### Attack Surface

**Potential Risks:**
1. **Malicious DHCP packets** → eBPF verifier prevents kernel crashes
2. **eBPF map poisoning** → Only root can update maps (Kubernetes RBAC)
3. **DoS via cache exhaustion** → Map size limits + LRU eviction

**Mitigations:**
- Rate limiting at XDP level
- Packet validation in eBPF
- Monitor cache eviction rate
- Kubernetes security contexts (drop capabilities)

---

## Future Enhancements

### 1. XDP-Based DDoS Protection

Extend eBPF program to drop malicious DHCP floods:
```c
// Rate limit per source MAC
struct bpf_map_def rate_limits = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),   // MAC
    .value_size = sizeof(u32), // Requests in last second
    .max_entries = 100000,
};

// Drop if >10 requests/sec from same MAC
if (requests_per_sec > 10) {
    return XDP_DROP;
}
```

### 2. DHCPv6 Support

Extend eBPF program for IPv6:
- Parse ICMPv6 + DHCPv6
- IPv6 address allocation cache

### 3. Integration with BNG

Combine DHCP + BNG in single eBPF datapath:
```
Subscriber → [eBPF: PPPoE + DHCP + QoS + CGNAT] → Internet
              ↑ All in kernel, ultra-low latency
```

### 4. Machine Learning-Based Pool Selection

Use eBPF to collect features, train model in userspace:
- Time of day
- Device type (MAC OUI)
- Historical usage patterns
→ Predict optimal pool for subscriber

---

## Conclusion

This architecture demonstrates how eBPF can accelerate ISP DHCP services by **10x** while maintaining distributed consistency through CRDT. The two-tier approach (fast path in kernel, slow path in userspace) provides:

✅ **Performance**: 50k req/sec, sub-millisecond latency
✅ **Scalability**: 100k subscribers per pod
✅ **Cost Savings**: $1,950/month per edge location
✅ **Edge Deployment**: Works with distributed state (Nexus)
✅ **Reliability**: Graceful degradation (eBPF → userspace fallback)

**Key Innovations:**
1. eBPF for DHCP fast path (industry first?)
2. Integration with CRDT for multi-region sync
3. Kubernetes-native deployment
4. Zero-instrumentation observability (Hubble)

**Next Steps:**
1. Build PoC (Phase 1)
2. Integrate with DHCP Server (Phase 2)
3. Connect to Nexus (Phase 3)
4. Production validation (Phase 4)

---

## References

- [Cilium eBPF Documentation](https://docs.cilium.io/en/latest/bpf/)
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [eBPF Go Library](https://github.com/cilium/ebpf)

---

**Author**: Mark Gascoyne
**Date**: December 2025
**Status**: Design Document (Not Implemented)
