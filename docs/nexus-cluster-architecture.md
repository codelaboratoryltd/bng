# Nexus Cluster Architecture

This document describes the multi-node Nexus deployment architecture with hashring-based IP allocation and CLSet CRDT synchronization.

## Overview

Nexus runs as a clustered service providing:
- **IP allocation** via bitmap allocators with hashring ownership
- **State storage** for subscribers, pools, and ISP configurations
- **CLSet CRDT** for eventually consistent distributed state
- **API endpoints** for BNG queries and management

```
┌─────────────────────────────────────────────────────────────┐
│                   Nexus Cluster (K8s)                        │
│                                                              │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐                  │
│  │ Nexus-1 │◄──►│ Nexus-2 │◄──►│ Nexus-3 │                  │
│  └────┬────┘    └────┬────┘    └────┬────┘                  │
│       │              │              │                        │
│       └──────────────┴──────────────┘                        │
│              CLSet CRDT Sync Layer                           │
│              (automatic conflict resolution)                 │
│                                                              │
│  Hashring:                                                   │
│  ├── Pool ownership distributed across nodes                │
│  ├── Writes routed to owner for allocation                  │
│  └── Reads served by any node (CLSet consistency)           │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ gRPC/HTTP API
                       │
     ┌─────────────────┼─────────────────┐
     │                 │                 │
┌────▼────┐      ┌────▼────┐      ┌─────▼────┐
│  BNG-1  │      │  BNG-2  │      │  BNG-N   │
│         │      │         │      │          │
│ - Cache │      │ - Cache │      │ - Cache  │
│ - eBPF  │      │ - eBPF  │      │ - eBPF   │
└─────────┘      └─────────┘      └──────────┘
```

## Component Responsibilities

### Nexus Cluster Nodes

Each Nexus node runs identically:

| Component | Responsibility |
|-----------|----------------|
| **CLSetStore** | Distributed key-value store with CRDT semantics |
| **PoolAllocator** | Bitmap-based IP/prefix allocation |
| **AllocationStore** | Dual-indexed allocation tracking |
| **Hashring** | Consistent hashing for pool ownership |
| **API Server** | gRPC/HTTP endpoints for BNG queries |

### BNG Nodes

BNG nodes are **consumers**, not cluster participants:

- Query Nexus for subscriber IP allocations
- Maintain local cache for DHCP fast path
- No hashring membership
- Continue operating during Nexus partition (cached data)

## Hashring Design

### Why Hashring?

The hashring provides:
1. **Deterministic ownership**: Same pool always owned by same node
2. **Balanced distribution**: Pools spread evenly across nodes
3. **Minimal disruption**: Node failure only affects its pools
4. **No coordination**: Write routing is local decision

### Pool Ownership

```
┌────────────────────────────────────────────────────────────┐
│                      Hashring                               │
│                                                             │
│            Nexus-1              Nexus-2                     │
│               │                    │                        │
│    pool-a ────┘                    └──── pool-c             │
│    pool-b ────┐                    ┌──── pool-d             │
│               │                    │                        │
│            Nexus-3                                          │
│               │                                             │
│    pool-e ────┘                                             │
│    pool-f ────┘                                             │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

Each pool is assigned to exactly one owner:
- **Writes** (allocate/release): Routed to owner node
- **Reads** (lookup): Served by any node via CLSet

### Allocation Flow

```
1. BNG receives RADIUS Access-Accept with pool hint
   │
   ▼
2. BNG calls Nexus API: POST /allocate
   { subscriber_id, pool_id }
   │
   ▼
3. Nexus node receives request
   ├── If owner: allocate from local bitmap
   └── If not owner: proxy to owner node
   │
   ▼
4. Owner allocates IP via bitmap allocator
   │
   ▼
5. Allocation written to CLSet
   │
   ▼
6. CLSet syncs to all Nexus nodes
   │
   ▼
7. BNG receives IP, caches in eBPF map
```

### Node Failure Handling

When a Nexus node fails:

```
┌──────────────────────────────────────────────────────────────┐
│ Before Failure:                                               │
│   Nexus-1: [pool-a, pool-b]                                   │
│   Nexus-2: [pool-c, pool-d]                                   │
│   Nexus-3: [pool-e, pool-f]                                   │
│                                                               │
│ Nexus-2 fails:                                                │
│   Hashring detects failure                                    │
│   pool-c → Nexus-1                                            │
│   pool-d → Nexus-3                                            │
│                                                               │
│ After Redistribution:                                         │
│   Nexus-1: [pool-a, pool-b, pool-c]                           │
│   Nexus-3: [pool-e, pool-f, pool-d]                           │
│                                                               │
│ Existing allocations: Unchanged (in CLSet)                    │
│ New allocations: Handled by new owners                        │
└──────────────────────────────────────────────────────────────┘
```

## CLSet Integration

### Data Model

```
/nexus/
├── pools/{pool-id}/
│   ├── config              # Pool configuration (CIDR, ISP, etc.)
│   └── bitmap              # Allocation bitmap (compressed)
│
├── allocations/
│   ├── by-pool/{pool-id}/{ip}      # → allocation record
│   ├── by-subscriber/{sub-id}/     # → [allocation records]
│   └── by-ip/{ip}                  # → allocation record
│
├── subscribers/{subscriber-id}/
│   ├── config              # Subscriber configuration
│   └── session             # Active session state
│
├── peers/
│   └── {peer-id}/          # Cluster peer info
│       ├── addr            # API address
│       ├── last_seen       # Heartbeat timestamp
│       └── pools           # Owned pools
│
└── hashring/
    └── state               # Current hashring configuration
```

### Sync Protocol

CLSet provides eventually consistent synchronization:

```go
// Local write (on owner node)
store.Put(ctx, "allocations/by-ip/10.0.0.50", record)

// CLSet automatically:
// 1. Assigns vector clock timestamp
// 2. Broadcasts to peer nodes
// 3. Peers merge using CRDT rules
// 4. Conflicts resolved by timestamp (last-write-wins for allocations)
```

### Conflict Resolution

For IP allocations, conflicts are rare due to hashring ownership:

| Scenario | Resolution |
|----------|------------|
| Same IP allocated twice | Impossible - single owner |
| Owner changed during allocation | Retry with new owner |
| Network partition during allocation | Local allocation, merge on recovery |

## Query Routing

### Option A: Any Node (Current Implementation)

Simple load balancing - any Nexus node can serve reads:

```
┌─────────┐     ┌──────────────┐     ┌─────────┐
│   BNG   │────►│ Load Balancer│────►│ Nexus-X │
└─────────┘     └──────────────┘     └─────────┘

Pros:
- Simple deployment
- No client-side routing logic
- All nodes have same data (CLSet)

Cons:
- Writes may proxy to owner (extra hop)
- Slightly higher write latency
```

### Option B: Hashring-Aware (Future Optimization)

Client routes writes directly to owner:

```
┌─────────┐                          ┌─────────┐
│   BNG   │──────────────────────────│ Nexus-1 │ (owner of pool-a)
└─────────┘                          └─────────┘

Flow:
1. BNG receives pool_id in request
2. BNG calculates owner via hashring
3. BNG sends directly to owner
4. No proxy needed

Pros:
- Lower write latency
- Reduced cross-node traffic

Cons:
- BNG needs hashring awareness
- More complex client
```

**Recommendation**: Start with Option A. Add Option B if write latency becomes an issue.

## Partition Handling

### During Partition

```
┌─────────────────────────────────────────────────────────────────┐
│                  Network Partition                               │
│                                                                  │
│  ┌─────────────────┐           │          ┌─────────────────┐   │
│  │  Partition A    │           │          │  Partition B    │   │
│  │                 │           │          │                 │   │
│  │  Nexus-1 ◄────► Nexus-2    │          │    Nexus-3      │   │
│  │                 │           │          │                 │   │
│  │  BNG-1, BNG-2   │           │          │    BNG-3        │   │
│  └─────────────────┘           │          └─────────────────┘   │
│                                │                                 │
└────────────────────────────────┼─────────────────────────────────┘

Partition A:
- Nexus-1 and Nexus-2 continue syncing
- Pools owned by Nexus-1/2: allocations work
- Pools owned by Nexus-3: allocations fail (owner unreachable)

Partition B:
- Nexus-3 operates alone
- Pools owned by Nexus-3: allocations work locally
- Cannot sync with Partition A
```

### BNG Behavior During Partition

| Operation | Behavior |
|-----------|----------|
| DHCP renewal (cached) | Works - uses eBPF cache |
| New allocation (reachable owner) | Works - normal flow |
| New allocation (unreachable owner) | Fails - queue for retry |
| Lookup (any Nexus) | Works - serves from local CLSet |

### Recovery

When partition heals:

```
1. Nexus nodes detect peer recovery
2. CLSet initiates delta sync
3. Allocations made during partition merge
4. Conflicts resolved via vector clocks
5. Bitmap state reconciled (union of allocations)
6. BNG caches refreshed from unified state
```

## API Specification

### Allocation Endpoints

```protobuf
service AllocationService {
  // Allocate IP from pool
  rpc Allocate(AllocateRequest) returns (AllocateResponse);

  // Release allocation
  rpc Release(ReleaseRequest) returns (ReleaseResponse);

  // Lookup by subscriber
  rpc LookupBySubscriber(LookupRequest) returns (LookupResponse);

  // Lookup by IP
  rpc LookupByIP(LookupByIPRequest) returns (LookupResponse);
}

message AllocateRequest {
  string subscriber_id = 1;
  string pool_id = 2;
  string mac = 3;           // Optional for IPv4
  string duid = 4;          // Required for IPv6
  uint32 iaid = 5;          // Required for IPv6
}

message AllocateResponse {
  string ip = 1;            // Allocated IP/prefix
  int32 prefix_length = 2;  // For IPv6 prefixes
  int64 expires_at = 3;     // Unix timestamp
}
```

### Cluster Management

```protobuf
service ClusterService {
  // Join cluster
  rpc Join(JoinRequest) returns (JoinResponse);

  // Get cluster status
  rpc Status(StatusRequest) returns (StatusResponse);

  // Get hashring state
  rpc GetHashring(HashringRequest) returns (HashringResponse);
}
```

## Deployment

### Kubernetes StatefulSet

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: nexus
spec:
  serviceName: nexus
  replicas: 3
  selector:
    matchLabels:
      app: nexus
  template:
    spec:
      containers:
      - name: nexus
        image: ghcr.io/codelaboratoryltd/nexus:latest
        ports:
        - containerPort: 9000  # gRPC
        - containerPort: 9001  # HTTP
        - containerPort: 9002  # CLSet P2P
        env:
        - name: NEXUS_PEER_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: NEXUS_PEERS
          value: "nexus-0.nexus:9002,nexus-1.nexus:9002,nexus-2.nexus:9002"
```

### Configuration

```yaml
# /etc/nexus/config.yaml
cluster:
  peer_id: nexus-0
  peers:
    - nexus-1.nexus:9002
    - nexus-2.nexus:9002

clset:
  namespace: nexus
  sync_interval: 5s
  peer_ttl: 30s

hashring:
  virtual_nodes: 150  # Per physical node
  replication: 0      # Single owner (CRDT handles redundancy)

api:
  grpc_addr: :9000
  http_addr: :9001
```

## Sizing Guidelines

### Node Count

| Deployment Size | Recommended Nodes | Rationale |
|-----------------|-------------------|-----------|
| Small (<10 OLTs) | 3 | Minimum for quorum |
| Medium (10-50 OLTs) | 3-5 | Balance capacity and overhead |
| Large (50+ OLTs) | 5-7 | Higher availability |

### Resource Requirements

| Component | CPU | Memory | Storage |
|-----------|-----|--------|---------|
| Nexus node | 2 cores | 4 GB | 10 GB SSD |
| Per 10K allocations | +0.1 core | +100 MB | +10 MB |
| CLSet sync | +0.5 core | +500 MB | - |

### Performance Targets

| Operation | Target Latency | Throughput |
|-----------|----------------|------------|
| Allocate (local owner) | <10ms | 10,000/sec |
| Allocate (proxy) | <20ms | 5,000/sec |
| Lookup | <5ms | 50,000/sec |
| CLSet sync | <100ms | - |

## Monitoring

### Key Metrics

```prometheus
# Allocation metrics
nexus_allocations_total{pool, result}
nexus_allocation_latency_seconds{pool, quantile}
nexus_pool_utilization{pool}

# Cluster metrics
nexus_cluster_peers_total
nexus_cluster_peer_status{peer}
nexus_hashring_pools{owner}

# CLSet metrics
nexus_clset_sync_latency_seconds
nexus_clset_entries_total
nexus_clset_conflicts_total
```

### Health Checks

```bash
# Cluster health
curl http://nexus:9001/health

# Peer status
curl http://nexus:9001/cluster/status

# Hashring state
curl http://nexus:9001/hashring
```

## Related Documentation

- [Architecture Overview](ARCHITECTURE.md) - System-wide architecture
- [eBPF DHCP Fast Path](ebpf-dhcp-architecture.md) - DHCP acceleration
- [Features Specification](FEATURES.md) - Complete feature list

## Related Issues

- #42 - Dual-indexed allocation store (implemented)
- #43 - Bitmap allocator (implemented)
- #44 - CLSet adapter (implemented)
- #47 - Standalone/WiFi modes (implemented)
