# BNG Features Specification

Comprehensive feature list for eBPF-accelerated Broadband Network Gateway.

---

## Core BNG Functions

### 1. Subscriber Session Management

**Purpose**: Track and manage subscriber sessions from connection to disconnection.

**Requirements**:
- Unique session identifier per subscriber
- Session state tracking (CONNECTING, AUTHENTICATED, ACTIVE, DISCONNECTING, TERMINATED)
- Session timeout handling (idle timeout, absolute timeout)
- Graceful session termination
- Session persistence across BNG restarts (via state store)
- Concurrent session limits per subscriber
- Session metadata (connection time, data usage, QoS tier)

**Performance Targets**:
- Support 100,000+ concurrent sessions per BNG instance
- Session creation: <10ms
- Session lookup: <100ns (eBPF map)

**Implementation Notes**:
- Session tracking in eBPF map for fast path
- Userspace service for complex session lifecycle
- Integration with RADIUS for session authorization

---

### 2. DHCP Server (DHCPv4)

**Purpose**: Deliver pre-allocated IP addresses to subscribers.

**Important**: IP allocation happens at RADIUS time using hashring, NOT during DHCP. DHCP is a read-only operation.

**Requirements**:

#### Fast Path (eBPF/XDP):
- DHCP DISCOVER → OFFER (lookup pre-allocated IP from eBPF map)
- DHCP REQUEST → ACK (cached leases)
- Lease renewal (in-kernel, no userspace)
- Packet validation and sanitization
- Cache hit rate: >95%

#### Slow Path (Userspace):
- Lookup subscriber's pre-allocated IP from Nexus (read-only)
- NO allocation logic - IP already assigned at RADIUS time
- Update eBPF cache for future fast path hits
- DHCP RELEASE handling
- DHCP DECLINE handling
- Lease expiry tracking (for cache cleanup)
- DHCP relay support (Option 82)

#### IP Pool Management (at RADIUS/Nexus level):
- Hashring-based allocation (deterministic, no conflicts)
- Multiple IP pools (per ISP, per service tier)
- Pool utilization monitoring
- IP address reservation (static IPs)
- Pool exhaustion alerts

**Performance Targets**:
- Fast path: 50,000+ req/sec, <100μs latency
- Slow path: 5,000 req/sec, <10ms latency
- Overall: 50,000+ req/sec (80/20 split)

**DHCP Options Support**:
- Subnet mask (Option 1)
- Router (Option 3)
- DNS servers (Option 6)
- Domain name (Option 15)
- Lease time (Option 51)
- DHCP message type (Option 53)
- Server identifier (Option 54)
- Renewal time (Option 58)
- Rebinding time (Option 59)
- Vendor-specific options (Option 43)

---

### 3. RADIUS Integration

**Purpose**: Authenticate and authorize subscribers, send accounting data.

**Requirements**:

#### Authentication:
- RADIUS Access-Request on new session
- Challenge-response support (if needed)
- Accept/Reject handling
- Return subscriber profile (QoS tier, IP pool, etc.)

#### Authorization:
- Parse RADIUS attributes:
  - Framed-IP-Address (static IP)
  - Session-Timeout
  - Idle-Timeout
  - Filter-Id (QoS policy)
  - Class (subscriber tier)
- Apply returned policies to session

#### Accounting:
- Accounting-Start on session creation
- Interim-Update (periodic usage reports)
- Accounting-Stop on session termination
- Data usage tracking (bytes in/out, packets in/out)
- Session duration tracking

**Performance Targets**:
- RADIUS timeout: 3 seconds
- Retry attempts: 3
- RADIUS server failover (primary/secondary)

**Vendor-Specific Attributes**:
- Support for custom VSAs (configurable)

---

### 4. QoS (Quality of Service)

**Purpose**: Per-subscriber traffic shaping and rate limiting.

**Requirements**:

#### Rate Limiting:
- Per-subscriber download rate limit
- Per-subscriber upload rate limit
- Token bucket algorithm (eBPF implementation)
- Burst allowance configuration
- Tiered rate limits (e.g., 100 Mbps, 500 Mbps, 1 Gbps)

#### Traffic Prioritization:
- Differentiated Services Code Point (DSCP) marking
- Priority queuing (best-effort, low-latency, high-throughput)
- Per-service QoS (e.g., VoIP priority over bulk downloads)

#### Traffic Policing:
- Exceed action (drop, mark, throttle)
- Conform action (forward, mark)

**Performance Targets**:
- QoS enforcement in XDP (kernel fast path)
- No significant latency overhead (<1μs)
- 100,000+ active QoS policies

**Configuration**:
- QoS profiles (YAML config or RADIUS)
- Dynamic policy updates (no session restart)

---

### 5. NAT44 (Carrier-Grade NAT)

**Purpose**: Conserve public IPv4 addresses by sharing them across multiple subscribers.

**Requirements**:

#### Port Allocation:
- Dynamic port allocation (1024-65535)
- Port reservation per subscriber (e.g., 128 ports)
- Port block allocation (contiguous ranges)
- Port exhaustion detection and alerting

#### NAT Session Tracking:
- 5-tuple tracking (src IP, src port, dst IP, dst port, protocol)
- NAT session timeout (configurable per protocol)
- TCP session state tracking
- UDP session timeout (short-lived)
- ICMP translation

#### NAT Pool Management:
- Multiple NAT pools (IPv4 public addresses)
- Pool utilization monitoring
- Subscriber → NAT IP mapping
- Port utilization per NAT IP

#### Protocols:
- TCP NAT
- UDP NAT
- ICMP NAT (Echo Request/Reply)
- Protocol-specific ALGs (Application Layer Gateways):
  - FTP (control + data channels)
  - SIP (VoIP)
  - RTSP (streaming)

**Performance Targets**:
- 1,000,000+ concurrent NAT sessions
- NAT lookup: <100ns (eBPF map)
- NAT translation in XDP (kernel fast path)

**Logging**:
- NAT session creation/deletion logs (for LEA compliance)
- Port allocation logs

---

### 6. Subscriber Authentication

**Purpose**: Verify subscriber identity before granting network access.

**Requirements**:

#### PPPoE (Point-to-Point Protocol over Ethernet):
- PPPoE Discovery (PADI, PADO, PADR, PADS, PADT)
- PPP authentication (PAP, CHAP, MS-CHAPv2)
- RADIUS integration for credential verification
- Session-ID generation and tracking
- AC-Name and Service-Name configuration

**Note**: PPPoE implementation TBD (may use VPP instead of eBPF)

#### IPoE (IP over Ethernet):
- DHCP-based authentication
- MAC address authentication (RADIUS)
- Option 82 (DHCP relay agent) for circuit identification
- No PPP overhead (simpler than PPPoE)

**Performance Targets**:
- PPPoE: 10,000+ sessions/sec establishment
- IPoE: 50,000+ DHCP auth/sec (reuses DHCP fast path)

---

### 7. Traffic Routing

**Purpose**: Route subscriber traffic to/from the internet.

**Requirements**:

#### IPv4 Routing:
- Default gateway for subscribers
- Static routes (configurable)
- Kernel routing table integration
- Route updates without service interruption

#### BGP Integration:
- Advertise NAT pool routes to upstream
- Receive default route from ISP
- BGP session management (via FRR or similar)

#### Routing Policies:
- Policy-based routing (PBR) for multi-homing
- Source-based routing (per subscriber tier)

**Performance Targets**:
- Routing lookups in kernel (standard Linux FIB)
- No additional latency overhead

---

### 8. Logging and Auditing

**Purpose**: Track all subscriber activities for compliance and troubleshooting.

**Requirements**:

#### Session Logs:
- Session start (timestamp, subscriber ID, IP, MAC)
- Session stop (timestamp, duration, data usage)
- Authentication success/failure
- Session termination reason

#### DHCP Logs:
- IP allocation (subscriber, IP, pool, lease time)
- IP release (subscriber, IP)
- DHCP errors (pool exhaustion, invalid requests)

#### NAT Logs:
- NAT session creation (subscriber IP, NAT IP, NAT port, destination)
- NAT session deletion
- Port exhaustion events

#### QoS Logs:
- Policy violations (rate limit exceeded)
- QoS policy changes

**Log Formats**:
- Structured JSON logs
- Syslog integration (RFC 5424)
- Log levels (DEBUG, INFO, WARN, ERROR)

**Log Retention**:
- Configurable retention period (default: 30 days)
- Log rotation and archival

---

### 9. Monitoring and Observability

**Purpose**: Provide real-time visibility into BNG health and performance.

**Requirements**:

#### Prometheus Metrics:
- DHCP request counters (total, fast path, slow path, errors)
- DHCP latency histograms (P50, P95, P99)
- Cache hit rate (fast path vs slow path)
- Active sessions (total, per client class)
- Active leases (total, per pool)
- Pool utilization (percentage)
- NAT sessions (total, per pool)
- NAT port utilization
- QoS policy violations
- Packet counters (RX, TX, dropped)
- Interface statistics

#### Grafana Dashboards:
- BNG overview (sessions, DHCP, NAT, QoS)
- DHCP performance (requests/sec, latency, cache hit rate)
- Pool utilization (per pool, alerts on >80%)
- NAT performance (sessions, port usage)
- QoS statistics (bandwidth usage, violations)
- Error rates and alerts

#### Hubble Integration:
- Network flow observability
- DHCP packet tracing
- NAT session visibility
- Per-subscriber traffic analysis
- XDP verdict tracking (XDP_TX, XDP_PASS, XDP_DROP)

#### Health Checks:
- Liveness probe (/healthz endpoint)
- Readiness probe (/readyz endpoint)
- eBPF program health (attached, maps accessible)
- Interface status (up/down)
- RADIUS connectivity check

**Alerting**:
- Pool utilization >80% (warning), >90% (critical)
- NAT port exhaustion
- High error rate (>5%)
- RADIUS server unavailable
- Interface down
- eBPF program detached

---

### 10. Configuration Management

**Purpose**: Flexible configuration for different deployment scenarios.

**Requirements**:

#### Configuration Sources:
- YAML configuration file (primary)
- Environment variables (overrides)
- Command-line flags (overrides)

#### Hot Reload:
- Configuration changes without restart (SIGHUP)
- Reload without dropping sessions
- Validation before applying changes

#### Configuration Schema:
```yaml
bng:
  interfaces:
    subscriber: eth1  # Subscriber-facing interface
    uplink: eth0      # Internet-facing interface

  dhcp:
    pools:
      - id: residential
        network: 10.0.0.0/16
        gateway: 10.0.0.1
        dns: [8.8.8.8, 8.8.4.4]
        lease_time: 86400
      - id: business
        network: 10.1.0.0/16
        gateway: 10.1.0.1
        dns: [1.1.1.1, 1.0.0.1]
        lease_time: 604800

  radius:
    servers:
      - host: radius1.example.com
        port: 1812
        secret: shared-secret
        timeout: 3s
      - host: radius2.example.com
        port: 1812
        secret: shared-secret
        timeout: 3s

  qos:
    policies:
      - name: residential-100mbps
        download: 100000000  # 100 Mbps
        upload: 20000000     # 20 Mbps
      - name: business-1gbps
        download: 1000000000
        upload: 100000000

  nat:
    pools:
      - pool_id: nat-pool-1
        public_ips:
          - 203.0.113.10
          - 203.0.113.11
        ports_per_subscriber: 128

  logging:
    level: info
    format: json
    output: stdout

  metrics:
    enabled: true
    port: 9090
    path: /metrics
```

---

### 11. Multi-Tenancy (Future)

**Purpose**: Support multiple ISPs or customer segments on single BNG.

**Requirements**:
- Tenant isolation (separate DHCP pools, NAT pools, QoS policies)
- Per-tenant RADIUS servers
- Per-tenant metrics and dashboards
- Tenant-specific configuration

**Note**: Not required for POC, design for future extensibility.

---

### 12. High Availability (Future)

**Purpose**: Ensure BNG service continuity during failures.

**Requirements**:
- Active-standby failover
- Session state synchronization (via CRDT)
- VRRP for gateway failover
- Graceful shutdown (notify subscribers)
- Fast failover (<1 second)

**Note**: Not required for POC, but architecture should support it.

---

## Performance Requirements Summary

| Metric | Target | Notes |
|--------|--------|-------|
| Concurrent Sessions | 100,000+ | Per BNG instance |
| DHCP Throughput | 50,000 req/sec | 80% fast path, 20% slow path |
| DHCP Latency (Fast Path) | <100 μs | P99 |
| DHCP Latency (Slow Path) | <10 ms | P99 |
| NAT Sessions | 1,000,000+ | Concurrent |
| NAT Lookup Latency | <100 ns | eBPF map |
| QoS Policies | 100,000+ | Active |
| Cache Hit Rate | >80% | DHCP fast path |
| Uplink Throughput | 10-40 Gbps | Edge deployment |
| CPU Usage | <50% | At target load |
| Memory Usage | <4 GB | eBPF maps + userspace |

---

## Feature Priority for POC

### Phase 1 (Critical):
- ✅ DHCP Fast Path (eBPF/XDP)
- ✅ DHCP Slow Path (Go userspace)
- ✅ IP Pool Management
- ✅ Basic Session Tracking
- ✅ Prometheus Metrics
- ✅ Hubble Observability

### Phase 2 (Important):
- ⏸ RADIUS Authentication
- ⏸ QoS Rate Limiting
- ⏸ NAT44 (Basic CGNAT)
- ⏸ Logging/Auditing

### Phase 3 (Nice-to-Have):
- ⏳ PPPoE Support (or evaluate VPP)
- ⏳ IPoE Support
- ⏳ Advanced QoS
- ⏳ BGP Integration

### Phase 4 (Future):
- 🔮 Multi-Tenancy
- 🔮 High Availability
- 🔮 DHCPv6
- 🔮 IPv6 Routing

---

## Agent Task Template

When assigning features to agents, use this template:

```markdown
# Task: [Feature Name]

## Objective
[1-sentence description of what needs to be built]

## Requirements
- [Requirement 1]
- [Requirement 2]
- ...

## Performance Targets
- [Metric 1]: [Target]
- [Metric 2]: [Target]

## Implementation Notes
- File locations: [e.g., pkg/dhcp/, bpf/dhcp.c]
- Dependencies: [e.g., cilium/ebpf, insomniacslk/dhcp]
- Integration points: [e.g., eBPF maps, RADIUS client]

## Testing Requirements
- Unit tests for [components]
- Integration test with [scenario]
- Performance test targeting [metric]

## Definition of Done
- [ ] Feature implemented and tested
- [ ] Prometheus metrics added
- [ ] Documentation updated
- [ ] PR merged to main
```

---

**Status**: Feature specification complete
**Last Updated**: 16 Dec 2025
