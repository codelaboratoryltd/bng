# Phase 3: Minimal Viable BNG with OLT Integration

Build a complete, demoable BNG showing the full subscriber lifecycle from ONT connection to activation.

---

## Goal

Create a **working end-to-end demonstration** of:
1. ONT auto-discovery and provisioning
2. Zero-touch walled garden access
3. Subscriber activation flow
4. Full internet access after activation
5. Session tracking and metrics

**NOT**: Optimized eBPF fast path (that's Phase 6+)
**IS**: Complete functional BNG you can demo and extend

---

## Architecture: Integrated Monolith

All functions in one binary for simplicity:

```
bng run
  ├── OLT Simulator (mock PON events)
  ├── RADIUS Client (talks to Worf, or stub)
  ├── DHCP Server (pool selection based on state)
  ├── Session Manager (track subscriber lifecycle)
  ├── Walled Garden (firewall rules)
  ├── Activation API (HTTP endpoint for portal)
  ├── RADIUS Accounting (usage tracking)
  └── Metrics (Prometheus + Grafana dashboard)
```

---

## Component Implementation Plan

### 1. OLT Simulator (`pkg/olt/`)

**Purpose**: Simulate ONT discovery and provisioning

**Files:**
- `pkg/olt/simulator.go` - Mock OLT that detects ONTs
- `pkg/olt/types.go` - ONT, Port, VLAN types
- `pkg/olt/events.go` - Event definitions

**Functions:**
```go
type OLTSimulator struct {
    aggregatorID string
    ports        map[string]*Port  // "1/1/1" -> Port
}

// Simulate ONT connection
func (o *OLTSimulator) ConnectONT(ontSerial string, port string) {
    // 1. Detect ONT
    // 2. Emit NewONTDetected event
    // 3. Auto-provision to WGAR VLAN
    // 4. Emit ONTProvisioned event
}

// Simulate reconfiguration (after activation)
func (o *OLTSimulator) ReconfigureONT(ontSerial string, pool string, qos QoS) {
    // 1. Update VLAN assignment
    // 2. Apply QoS policy
    // 3. Emit ONTReconfigured event
}
```

**Events:**
- `NewONTDetected{ONTSerial, Port, AggregatorID}`
- `ONTProvisioned{ONTSerial, VLAN, State}`
- `ONTReconfigured{ONTSerial, NewVLAN, QoS}`
- `ONTDisconnected{ONTSerial}`

---

### 2. Authentication (`pkg/auth/`)

**Purpose**: Zero-touch RADIUS authentication using ONT serial

**Files:**
- `pkg/auth/radius.go` - RADIUS client
- `pkg/auth/stub.go` - In-memory auth (for testing without Worf)

**Functions:**
```go
type RADIUSClient struct {
    server string
    secret string
    state  *state.Store  // Lookup ONT → Pool mapping
}

func (r *RADIUSClient) Authenticate(ontSerial string) (*AuthResponse, error) {
    // Send RADIUS Access-Request
    // Username: ontSerial
    // Password: "" (zero-touch!)
    //
    // Response:
    //   Framed-Pool: wgar | isp-residential | isp-business
    //   Subscriber-Id: SVC-123
    //   QoS attributes
}
```

**Stub implementation (no RADIUS server):**
```go
type StubAuth struct {
    records map[string]*AuthRecord  // ontSerial -> record
}

func (s *StubAuth) Authenticate(ontSerial string) (*AuthResponse, error) {
    // Lookup in memory
    // Return pool assignment
}
```

---

### 3. DHCP Server (`pkg/dhcp/`)

**Purpose**: Deliver pre-allocated IP addresses to subscribers (READ-ONLY)

**Important**: IP allocation happens at RADIUS time using hashring, NOT during DHCP.

**Files:**
- `pkg/dhcp/server.go` - DHCP server
- `pkg/dhcp/pools.go` - Pool metadata (gateway, DNS, lease time)
- `pkg/dhcp/lease.go` - Lease tracking

**Pools (metadata only - allocation is at RADIUS/Nexus level):**
```yaml
pools:
  - name: wgar
    network: 10.255.0.0/16
    gateway: 10.255.0.1
    dns: [8.8.8.8, 8.8.4.4]
    lease_time: 600s  # Short lease for walled garden

  - name: isp-residential
    network: 10.0.0.0/12
    gateway: 10.0.0.1
    dns: [1.1.1.1, 1.0.0.1]
    lease_time: 86400s  # 24 hours

  - name: isp-business
    network: 10.16.0.0/12
    gateway: 10.16.0.1
    dns: [1.1.1.1, 1.0.0.1]
    lease_time: 604800s  # 7 days
```

**Flow (DHCP is read-only - IP already allocated at RADIUS time):**
```go
func (d *DHCPServer) HandleDISCOVER(pkt *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
    // 1. Extract MAC, Option 82 (Circuit-ID)
    mac := pkt.ClientHWAddr
    circuitID := extractCircuitID(pkt)  // "agg-01|1/1/1"

    // 2. Lookup subscriber from Nexus (IP already allocated at RADIUS time)
    subscriber, err := d.nexus.GetSubscriberByMAC(mac)
    if err != nil {
        // Unknown subscriber - send to walled garden
        return d.handleWalledGarden(pkt)
    }

    // 3. Get pre-allocated IP (NO allocation here - just a read!)
    ip := subscriber.AllocatedIP
    if ip == nil {
        // Subscriber authenticated but no IP yet - RADIUS not complete
        return nil, errors.New("subscriber has no allocated IP")
    }

    // 4. Get pool metadata for DHCP options
    pool := d.pools.Get(subscriber.PoolName)

    // 5. Create/update lease tracking
    lease := &Lease{
        MAC:       mac,
        IP:        ip,
        ONTSerial: subscriber.ONTSerial,
        Pool:      subscriber.PoolName,
        CircuitID: circuitID,
        ExpiresAt: time.Now().Add(pool.LeaseTime),
    }
    d.leases.Update(lease)

    // 6. Generate DHCP OFFER with pre-allocated IP
    return generateOffer(pkt, ip, pool), nil
}
```

---

### 4. Session Manager (`pkg/session/`)

**Purpose**: Track subscriber lifecycle state

**Files:**
- `pkg/session/manager.go` - Session tracking
- `pkg/session/types.go` - Session states
- `pkg/session/events.go` - Session events

**Session States:**
```go
type SessionState int

const (
    StateDiscovered  SessionState = iota  // ONT detected
    StateWGAR                              // Walled Garden
    StateActivating                        // Activation in progress
    StateActive                            // Full internet
    StateSuspended                         // Payment failed
    StateTerminated                        // Cancelled
)
```

**Session Tracking:**
```go
type Session struct {
    ONTSerial   string
    MAC         net.HardwareAddr
    IP          net.IP
    CircuitID   string        // "agg-01|1/1/1"
    Pool        string        // "wgar" | "isp-residential"
    ServiceID   string        // Assigned after activation
    State       SessionState
    StartTime   time.Time
    LastSeen    time.Time
    BytesIn     uint64
    BytesOut    uint64
    QoS         QoSPolicy
}

func (s *SessionManager) UpdateState(ontSerial string, newState SessionState) {
    // State machine transitions
    // Emit events
    // Update metrics
}
```

---

### 5. Walled Garden (`pkg/firewall/`)

**Purpose**: Restrict access for non-activated subscribers

**Files:**
- `pkg/firewall/walled_garden.go` - Access control
- `pkg/firewall/whitelist.go` - Allowed destinations

**Implementation:**
```go
type WalledGarden struct {
    sessions  *session.Manager
    whitelist []net.IPNet  // Activation portal, payment gateway
}

func (w *WalledGarden) AllowPacket(src, dst net.IP, dstPort uint16) bool {
    session := w.sessions.GetByIP(src)

    // If not in WGAR, allow everything
    if session.State != session.StateWGAR {
        return true
    }

    // In WGAR: Check whitelist
    // Allow: DNS, DHCP, HTTP/HTTPS to portal
    if dstPort == 53 || dstPort == 67 {
        return true
    }

    for _, allowed := range w.whitelist {
        if allowed.Contains(dst) {
            return true
        }
    }

    return false  // Drop
}
```

**Note**: For demo, just log allow/deny decisions. Full firewall integration is Phase 5.

---

### 6. Activation API (`pkg/activation/`)

**Purpose**: HTTP API for subscriber activation (simulates Portal)

**Files:**
- `pkg/activation/handler.go` - HTTP handlers
- `pkg/activation/client.go` - Client for testing

**Endpoints:**
```go
POST /api/v1/activate
{
  "ont_serial": "ADTN12345678",
  "service_id": "SVC-001",
  "pool": "isp-residential",
  "qos_download_bps": 100000000,
  "qos_upload_bps": 20000000
}

Response:
{
  "status": "success",
  "session": {
    "ont_serial": "ADTN12345678",
    "old_state": "wgar",
    "new_state": "activating",
    "old_ip": "10.255.1.100",
    "message": "Waiting for DHCP renewal"
  }
}
```

**Flow:**
```go
func (a *ActivationHandler) Activate(req *ActivationRequest) error {
    // 1. Lookup session by ONT serial
    session := a.sessions.GetByONT(req.ONTSerial)

    // 2. Validate current state (must be WGAR)
    if session.State != StateWGAR {
        return errors.New("invalid state for activation")
    }

    // 3. Update session state
    session.ServiceID = req.ServiceID
    session.State = StateActivating
    a.sessions.Update(session)

    // 4. Simulate OLT reconfiguration
    a.olt.ReconfigureONT(req.ONTSerial, req.Pool, req.QoS)

    // 5. Update auth record (for next DHCP renewal)
    a.auth.UpdatePool(req.ONTSerial, req.Pool)

    // 6. Emit activation event
    a.events.Publish(SubscriberActivated{
        ONTSerial: req.ONTSerial,
        ServiceID: req.ServiceID,
    })

    return nil
}
```

---

### 7. RADIUS Accounting (`pkg/accounting/`)

**Purpose**: Send usage data to Worf (or stub)

**Files:**
- `pkg/accounting/radius.go` - RADIUS accounting client
- `pkg/accounting/stub.go` - In-memory accounting

**Messages:**
```go
func (a *RADIUSAccounting) SessionStart(session *Session) error {
    // Send Accounting-Start
    // Attributes:
    //   User-Name: session.ONTSerial
    //   Framed-IP-Address: session.IP
    //   ADSL-Agent-Circuit-ID: session.CircuitID
    //   ADSL-Agent-Remote-ID: session.ONTSerial
    //   Acct-Session-Id: <uuid>
}

func (a *RADIUSAccounting) SessionUpdate(session *Session) error {
    // Send Accounting-Interim (every 5 min)
    // Attributes:
    //   Acct-Input-Octets: session.BytesIn
    //   Acct-Output-Octets: session.BytesOut
    //   Acct-Session-Time: time.Since(session.StartTime)
}

func (a *RADIUSAccounting) SessionStop(session *Session, reason string) error {
    // Send Accounting-Stop
    // Attributes:
    //   Acct-Terminate-Cause: reason
    //   Acct-Session-Time: <total>
}
```

---

### 8. Metrics & Observability (`pkg/metrics/`)

**Purpose**: Prometheus metrics for Grafana dashboards

**Metrics:**
```go
// Sessions
bng_sessions_total{state="discovered|wgar|active|suspended"}
bng_session_duration_seconds{state}

// DHCP
bng_dhcp_requests_total{pool="wgar|isp-residential|isp-business"}
bng_dhcp_pool_utilization{pool}
bng_dhcp_pool_available_ips{pool}

// Traffic
bng_traffic_bytes_total{direction="in|out", pool}
bng_traffic_packets_total{direction, pool}

// Activation
bng_activations_total{result="success|failed"}
bng_activation_duration_seconds

// Walled Garden
bng_walled_garden_drops_total{reason="not_whitelisted"}
```

---

## Demo Script

### Automated Demo

```bash
./bng demo --scenario full-lifecycle --subscribers 10

# Simulates:
# 1. 10 ONTs connect over 30 seconds
# 2. Each gets WGAR IP
# 3. After 10s, 7 activate (3 stay in WGAR)
# 4. Activated subs get ISP IPs
# 5. Traffic simulation
# 6. 1 subscriber suspended (payment fail)
# 7. After 60s total, show final metrics
```

**Demo Output:**
```
=== BNG Demo: Full Subscriber Lifecycle ===

[00:00] Starting OLT simulator...
[00:00] Starting BNG services...
[00:02] BNG ready - http://localhost:8080

[00:05] ONT-001 connected on port agg-01|1/1/1
[00:05] ONT-001 provisioned to WGAR
[00:06] ONT-001 DHCP: 10.255.1.1 (wgar pool)
[00:06] ONT-001 session started: WGAR

[00:08] ONT-002 connected on port agg-01|1/1/2
... (8 more ONTs) ...

[00:15] All 10 ONTs connected and in WGAR

[00:20] Activating 7 subscribers...
[00:20] ONT-001 activation requested: SVC-001
[00:20] ONT-001 OLT reconfigured: WGAR → ISP residential
[00:21] ONT-001 DHCP renewed: 10.0.1.1 (isp-residential pool)
[00:21] ONT-001 session active: FULL ACCESS
... (6 more activations) ...

[00:30] 3 subscribers remain in WGAR (not activated)

[00:40] Traffic simulation: 100 MB total

[00:50] ONT-005 suspended: payment failed
[00:50] ONT-005 OLT reconfigured: ISP → WGAR
[00:51] ONT-005 DHCP renewed: 10.255.1.5 (back to wgar)

[01:00] Demo complete!

=== Final Metrics ===
Total ONTs: 10
  - WGAR: 4 (3 never activated + 1 suspended)
  - Active: 6

DHCP Pools:
  - wgar: 4/65535 IPs (0.01%)
  - isp-residential: 6/1048576 IPs (0.0006%)

Traffic:
  - Total: 100 MB
  - Per subscriber (avg): 10 MB

Grafana dashboard: http://localhost:3000/d/bng-overview
```

---

## Grafana Dashboard

**Panels:**
1. **Sessions Over Time** (stacked area)
   - WGAR, Active, Suspended

2. **Pool Utilization** (gauge)
   - WGAR: 0.01%
   - ISP Residential: 0.0006%

3. **Activation Funnel** (funnel chart)
   - 10 ONTs detected
   - 10 provisioned to WGAR
   - 7 activated
   - 6 currently active (1 suspended)

4. **Top Talkers** (table)
   - ONT Serial, IP, Bytes In, Bytes Out

5. **State Distribution** (pie chart)
   - WGAR: 40%
   - Active: 60%

6. **Activation Rate** (stat)
   - 70% activation rate
   - Avg time to activate: 15s

---

## Testing Plan

### Unit Tests
- DHCP pool allocation/deallocation
- Session state machine transitions
- Walled garden allow/deny logic
- RADIUS client (mocked server)

### Integration Tests
- Full flow: ONT connect → WGAR → Activate → Active
- DHCP renewal after activation (pool change)
- Suspension flow (Active → WGAR)
- Multiple concurrent activations

### Load Tests (Phase 4)
- 1000 simultaneous ONT connections
- 1000 DHCP requests/sec
- Session state updates under load

---

## File Structure (Phase 3)

```
pkg/
├── olt/
│   ├── simulator.go      # Mock OLT
│   ├── types.go          # ONT, Port, VLAN
│   └── events.go         # Event definitions
├── auth/
│   ├── radius.go         # RADIUS client
│   └── stub.go           # In-memory auth
├── dhcp/
│   ├── server.go         # DHCP server
│   ├── pools.go          # Pool management
│   └── lease.go          # Lease tracking
├── session/
│   ├── manager.go        # Session tracking
│   ├── types.go          # Session, State
│   └── events.go         # Session events
├── firewall/
│   ├── walled_garden.go  # Access control
│   └── whitelist.go      # Allowed destinations
├── activation/
│   ├── handler.go        # HTTP API
│   └── client.go         # Test client
├── accounting/
│   ├── radius.go         # RADIUS accounting
│   └── stub.go           # In-memory
├── metrics/
│   └── prometheus.go     # Metrics definitions
└── state/
    └── store.go          # In-memory state (→ Nexus Phase 4)

cmd/bng/
├── main.go               # CLI entry
├── run.go                # Main server command
└── demo.go               # Demo scenario command
```

---

## Success Criteria

- [ ] Can simulate 10 ONT connections
- [ ] DHCP allocates IPs from correct pools
- [ ] Session states track correctly (WGAR → Activating → Active)
- [ ] Activation API changes pool assignment
- [ ] DHCP renewal after activation gets new IP
- [ ] Walled garden allow/deny logic works
- [ ] RADIUS accounting messages sent (or logged)
- [ ] Prometheus metrics exported
- [ ] Grafana dashboard shows all data
- [ ] Demo script runs end-to-end
- [ ] Can run in Kubernetes (Tilt)

---

## Timeline

**Week 1**: Core infrastructure
- OLT simulator
- DHCP server with pools
- Session manager
- Basic metrics

**Week 2**: Activation flow
- RADIUS stub
- Activation API
- State transitions
- Walled garden logic

**Week 3**: Demo & polish
- Demo script
- Grafana dashboard
- Integration tests
- Documentation

---

**Next**: Start implementing! Begin with OLT simulator + session manager.
