# BNG Architecture - OLT Edge Deployment

Complete Broadband Network Gateway for FTTH/OLT deployments with zero-touch activation.

---

## Real-World Context: ISP Fiber Deployment

This BNG is designed to run at the **OLT (Optical Line Terminal)** in a fiber-to-the-home (FTTH) deployment.

### The Problem

When a subscriber's **ONT (Optical Network Terminal)** is connected to fiber:
1. ISP doesn't know who the subscriber is yet
2. Subscriber needs internet to access activation portal
3. Can't give full internet before payment/activation
4. Need zero-touch activation (no manual config)

### The Solution: Walled Garden + One-Touch Activation

```
ONT connects → Auto-provision → Walled Garden → Activate → Full Internet
```

---

## Complete Subscriber Lifecycle

### 1. ONT Discovery & Auto-Provisioning

**OLT detects new ONT:**
```
Physical fiber connection
    ↓
OLT/Aggregator detects ONT (via NETCONF/gNMI/SNMP)
    ↓
Arthur (OLT Manager) provisions ONT to Walled Garden (WGAR)
    ↓
Worf (RADIUS) creates auth record using ONT serial number
    (Zero-touch: No password needed!)
```

**Key insight**: Subscriber doesn't configure anything. ONT serial number is the identifier.

---

### 2. Initial Network Access (Walled Garden)

**Subscriber boots up:**
```
ONT/CPE sends DHCP DISCOVER
    ↓
DHCP Option 82 added by OLT:
  Circuit-ID: <aggregator-id>|<port-id>
  (This tells us WHERE subscriber is in the network)
    ↓
BNG DHCP allocates IP from Walled Garden pool
    ↓
BNG sends RADIUS Accounting-Start to Worf
  Attributes:
  - ADSL-Agent-Circuit-ID (aggregator|port)
  - ADSL-Agent-Remote-ID (ONT serial)
  - Framed-IP-Address (allocated IP)
    ↓
Worf maps: IP → ONT serial → Network location
```

**Subscriber now has internet... but limited:**
- ✅ Can access activation portal
- ✅ Can access payment pages
- ❌ Can't access other sites (firewall/routing rules)

---

### 3. Activation Flow

**Subscriber visits activation portal:**
```
Subscriber browses web → HTTP redirect to portal
    ↓
Portal shows activation page
    ↓
Subscriber enters details, pays
    ↓
Portal sends: SubscriberLineOrderPlacedRequest
  Identifies subscriber by: IP address OR ONT serial
  Contains: ServiceID, Tenancy (ISP pool), QoS tier
    ↓
Worf looks up subscriber record
    ↓
Worf emits: ModifySubscriberLine event
    ↓
Arthur reconfigures ONT on OLT
  - Moves from WGAR VLAN to ISP VLAN
  - Applies QoS policy
  - Updates Framed-Pool for DHCP
    ↓
Arthur emits: SubscriberLineProvisioningSuccess
    ↓
Worf updates auth record with ServiceID
```

**Subscriber is now activated!**

---

### 4. Full Network Access

**DHCP renewal after activation:**
```
CPE DHCP renewal
    ↓
RADIUS auth request with ONT serial
    ↓
Worf responds with:
  - Framed-Pool: <isp-pool-name>
  - Alcatel-Subscriber-Id-String: <service-id>
  - QoS attributes
    ↓
BNG DHCP allocates IP from ISP pool
    ↓
Subscriber gets new IP address
    ↓
Full internet access enabled
```

**Session tracking:**
```
RADIUS Accounting-Start → Session begins
RADIUS Accounting-Interim → Usage updates (every 5 min)
RADIUS Accounting-Stop → Session ends
```

---

## Vitrifi Component Mapping

| Component | Purpose | BNG Integration |
|-----------|---------|-----------------|
| **Arthur** | OLT/Aggregator manager, discovers ONTs, provisions VLANs/QoS | ✅ Simulated: Mock OLT events |
| **Worf** | RADIUS AAA server, zero-touch auth, session tracking | ✅ Integrated: RADIUS client |
| **Brushtail** | DHCP server | ✅ Integrated: DHCP with pool selection |
| **Neelix** | CRDT state management | ⏳ Phase 4: Replace in-memory state |

---

## BNG Core Functions (Demo Implementation)

### 1. OLT Integration (Simulated)

**Events from OLT:**
- `NewONTDetected` → Auto-provision to WGAR
- `ONTConfigured` → VLAN assigned, ready for DHCP
- `ONTDisconnected` → Clean up session

**Implementation:**
```go
// pkg/olt/simulator.go
type OLTSimulator struct {
    // Simulate Adtran/Ciena/Nokia OLT
}

func (o *OLTSimulator) SimulateONTConnection(ontSerial string) {
    // Emit NewONTDetected event
    // Auto-provision to WGAR
}
```

---

### 2. Zero-Touch Authentication

**RADIUS Auth:**
```
Username: <ONT-serial-number>
Password: <empty or any>  # Zero-touch!

Response (if known):
  Access-Accept
  Framed-Pool: wgar  # Or isp-pool after activation
  Subscriber-Id: <service-id>
```

**Implementation:**
```go
// pkg/auth/radius.go
func (r *RADIUSAuth) Authenticate(ontSerial string) (pool string, err error) {
    // Lookup ONT in state store
    // Return assigned pool (wgar or isp-pool)
}
```

---

### 3. DHCP with Pool Selection

**Pools:**
- `wgar`: Walled Garden (10.255.0.0/16)
- `isp-residential`: Residential service (10.0.0.0/12)
- `isp-business`: Business service (10.16.0.0/12)

**Implementation:**
```go
// pkg/dhcp/server.go
func (d *DHCPServer) AllocateIP(mac, ontSerial string) (net.IP, error) {
    // 1. RADIUS auth → get pool name
    // 2. Allocate IP from pool
    // 3. Store lease with ONT serial, Circuit-ID
    // 4. Send RADIUS Accounting-Start
}
```

---

### 4. Session Management

**Session States:**
```
DISCOVERED     → ONT detected, not configured yet
WGAR           → In Walled Garden, waiting for activation
ACTIVATING     → Activation in progress
ACTIVE         → Full internet access
SUSPENDED      → Payment failed, back to WGAR
TERMINATED     → Service cancelled
```

**Implementation:**
```go
// pkg/session/manager.go
type SessionManager struct {
    sessions map[string]*Session  # keyed by ONT serial
}

type Session struct {
    ONTSerial   string
    State       SessionState
    IP          net.IP
    Pool        string
    ServiceID   string
    StartTime   time.Time
    BytesIn     uint64
    BytesOut    uint64
}
```

---

### 5. Walled Garden Enforcement

**Firewall Rules:**
```
Allow:
- DNS (to any)
- DHCP (to BNG)
- HTTP/HTTPS to activation portal
- Payment gateway IPs

Deny:
- Everything else
```

**Implementation:**
```go
// pkg/firewall/walled_garden.go
func (w *WalledGarden) Allow(src net.IP, dst net.IP, port uint16) bool {
    session := w.getSession(src)
    if session.State != WGAR {
        return true  // Full access
    }

    // Check whitelist
    return w.isWhitelisted(dst, port)
}
```

---

### 6. Activation API

**Portal Integration:**
```http
POST /api/v1/activate
{
  "ont_serial": "ADTN12345678",
  "service_id": "SVC-001",
  "pool": "isp-residential",
  "qos_download": 100000000,
  "qos_upload": 20000000
}
```

**Implementation:**
```go
// pkg/activation/handler.go
func (a *ActivationHandler) Activate(ontSerial, serviceID string) error {
    // 1. Lookup session by ONT serial
    // 2. Update session: WGAR → ACTIVATING
    // 3. Emit OLT config event (simulated)
    // 4. Wait for DHCP renewal
    // 5. Update session: ACTIVATING → ACTIVE
}
```

---

### 7. RADIUS Accounting

**Messages sent to Worf:**
```
Accounting-Start:
  User-Name: <ONT-serial>
  Framed-IP-Address: 10.255.1.100
  ADSL-Agent-Circuit-ID: agg-01|1/1/1
  ADSL-Agent-Remote-ID: ADTN12345678
  Acct-Session-Id: <unique>

Accounting-Interim (every 5 min):
  Acct-Input-Octets: 1234567
  Acct-Output-Octets: 7654321

Accounting-Stop:
  Acct-Session-Time: 3600
  Acct-Terminate-Cause: User-Request
```

**Implementation:**
```go
// pkg/accounting/radius.go
func (a *RADIUSAccounting) SessionStart(session *Session) error {
    // Send Accounting-Start with Circuit-ID
    // Worf will map IP → ONT serial → location
}
```

---

## Demo Flow

### Simulated Scenario

**Simulate 10 subscribers activating:**

```bash
./bng demo --subscribers 10

# Output:
# [ONT-001] Detected on OLT port agg-01|1/1/1
# [ONT-001] Provisioned to WGAR
# [ONT-001] DHCP allocated: 10.255.1.1
# [ONT-001] Session started: WGAR
# [ONT-001] Activation portal accessed
# [ONT-001] Activation completed → ISP pool
# [ONT-001] DHCP renewed: 10.0.1.1
# [ONT-001] Session active: FULL ACCESS
# ...
# [ONT-010] Session active: FULL ACCESS
#
# Summary:
# - 10 ONTs discovered
# - 10 sessions in ACTIVE state
# - 5 in wgar pool, 5 in isp-residential pool
# - Total traffic: 1.2 GB
```

### Grafana Dashboard Shows:

- Active sessions: 10
- WGAR subscribers: 5 (waiting activation)
- ISP subscribers: 5 (activated)
- IP pool utilization: WGAR 5%, ISP 0.05%
- Top talkers by bandwidth
- Session state distribution (pie chart)

---

## Integration Points (Future)

### Phase 4: Real Vitrifi Integration

Replace simulated components with real services:

| Component | Current (Demo) | Phase 4 (Real) |
|-----------|---------------|----------------|
| OLT Manager | `pkg/olt/simulator.go` | **Arthur** client (NATS events) |
| RADIUS | Built-in client | **Worf** integration (NATS + RADIUS) |
| DHCP | Built-in server | **Brushtail** client |
| State Store | In-memory map | **Neelix** CRDT |
| Config | YAML file | Portal API / NATS events |

**NATS Event Bus:**
```
BNG subscribes to:
- NewCircuitProvisionedPayload (from Arthur)
- SubscriberLineProvisioningSuccessPayload (from Arthur)

BNG publishes:
- SubscriberLineActivatedPayload (session goes live)
- DHCPLeaseAssignedPayload (IP allocated)
- AccountingUpdatePayload (usage stats)
```

---

## Why This Matters

### For Job Interviews

> "I built a complete BNG with zero-touch activation for fiber deployments. It handles the full lifecycle: ONT discovery, walled garden provisioning, subscriber activation, and session tracking - just like real ISP deployments."

### For Brandon Conversation

> "I implemented the subscriber activation flow that Vitrifi uses - walled garden, RADIUS AAA, DHCP pool selection based on service tier. Now I want to explore where eBPF/VPP optimization makes sense in this flow."

### For Portfolio

- **Real ISP use case**: Not just DHCP, full subscriber lifecycle
- **Event-driven architecture**: NATS event bus, microservices-ready
- **Production patterns**: RADIUS AAA, session tracking, metrics
- **Cloud-native**: Kubernetes deployment, Cilium CNI, Hubble observability

---

## References

- Vitrifi Worf: RADIUS AAA with zero-touch activation
- Vitrifi Arthur: OLT management and auto-provisioning
- Vitrifi Brushtail: DHCP server with pool selection
- RFC 2865: RADIUS
- RFC 2131: DHCP
- RFC 3046: DHCP Option 82 (Relay Agent Information)

---

**Author**: Mark Gascoyne
**Date**: 16 Dec 2025
**Status**: Architecture design for Phase 3 implementation
