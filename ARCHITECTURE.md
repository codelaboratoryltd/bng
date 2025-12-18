# OLT-BNG Architecture

## Executive Summary

This document describes the architecture for a **distributed Broadband Network Gateway (BNG)** that runs directly on white-box OLT hardware, eliminating the need for dedicated BNG appliances. The system uses **CLSet** (a CRDT-based distributed database) as its backbone for configuration distribution and state synchronization, enabling offline operation and zero-touch provisioning.

### Traditional vs Our Architecture

```
TRADITIONAL ISP EDGE:
CPE → ONU/ONT → OLT → [BNG Appliance] → Internet
                           ↑
              Dedicated hardware, single point of failure
              Manual configuration, expensive

OUR ARCHITECTURE:
CPE → ONU/ONT → OLT(+BNG) → Internet
                    ↑
       White box running Linux + eBPF
       Self-registers on boot (ZTP)
       Pulls config from CLSet mesh
       Can operate offline
```

## Design Principles

1. **Edge-Native**: Processing happens at the OLT, not in a central location
2. **Offline-First**: OLTs must continue serving subscribers during network partitions
3. **Zero-Touch**: New OLTs self-register and auto-configure via serial number lookup
4. **Cloud-Native**: Declarative configuration, observable
5. **CRDT-Based**: Distributed state with automatic conflict resolution
6. **Multi-Party**: Supports structural separation (NetCo/ISPCo) with subscriber portability

---

## Industry Context: Structural Separation

In many markets, the physical network infrastructure (NetCo) is separated from retail service provision (ISPCo):

```
┌─────────────────────────────────────────────────────────────────┐
│                        NETCO (Network Company)                   │
│                                                                  │
│  Owns and operates:                                             │
│  ├── Fiber infrastructure (ducts, cables)                       │
│  ├── Street cabinets                                            │
│  ├── OLT hardware                                               │
│  ├── PON network (splitters, ONTs)                              │
│  └── Backhaul to handoff points                                 │
│                                                                  │
│  Examples: Openreach (UK), Chorus (NZ), NBN (AU)                │
└─────────────────────────────────────────────────────────────────┘
                              │
                    Wholesale Layer 2/3
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│    ISPCo A      │ │    ISPCo B      │ │    ISPCo C      │
│                 │ │                 │ │                 │
│ Provides:       │ │ Provides:       │ │ Provides:       │
│ ├── Internet    │ │ ├── Internet    │ │ ├── Internet    │
│ ├── IP address  │ │ ├── IP address  │ │ ├── IP address  │
│ ├── RADIUS auth │ │ ├── RADIUS auth │ │ ├── RADIUS auth │
│ ├── QoS policy  │ │ ├── QoS policy  │ │ ├── QoS policy  │
│ └── Billing     │ │ └── Billing     │ │ └── Billing     │
└─────────────────┘ └─────────────────┘ └─────────────────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                    Subscribers can MOVE
                    between ISPs without
                    changing physical connection
```

### Subscriber Portability

A subscriber's physical connection (ONT, VLAN) stays the same when they change ISP:

```
BEFORE (ISP A):
Subscriber → ONT-123 → OLT → VLAN 200:100 → ISP A RADIUS → ISP A IP Pool

AFTER CHURN TO ISP B:
Subscriber → ONT-123 → OLT → VLAN 200:100 → ISP B RADIUS → ISP B IP Pool
                 ↑              ↑
            Same ONT      Same VLAN        Different ISP!
```

### Data Model: Physical vs Service Layer

```
/subscribers/{subscriber-id}/
├── # Physical Layer (NetCo) - STABLE
├── nte_id           # ONT serial (doesn't change)
├── device_id        # Which OLT (doesn't change)
├── vlan             # S-TAG:C-TAG (doesn't change)
├── netco_id         # Which NetCo owns the line
│
├── # Service Layer (ISPCo) - CAN CHANGE
├── ispco_id         # Current ISP
├── radius_realm     # @ispA.com or @ispB.com
├── ip_pool          # ISP's IP pool
├── qos_policy       # ISP's QoS rules
└── service_tier     # Product tier
```

---

## System Components

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLSet Mesh                               │
│              (CRDT - Distributed Configuration & State)          │
│                                                                  │
│  Neelix Server(s)          Neelix Server(s)                     │
│  (Regional POP 1)          (Regional POP 2)                     │
│       ↕ sync                    ↕ sync                          │
└──────────────────────────────────────────────────────────────────┘
        ▲           ▲           ▲           ▲
        │           │           │           │
   ┌────┴───┐  ┌────┴───┐  ┌────┴───┐  ┌────┴───┐
   │ OLT-1  │  │ OLT-2  │  │ OLT-3  │  │ OLT-N  │
   │ Agent  │  │ Agent  │  │ Agent  │  │ Agent  │
   └────────┘  └────────┘  └────────┘  └────────┘
       │            │           │           │
      PON          PON         PON         PON
       │            │           │           │
     ONTs         ONTs        ONTs        ONTs
```

### Multi-ISP Integration

```
┌─────────────────────────────────────────────────────────────────┐
│                      CLSet Mesh (NetCo operated)                 │
│                                                                  │
│  Physical Layer State:              Service Layer State:         │
│  ├── /devices/* (OLTs)             ├── /ispcos/* (ISP configs)  │
│  ├── /discovery/* (ONTs)           ├── /subscribers/*/ispco_id  │
│  ├── /allocations/vlans/*          ├── /allocations/ipv4/*      │
│  └── /netcos/* (NetCo config)      └── /pools/* (per ISP)       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                    │
    ┌───────────────┼───────────────┐
    │               │               │
    ▼               ▼               ▼
┌─────────┐   ┌─────────┐   ┌─────────┐
│ ISP A   │   │ ISP B   │   │ ISP C   │
│ RADIUS  │   │ RADIUS  │   │ RADIUS  │
│ Server  │   │ Server  │   │ Server  │
└─────────┘   └─────────┘   └─────────┘

OLT routes RADIUS requests based on subscriber's ispco_id
```

### Component Responsibilities

| Component | Location | Responsibility |
|-----------|----------|----------------|
| **Neelix Server** | Regional POP | Full CLSet node, bootstrap API, image registry |
| **Neelix Agent** | OLT | CLSet client, local cache, offline operation |
| **OLT-BNG** | OLT | Single binary: PON mgmt, DHCP, NAT, QoS, RADIUS |
| **eBPF Programs** | OLT Kernel | Fast path: packet processing, rate limiting |
| **ISP RADIUS** | ISP POP | Authentication, authorization, accounting |

---

## Neelix Server

The Neelix Server runs at regional POPs (Points of Presence) and provides:

### Bootstrap API

```
POST /api/v1/devices/register
  - Receives OLT registration requests
  - Looks up serial number in device database
  - Returns configuration or "pending approval" status

GET /api/v1/devices/{device-id}/config
  - Returns full device configuration
  - Used for initial bootstrap and config refresh

GET /api/v1/images/{image-name}/manifest
  - Returns OCI image manifest
  - Used by agents to check for updates
```

### CLSet Full Node

- Participates in CRDT mesh as a full node
- Stores complete state for all devices and subscribers
- Handles merge conflicts using CRDT semantics
- Provides query API for management tools

### Image Registry

- Hosts OCI-compatible container images
- OLT-BNG images versioned and signed
- Agents pull images on bootstrap and updates

---

## Neelix Agent (OLT-Side)

The agent runs on each OLT as part of the OLT-BNG binary.

### State Machine

```
┌─────────────┐
│  BOOTSTRAP  │ First boot, no config
└──────┬──────┘
       │ Register with server
       ▼
┌─────────────┐
│  CONNECTED  │ Online, syncing with CLSet mesh
└──────┬──────┘
       │ Network partition
       ▼
┌─────────────┐
│ PARTITIONED │ Offline, using cached state
└──────┬──────┘
       │ Network restored
       ▼
┌─────────────┐
│ RECOVERING  │ Merging local changes with mesh
└──────┬──────┘
       │ Sync complete
       ▼
┌─────────────┐
│  CONNECTED  │
└─────────────┘
```

### Offline Operation

When the OLT loses connectivity to the Neelix Server:

**Continues Working:**
- Existing subscriber sessions (cached in local CLSet)
- DHCP lease renewals (local lease database)
- NAT translations (eBPF maps)
- QoS policies (eBPF maps)
- Anti-spoofing (eBPF maps)

**Degraded:**
- New subscriber authentication (no RADIUS)
- New IP allocations (limited to local pool cache)
- Config updates (queued until reconnect)
- ISP churn (can't validate new ISP)

**CRDT Guarantees:**
- Allocations made offline will merge on reconnect
- Conflicts resolved deterministically
- No data loss

### Local Cache Structure

```
/var/lib/neelix/
├── clset/              # Local CLSet database
│   ├── devices/        # Device configurations
│   ├── subscribers/    # Subscriber state
│   ├── allocations/    # IP/VLAN allocations
│   ├── pools/          # Pool definitions
│   └── ispcos/         # ISP configurations
├── leases/             # DHCP lease persistence
└── state/              # Runtime state
```

---

## OLT-BNG Binary

A single statically-linked binary containing all BNG functionality.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         olt-bng binary                          │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Neelix Agent                           │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────┐  │  │
│  │  │ Bootstrap  │  │  CLSet     │  │  Config Watcher    │  │  │
│  │  │            │  │  Client    │  │                    │  │  │
│  │  └────────────┘  └────────────┘  └────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │     PON      │  │    VLAN     │  │      RADIUS          │  │
│  │   Manager    │  │  Allocator  │  │      Client          │  │
│  │  (Arthur)    │  │ (Lancelot)  │  │  (multi-ISP aware)   │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │    DHCP      │  │    NAT44    │  │        QoS           │  │
│  │   Server     │  │   CGNAT     │  │    Rate Limit        │  │
│  │  (v4 + v6)   │  │             │  │                      │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Anti-Spoof  │  │   Walled    │  │     Subscriber       │  │
│  │              │  │   Garden    │  │      Manager         │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    eBPF Loader                            │  │
│  │   XDP: dhcp_fastpath, nat44, qos_ratelimit               │  │
│  │   TC:  antispoof, walled_garden                          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                 Metrics (Prometheus)                      │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Package Structure

```
pkg/
├── agent/              # Neelix agent (CLSet client, state machine)
│   ├── agent.go        # Main agent logic
│   ├── bootstrap.go    # Device registration
│   ├── clset.go        # CLSet client wrapper
│   ├── cache.go        # Local state cache
│   └── watcher.go      # Config change notifications
│
├── pon/                # PON management (Arthur logic)
│   ├── manager.go      # PON port discovery
│   ├── nte.go          # NTE (ONU/ONT) handling
│   ├── omci.go         # OMCI protocol (GPON)
│   └── gnmi.go         # gNMI protocol (vendor-specific)
│
├── vlan/               # VLAN allocation (Lancelot logic)
│   ├── allocator.go    # S-TAG/C-TAG allocation
│   ├── pool.go         # VLAN pool management
│   └── types.go        # VLAN types
│
├── subscriber/         # Subscriber state management
│   ├── manager.go      # Subscriber lifecycle
│   ├── session.go      # Active session tracking
│   ├── portability.go  # ISP churn handling
│   └── types.go        # Subscriber types
│
├── walled_garden/      # Captive portal / quarantine
│   ├── manager.go      # Walled garden logic
│   ├── portal.go       # HTTP server
│   └── ebpf.go         # eBPF redirect rules
│
├── dhcp/               # DHCP server
├── dhcpv6/             # DHCPv6 server
├── nat/                # NAT44 manager
├── qos/                # QoS manager
├── antispoof/          # Anti-spoofing
├── radius/             # RADIUS client (multi-ISP)
├── ebpf/               # eBPF loader
├── pppoe/              # PPPoE
├── slaac/              # SLAAC/RADVD
└── metrics/            # Prometheus metrics
```

---

## Physical Topology

### Street Cabinet (OLT Location)

```
┌─────────────────────────────────────────────────────────────────┐
│                        STREET CABINET                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                     WHITE BOX OLT                         │  │
│  │                                                           │  │
│  │   PON Ports (GPON/XGS-PON)         Uplink Ports          │  │
│  │   ┌───┐ ┌───┐ ┌───┐ ┌───┐         ┌───────────────┐     │  │
│  │   │ 1 │ │ 2 │ │...│ │16 │         │ 10G/25G SFP+  │     │  │
│  │   └─┬─┘ └─┬─┘ └─┬─┘ └─┬─┘         └───────┬───────┘     │  │
│  └─────┼─────┼─────┼─────┼───────────────────┼──────────────┘  │
│        │     │     │     │                   │                  │
└────────┼─────┼─────┼─────┼───────────────────┼──────────────────┘
         │     │     │     │                   │
    To Splitters (1:32/1:64)            BACKHAUL FIBER
         │     │     │     │                   │
    ┌────┴─────┴─────┴─────┴────┐              │
    │        ONTs/ONUs          │              │
    │    (Customer Premises)    │              │
    └───────────────────────────┘              │
                                               │
                                               ▼
                              ┌────────────────────────────────┐
                              │      AGGREGATION SITE          │
                              │      (Exchange/CO/POP)         │
                              │                                │
                              │  ┌──────────────────────────┐ │
                              │  │   Aggregation Switch     │ │
                              │  └────────────┬─────────────┘ │
                              │               │               │
                              │  ┌────────────┴─────────────┐ │
                              │  │     Neelix Server        │ │
                              │  │   (NetCo operated)       │ │
                              │  └────────────┬─────────────┘ │
                              │               │               │
                              │  ┌────────────┴─────────────┐ │
                              │  │      Core Router         │ │
                              │  └────────────┬─────────────┘ │
                              └───────────────┼───────────────┘
                                              │
                      ┌───────────────────────┼───────────────────────┐
                      ▼                       ▼                       ▼
               ┌───────────┐           ┌───────────┐           ┌───────────┐
               │  ISP A    │           │  ISP B    │           │  ISP C    │
               │  Network  │           │  Network  │           │  Network  │
               └───────────┘           └───────────┘           └───────────┘
```

### Backhaul Network Planes

```
BACKHAUL FIBER (OLT → Aggregation)
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  VLAN 100: Management Plane (NetCo)                        │
│  ├── OLT ↔ Neelix Server (CLSet sync, gRPC)               │
│  ├── OLT ↔ Registry (OCI image pull)                       │
│  └── OLT ↔ Prometheus (metrics scrape)                     │
│                                                             │
│  VLAN 101-199: ISP Control Planes                          │
│  ├── VLAN 101: ISP A RADIUS                                │
│  ├── VLAN 102: ISP B RADIUS                                │
│  └── VLAN 103: ISP C RADIUS                                │
│                                                             │
│  VLAN 200-4094: Subscriber Plane (S-VLANs)                 │
│  ├── Each subscriber gets unique S-TAG:C-TAG pair          │
│  ├── Traffic tagged and forwarded based on ISP             │
│  └── QoS applied at OLT before backhaul                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## CLSet Data Schema

### Key Hierarchy

```
/
├── netcos/
│   └── {netco-id}/
│       ├── name                # "Openreach", "Chorus", etc.
│       └── config              # NetCo-wide settings
│
├── ispcos/
│   └── {ispco-id}/
│       ├── name                # "ISP A", "ISP B"
│       ├── radius/
│       │   ├── servers         # ["10.0.0.10:1812"]
│       │   ├── secret_ref      # Vault reference
│       │   └── realm           # "@ispa.com"
│       ├── pools/
│       │   ├── ipv4            # ["ispa-cgnat", "ispa-public"]
│       │   └── ipv6            # ["ispa-v6"]
│       └── qos_policies/       # ISP-specific QoS templates
│
├── devices/
│   └── {device-id}/
│       ├── status              # "booting" | "ready" | "offline"
│       ├── config              # Full device configuration
│       ├── image               # Current running image version
│       ├── last_seen           # Timestamp (heartbeat)
│       ├── serial              # Hardware serial number
│       └── netco_id            # Which NetCo owns this OLT
│
├── subscribers/
│   └── {subscriber-id}/
│       ├── # Physical (NetCo) - stable
│       ├── nte_id              # ONT serial
│       ├── device_id           # Which OLT
│       ├── vlan                # S-TAG:C-TAG
│       ├── netco_id            # Which NetCo
│       │
│       ├── # Service (ISPCo) - can change
│       ├── ispco_id            # Current ISP
│       ├── radius_realm        # @ispa.com
│       ├── service_tier        # "premium"
│       ├── qos_policy          # Reference to QoS
│       │
│       ├── # Session state
│       ├── session             # Active session
│       ├── mac                 # Current MAC
│       ├── ipv4                # Assigned IPv4
│       └── ipv6_prefix         # Assigned IPv6
│
├── allocations/
│   ├── ipv4/{pool}/{ip}        # → subscriber-id
│   ├── ipv6/{pool}/{prefix}    # → subscriber-id
│   └── vlans/{s-tag}:{c-tag}   # → subscriber-id
│
├── pools/
│   └── {pool-name}/
│       ├── type                # "ipv4" | "ipv6" | "vlan"
│       ├── range               # CIDR or tag range
│       ├── owner               # netco_id or ispco_id
│       └── device_filter       # Which OLTs can allocate
│
├── discovery/
│   └── {device-id}/ntes/{nte-serial}/
│       ├── port                # PON port number
│       ├── status              # "discovered" | "provisioned"
│       ├── vendor              # ONU vendor
│       └── model               # ONU model
│
└── registry/images/{image-name}/
    ├── latest                  # Latest version
    └── manifest                # OCI manifest
```

---

## Bootstrap Flow (Zero-Touch Provisioning)

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. OLT HARDWARE BOOT                                            │
│    ├── Linux kernel boots                                      │
│    └── systemd starts olt-bng.service                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. BOOTSTRAP PHASE                                              │
│    ├── Read serial from DMI/SMBIOS                             │
│    ├── Get IP via DHCP on management VLAN                      │
│    └── Resolve Neelix server                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. REGISTRATION                                                 │
│    POST /api/v1/devices/register                                │
│    { serial, mac, model, capabilities }                         │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│ KNOWN DEVICE            │     │ UNKNOWN DEVICE          │
│ → Return config         │     │ → Return "pending"      │
│ → Continue              │     │ → Await approval        │
└─────────────────────────┘     └─────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. JOIN CLSET MESH                                              │
│    ├── Connect to CLSet peers                                   │
│    ├── Sync local cache                                        │
│    ├── Subscribe to config changes                             │
│    └── Start heartbeat                                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. SERVICE INITIALIZATION                                       │
│    ├── Load eBPF programs                                      │
│    ├── Initialize DHCP, NAT, QoS                               │
│    ├── Configure RADIUS for each ISP                           │
│    ├── Start PON manager                                       │
│    └── Update status = "ready"                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Subscriber Flows

### New Subscriber Connection

```
1. ONT CONNECTS TO PON
   └── PON Manager detects new ONU

2. NTE DISCOVERY
   ├── Read ONU serial via OMCI
   ├── Store in CLSet: /discovery/{device}/ntes/{serial}
   └── Known? → Load config, Unknown? → Walled Garden

3. VLAN ALLOCATION (NetCo)
   ├── Allocate S-TAG:C-TAG
   └── Configure ONU port

4. DHCP REQUEST
   ├── Lookup subscriber → get ispco_id
   └── Route to ISP handling

5. RADIUS AUTH (ISP-specific)
   ├── Load ISP config
   ├── Send to ISP's RADIUS
   └── Get Accept + attributes

6. IP ALLOCATION (ISP pool)
   ├── Allocate from ISP's range
   └── Store in CLSet

7. SESSION ESTABLISHMENT
   ├── Update CLSet
   ├── Program eBPF maps
   ├── Send DHCP Ack
   └── RADIUS Accounting-Start
```

### ISP Churn

```
1. DETECT CHANGE
   └── CLSet watch: ispco_id changed

2. TEARDOWN OLD SESSION
   ├── RADIUS Accounting-Stop to old ISP
   ├── Release old IP allocation
   ├── Clear eBPF maps
   └── Disconnect CPE

3. ESTABLISH NEW SESSION
   ├── CPE sends new DHCP
   ├── Route RADIUS to new ISP
   ├── Allocate from new ISP pool
   ├── Apply new QoS policy
   └── Subscriber online with new ISP

NOTE: Physical layer unchanged!
      Same ONT, same port, same VLAN
```

---

## Walled Garden

Unknown/unauthenticated devices are quarantined:
- Allow DNS + HTTP to captive portal
- Redirect all other traffic
- Display registration page

```c
// eBPF: walled_garden.c
SEC("tc")
int walled_garden(struct __sk_buff *skb) {
    struct subscriber_info *sub = lookup_by_mac(skb);

    if (!sub || !sub->authenticated) {
        if (is_dns(skb) || is_to_portal(skb))
            return TC_ACT_OK;
        if (is_http(skb))
            return redirect_to_portal(skb);
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}
```

---

## Metrics

```
# Device
olt_bng_device_status{device_id, netco_id} 1
olt_bng_clset_connected 1

# Per-ISP
olt_bng_subscribers_total{ispco_id, state} 200
olt_bng_dhcp_leases_active{ispco_id, pool} 150
olt_bng_nat_translations{ispco_id} 15000

# PON
olt_bng_pon_ntes_active{port} 32

# QoS
olt_bng_qos_packets_passed{ispco_id} 1000000
olt_bng_qos_packets_dropped{ispco_id} 5000
```

---

## Security

### Multi-Party Isolation
- ISP RADIUS secrets never shared
- IP pools isolated per ISP
- Subscriber data partitioned
- NetCo: physical layer only
- ISPCo: service layer only

### eBPF
- Kernel-verified before loading
- Maps isolated per-program

### Network
- Management on separate VLAN
- TLS for CLSet/API
- Secrets in vault

---

## Glossary

| Term | Definition |
|------|------------|
| **BNG** | Broadband Network Gateway |
| **CLSet** | CRDT-based distributed database |
| **CGNAT** | Carrier-Grade NAT |
| **CPE** | Customer Premises Equipment |
| **C-TAG** | Customer VLAN tag (inner) |
| **GPON** | Gigabit Passive Optical Network |
| **ISPCo** | Internet Service Provider Company |
| **NetCo** | Network Company (infrastructure) |
| **NTE** | Network Terminating Equipment |
| **OLT** | Optical Line Terminal |
| **ONU/ONT** | Optical Network Unit/Terminal |
| **PON** | Passive Optical Network |
| **S-TAG** | Service VLAN tag (outer) |
| **XDP** | eXpress Data Path |
| **ZTP** | Zero-Touch Provisioning |
