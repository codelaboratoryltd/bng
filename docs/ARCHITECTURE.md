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
│  Nexus Server(s)          Nexus Server(s)                     │
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
| **Nexus Server** | Regional POP | Full CLSet node, bootstrap API, image registry |
| **Nexus Agent** | OLT | CLSet client, local cache, offline operation |
| **OLT-BNG** | OLT | Single binary: PON mgmt, DHCP, NAT, QoS, RADIUS |
| **eBPF Programs** | OLT Kernel | Fast path: packet processing, rate limiting |
| **ISP RADIUS** | ISP POP | Authentication, authorization, accounting |

---

## Nexus Server

The Nexus Server runs at regional POPs (Points of Presence) and provides:

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

## Nexus Agent (OLT-Side)

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

When the OLT loses connectivity to the Nexus Server:

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
/var/lib/nexus/
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
│  │                    Nexus Agent                           │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────┐  │  │
│  │  │ Bootstrap  │  │  CLSet     │  │  Config Watcher    │  │  │
│  │  │            │  │  Client    │  │                    │  │  │
│  │  └────────────┘  └────────────┘  └────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │     PON      │  │    VLAN     │  │      RADIUS          │  │
│  │   Manager    │  │  Allocator  │  │      Client          │  │
│  │              │  │             │  │  (multi-ISP aware)   │  │
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
├── agent/              # Nexus agent (CLSet client, state machine)
│   ├── agent.go        # Main agent logic
│   ├── bootstrap.go    # Device registration
│   ├── clset.go        # CLSet client wrapper
│   ├── cache.go        # Local state cache
│   └── watcher.go      # Config change notifications
│
├── pon/                # PON management
│   ├── manager.go      # PON port discovery
│   ├── nte.go          # NTE (ONU/ONT) handling
│   ├── omci.go         # OMCI protocol (GPON)
│   └── gnmi.go         # gNMI protocol (vendor-specific)
│
├── vlan/               # VLAN allocation
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
                              │  │     Nexus Server        │ │
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
│  ├── OLT ↔ Nexus Server (CLSet sync, gRPC)               │
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
│    └── Resolve Nexus server                                   │
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

### Complete ZTP Flow: ONT Installation to Internet Access

This is the full zero-touch provisioning flow from physical installation to customer internet access.

#### Phase 1: ONT Discovery (New ONT Connected)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. TECHNICIAN INSTALLS ONT AT CUSTOMER PREMISES                              │
│                                                                              │
│    - Fiber patched to ONT                                                   │
│    - ONT powered on                                                          │
│    - ONT sends PLOAM upstream to OLT                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. OLT-BNG DETECTS NEW ONT                                                   │
│                                                                              │
│    PON Manager detects ONU via OMCI/PLOAM                                   │
│    Reads ONT serial number: "ADTN-12345678"                                 │
│                                                                              │
│    Stores discovery event in CLSet:                                          │
│    /discovery/{device-id}/ntes/ADTN-12345678/                               │
│    {                                                                         │
│      "port": "1/1/3",                                                       │
│      "status": "discovered",                                                │
│      "vendor": "ADTRAN",                                                    │
│      "model": "SDX-621",                                                    │
│      "first_seen": "2025-12-19T10:30:00Z"                                   │
│    }                                                                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. OLT-BNG CHECKS IF ONT IS KNOWN                                            │
│                                                                              │
│    Lookup in local Nexus cache:                                             │
│    /subscribers/*/nte_id == "ADTN-12345678"                                 │
│                                                                              │
│    Result: NOT FOUND (new installation)                                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. ONT PROVISIONED TO WALLED GARDEN                                          │
│                                                                              │
│    OLT-BNG auto-provisions ONT:                                             │
│    - Allocates temporary S-TAG:C-TAG (e.g., 4000:100)                       │
│    - Configures ONT port via OMCI                                           │
│    - Adds MAC to walled garden eBPF map                                     │
│                                                                              │
│    Walled Garden allows:                                                     │
│    - DNS (to resolve captive portal)                                        │
│    - DHCP (to get walled garden IP)                                         │
│    - HTTP/HTTPS to activation portal only                                   │
│    - Everything else blocked/redirected                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Phase 2: Customer Gets Walled Garden Access

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. CUSTOMER DEVICE SENDS DHCP DISCOVER                                       │
│                                                                              │
│    Customer plugs in router/device                                          │
│    Device broadcasts DHCP DISCOVER                                          │
│                                                                              │
│    eBPF/XDP receives packet:                                                │
│    - Lookup MAC in subscriber map → MISS                                    │
│    - Check walled garden map → HIT (MAC is in WGAR)                         │
│    - Pass to userspace (slow path)                                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 6. DHCP SERVER ASSIGNS WALLED GARDEN IP                                      │
│                                                                              │
│    Userspace DHCP server:                                                   │
│    - Sees MAC is in walled garden state                                     │
│    - Allocates IP from WGAR pool: 10.255.1.50                               │
│    - Short lease time (10 minutes)                                          │
│    - DNS points to captive portal resolver                                  │
│                                                                              │
│    Customer device now has IP: 10.255.1.50                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 7. CUSTOMER REDIRECTED TO CAPTIVE PORTAL                                     │
│                                                                              │
│    Customer opens browser → http://google.com                               │
│                                                                              │
│    eBPF walled garden rules:                                                │
│    - HTTP request intercepted                                               │
│    - Redirected to: https://activate.netco.example/                         │
│                                                                              │
│    Customer sees activation portal:                                          │
│    ┌─────────────────────────────────────────────────┐                      │
│    │  Welcome! Your connection is ready.             │                      │
│    │                                                 │                      │
│    │  Choose your Internet provider:                 │                      │
│    │  ○ ISP-A  (100Mbps from $49/mo)                │                      │
│    │  ○ ISP-B  (500Mbps from $79/mo)                │                      │
│    │  ○ ISP-C  (1Gbps from $99/mo)                  │                      │
│    │                                                 │                      │
│    │  [Sign Up Now]                                  │                      │
│    └─────────────────────────────────────────────────┘                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Phase 3: Customer Signs Up with ISP

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 8. CUSTOMER COMPLETES SIGN-UP                                                │
│                                                                              │
│    Customer selects ISP-A, enters payment details                           │
│    ISP-A's BSS/OSS creates subscriber record                                │
│                                                                              │
│    ISP-A provisions subscriber via Nexus API:                               │
│    POST /api/v1/subscribers                                                 │
│    {                                                                         │
│      "subscriber_id": "SUB-2024-999",                                       │
│      "nte_id": "ADTN-12345678",           ← Links to discovered ONT        │
│      "ispco_id": "ISP-A",                                                   │
│      "service_tier": "residential-100",                                     │
│      "qos_download": 100000000,           ← 100 Mbps                        │
│      "qos_upload": 20000000               ← 20 Mbps                         │
│    }                                                                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 9. SUBSCRIBER RECORD SYNCS VIA CLSET                                         │
│                                                                              │
│    Nexus Server receives new subscriber                                      │
│    CLSet propagates to all OLT-BNGs                                         │
│                                                                              │
│    OLT-BNG receives sync:                                                    │
│    - Matches nte_id to discovered ONT                                        │
│    - Updates local cache                                                     │
│    - ONT now has associated subscriber                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Phase 4: RADIUS Authentication & IP Allocation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 10. OLT-BNG TRIGGERS AUTHENTICATION                                          │
│                                                                              │
│    OLT-BNG sees subscriber now provisioned                                  │
│    Initiates RADIUS Access-Request to ISP-A:                                │
│                                                                              │
│    RADIUS Access-Request:                                                   │
│    - User-Name: "ADTN-12345678@ispa.com"                                   │
│    - NAS-Identifier: "OLT-2024-ABC123"                                      │
│    - NAS-Port-Id: "1/1/3"                                                   │
│    - Calling-Station-Id: "aa:bb:cc:dd:ee:ff" (CPE MAC)                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 11. ISP-A RADIUS AUTHENTICATES                                               │
│                                                                              │
│    ISP-A RADIUS server:                                                     │
│    - Validates subscriber exists and is active                              │
│    - Checks payment status: OK                                              │
│                                                                              │
│    RADIUS Access-Accept:                                                    │
│    - Framed-Pool: "ispa-residential"                                        │
│    - Filter-Id: "100M-down-20M-up"                                          │
│    - Session-Timeout: 86400                                                 │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 12. IP ALLOCATED FROM HASHRING (at RADIUS time)                              │
│                                                                              │
│    OLT-BNG allocates IP from ISP-A's pool via Nexus hashring:              │
│                                                                              │
│    Hashring lookup:                                                          │
│    - Pool: "ispa-residential" (100.64.0.0/22)                               │
│    - Subscriber hash position → deterministic IP                            │
│    - IP allocated: 100.64.1.42                                              │
│                                                                              │
│    Subscriber record updated in CLSet:                                       │
│    /subscribers/SUB-2024-999/                                               │
│    {                                                                         │
│      "ipv4": "100.64.1.42",           ← IP now assigned                    │
│      "session_state": "authenticated",                                       │
│      "authenticated_at": "2025-12-19T10:35:00Z"                             │
│    }                                                                         │
│                                                                              │
│    eBPF maps updated:                                                        │
│    - subscriber_pools[MAC] = { ip: 100.64.1.42, pool: ispa-res, ... }       │
│    - MAC removed from walled garden map                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Phase 5: Customer Gets Real IP & Internet Access

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 13. DHCP LEASE EXPIRES / RENEW TRIGGERED                                     │
│                                                                              │
│    Walled garden lease was short (10 min)                                   │
│    Customer device sends DHCP DISCOVER/REQUEST                              │
│                                                                              │
│    eBPF/XDP receives packet:                                                │
│    - Lookup MAC in subscriber map → HIT!                                    │
│    - Pre-allocated IP found: 100.64.1.42                                    │
│    - Generate DHCP OFFER/ACK in kernel (FAST PATH)                          │
│    - Return XDP_TX                                                           │
│                                                                              │
│    Latency: ~10 microseconds                                                │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 14. CUSTOMER HAS INTERNET ACCESS                                             │
│                                                                              │
│    Customer device now has:                                                  │
│    - IP: 100.64.1.42                                                        │
│    - Gateway: 100.64.0.1 (OLT-BNG)                                          │
│    - DNS: ISP-A's DNS servers                                               │
│                                                                              │
│    Traffic flow (LOCAL - no central BNG):                                   │
│    Customer → ONT → OLT-BNG → Policy Routing → ISP-A PE → Internet         │
│                                    │                                         │
│                                    └── ip rule: from 100.64.1.42 table 100  │
│                                        table 100: default via ISP-A PE      │
│                                                                              │
│    QoS applied via eBPF: 100 Mbps down, 20 Mbps up                          │
│    RADIUS Accounting-Start sent to ISP-A                                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Summary: What Happens Where

| Action | Location | Central Involved? |
|--------|----------|-------------------|
| ONT detection | OLT-BNG (local) | No |
| Walled garden | OLT-BNG (local) | No |
| Customer sign-up | ISP portal → Nexus | Yes (config sync) |
| RADIUS auth | OLT-BNG → ISP RADIUS | Yes (ISP's RADIUS) |
| IP allocation | Nexus hashring | Yes (at RADIUS time) |
| DHCP delivery | OLT-BNG (local eBPF) | No |
| Traffic routing | OLT-BNG → ISP (BGP) | No |
| QoS enforcement | OLT-BNG (local eBPF) | No |

**Key Point**: Subscriber traffic NEVER flows through central infrastructure. Only control plane
operations (config sync, RADIUS auth, monitoring) involve central services.

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

## Upstream Routing Architecture

### Why BGP at the OLT-BNG?

Running BGP directly on each OLT-BNG eliminates single points of failure and enables faster failover:

```
          ISP-A                    ISP-B
            │                        │
    ┌───────┴───────┐        ┌───────┴───────┐
    │               │        │               │
    ▼               ▼        ▼               ▼
┌───────┐       ┌───────┐ ┌───────┐       ┌───────┐
│OLT-BNG│       │OLT-BNG│ │OLT-BNG│       │OLT-BNG│
│Site 1 │       │Site 2 │ │Site 1 │       │Site 2 │
└───────┘       └───────┘ └───────┘       └───────┘

Each OLT-BNG has direct eBGP sessions to ISP PE routers
- Site 1 fails? Site 2 keeps working
- ISP-A fails? Traffic shifts to ISP-B
- No single point of failure
```

### Physical Network Topology

```
                                    ┌─────────────────────────────────────┐
                                    │           INTERNET                  │
                                    └─────────────────────────────────────┘
                                                    │
                          ┌─────────────────────────┼─────────────────────────┐
                          │                         │                         │
                          ▼                         ▼                         ▼
                   ┌────────────┐           ┌────────────┐           ┌────────────┐
                   │   ISP-A    │           │   ISP-B    │           │   ISP-C    │
                   │  (NetCo)   │           │  (Retail)  │           │  (Retail)  │
                   │            │           │            │           │            │
                   │ AS 64501   │           │ AS 64502   │           │ AS 64503   │
                   └─────┬──────┘           └─────┬──────┘           └─────┬──────┘
                         │                        │                        │
                         │ eBGP sessions          │                        │
                         │ to each OLT-BNG        │                        │
                         ▼                        ▼                        ▼
               ══════════════════════════════════════════════════════════════════
                              Core/Aggregation Network (L2/MPLS/VXLAN)
               ══════════════════════════════════════════════════════════════════
                         │                                            │
                         │ 10-40 Gbps uplinks                         │
                         │                                            │
            ┌────────────┴────────────┐              ┌────────────────┴────────────┐
            │                         │              │                             │
            ▼                         ▼              ▼                             ▼
   ┌─────────────────┐      ┌─────────────────┐    ┌─────────────────┐   ┌─────────────────┐
   │   OLT-BNG #1    │      │   OLT-BNG #2    │    │   OLT-BNG #3    │   │   OLT-BNG #4    │
   │   (Edge Site)   │      │   (Edge Site)   │    │   (Edge Site)   │   │   (Edge Site)   │
   │                 │      │                 │    │                 │   │                 │
   │ 1,500 subs      │      │ 2,000 subs      │    │ 1,200 subs      │   │ 1,800 subs      │
   │ AS 64500        │      │ AS 64500        │    │ AS 64500        │   │ AS 64500        │
   └────────┬────────┘      └────────┬────────┘    └────────┬────────┘   └────────┬────────┘
            │                        │                      │                     │
            │ PON                    │                      │                     │
            ▼                        ▼                      ▼                     ▼
     ┌──────┴──────┐          ┌──────┴──────┐        ┌──────┴──────┐       ┌──────┴──────┐
     │ ONT  ONT    │          │ ONT  ONT    │        │ ONT  ONT    │       │ ONT  ONT    │
     │ ONT  ONT    │          │ ONT  ONT    │        │ ONT  ONT    │       │ ONT  ONT    │
     │ ...         │          │ ...         │        │ ...         │       │ ...         │
     └─────────────┘          └─────────────┘        └─────────────┘       └─────────────┘
        Subscribers              Subscribers            Subscribers           Subscribers
```

### BGP Integration with FRR

Each OLT-BNG runs FRR (Free Range Routing) as a separate daemon, controlled by our BNG process:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                      OLT-BNG (AS 64500)                                       │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                         FRR (bgpd)                                   │     │
│  │                                                                      │     │
│  │  neighbor 10.0.0.1 remote-as 64501  (ISP-A PE, primary)             │     │
│  │  neighbor 10.0.0.2 remote-as 64501  (ISP-A PE, backup)              │     │
│  │  neighbor 10.0.0.3 remote-as 64502  (ISP-B PE)                      │     │
│  │                                                                      │     │
│  │  network 100.64.0.0/22   ← Announce subscriber pool                 │     │
│  │                                                                      │     │
│  │  Receives: default route 0.0.0.0/0 from all peers                   │     │
│  │  Installs: routes via netlink based on BGP best path                │     │
│  │  Failover: PE dies → automatic convergence                         │     │
│  │                                                                      │     │
│  └──────────────────────────────┬──────────────────────────────────────┘     │
│                                 │                                             │
│                                 │ Routes installed via netlink                │
│                                 ▼                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                    BNG Process (our code)                            │     │
│  │                                                                      │     │
│  │  pkg/routing/Manager                                                 │     │
│  │    ├── Monitors FRR status via vtysh/gRPC                           │     │
│  │    ├── Triggers prefix withdraw on local failure                    │     │
│  │    ├── Policy routing for multi-ISP subscribers                     │     │
│  │    └── Health checks with BFD integration                           │     │
│  │                                                                      │     │
│  │  pkg/routing/BGPController                                          │     │
│  │    ├── AnnouncePrefix() - tell FRR to advertise                     │     │
│  │    ├── WithdrawPrefix() - remove advertisement                      │     │
│  │    └── GetNeighborStatus() - monitor BGP sessions                   │     │
│  │                                                                      │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

### Multi-ISP Routing with Policy Rules

Subscribers are routed to their ISP using Linux policy routing (ip rules + multiple routing tables):

```
┌──────────────────────────────────────────────────────────────────┐
│                      OLT-BNG (AS 64500)                           │
│                                                                   │
│  FRR installs routes per-neighbor into separate tables:          │
│  ───────────────────────────────────────────────────────         │
│  Table 100 (ISP-A): default via 10.0.0.1 dev eth0                │
│  Table 200 (ISP-B): default via 10.0.0.3 dev eth1                │
│  Table 254 (main):  default via 10.0.0.1 (best path)             │
│                                                                   │
│  Policy Rules (managed by pkg/routing/Manager):                  │
│  ────────────────────────────────────────────                    │
│  Priority 100: from 100.64.0.50 lookup 100  ← Sub on ISP-A       │
│  Priority 100: from 100.64.0.51 lookup 200  ← Sub on ISP-B       │
│  Priority 100: from 100.64.0.52 lookup 100  ← Sub on ISP-A       │
│  Priority 32766: from all lookup main        ← Default           │
│                                                                   │
│  Traffic Flow:                                                    │
│  ─────────────                                                   │
│  Subscriber 100.64.0.50 (ISP-A customer)                         │
│    → Packet src=100.64.0.50                                      │
│    → Rule match: lookup table 100                                │
│    → Route: via 10.0.0.1 (ISP-A PE)                              │
│    → Egress on eth0 to ISP-A                                     │
│                                                                   │
│  Subscriber 100.64.0.51 (ISP-B customer)                         │
│    → Packet src=100.64.0.51                                      │
│    → Rule match: lookup table 200                                │
│    → Route: via 10.0.0.3 (ISP-B PE)                              │
│    → Egress on eth1 to ISP-B                                     │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### Upstream Redundancy with ECMP

For ISPs with multiple PE routers, ECMP provides load balancing and redundancy:

```
                    ISP-A Network (AS 64501)
                    ┌─────────────────────────────────────────────┐
                    │                                              │
                    │   ┌─────────┐           ┌─────────┐         │
                    │   │  PE-1   │           │  PE-2   │         │
                    │   │(Primary)│           │(Backup) │         │
                    │   │10.0.0.1 │           │10.0.0.2 │         │
                    │   └────┬────┘           └────┬────┘         │
                    └────────┼─────────────────────┼──────────────┘
                             │                     │
                             │ eBGP                │ eBGP
                             │ weight=100          │ weight=100
                             │                     │
┌────────────────────────────┼─────────────────────┼──────────────────────────┐
│                        OLT-BNG                                               │
│                                                                              │
│  FRR Configuration:                                                          │
│  ──────────────────                                                          │
│  router bgp 64500                                                            │
│    neighbor 10.0.0.1 remote-as 64501                                        │
│    neighbor 10.0.0.2 remote-as 64501                                        │
│    maximum-paths 2                           ← Enable ECMP                   │
│                                                                              │
│  Resulting Route (installed via netlink):                                    │
│  ────────────────────────────────────────                                    │
│  default via 10.0.0.1 dev eth0 weight 1                                     │
│          via 10.0.0.2 dev eth0 weight 1     ← ECMP multipath                │
│                                                                              │
│  Traffic Distribution:                                                       │
│  ─────────────────────                                                      │
│  Linux kernel hashes (src_ip, dst_ip, src_port, dst_port, protocol)         │
│  to select next-hop, providing per-flow load balancing                      │
│                                                                              │
│  Failover:                                                                   │
│  ─────────                                                                  │
│  PE-1 fails → BGP session drops → FRR removes from ECMP                     │
│            → All traffic via PE-2 (sub-second with BFD)                     │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Health Checking and Fast Failover

```
┌─────────────────────────────────────────────────────────────────┐
│                    Health Check Architecture                     │
│                                                                  │
│  Layer 1: BFD (Bidirectional Forwarding Detection)              │
│  ─────────────────────────────────────────────────              │
│  ├── Sub-second failure detection (50ms intervals)             │
│  ├── Integrated with FRR BGP                                    │
│  └── Triggers immediate BGP session teardown                    │
│                                                                  │
│  Layer 2: BGP Keepalives                                        │
│  ───────────────────────                                        │
│  ├── Default: 60s hold time (3x 20s keepalive)                 │
│  ├── Tunable per-neighbor                                       │
│  └── Fallback if BFD not available                              │
│                                                                  │
│  Layer 3: Application Health (pkg/routing/HealthChecker)        │
│  ───────────────────────────────────────────────────            │
│  ├── ICMP ping to upstream gateway                              │
│  ├── TCP connect to well-known ports                            │
│  ├── Hysteresis: 3 failures → down, 2 successes → up           │
│  └── Triggers: prefix withdraw, traffic reroute                 │
│                                                                  │
│  Failure Timeline:                                               │
│  ─────────────────                                              │
│  T+0ms     Link failure                                         │
│  T+50ms    BFD detects (if enabled)                             │
│  T+100ms   BGP session marked down                              │
│  T+150ms   FRR withdraws routes, installs backup                │
│  T+200ms   Traffic flowing via backup path                      │
│                                                                  │
│  Without BFD:                                                    │
│  T+0s      Link failure                                         │
│  T+60s     BGP hold timer expires                               │
│  T+60.1s   Routes withdrawn, backup installed                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### NetCo/ISPCo Traffic Separation

```
                                 ISP-A (Retail)     ISP-B (Retail)
                                      │                  │
                                      │ BGP              │ BGP
                                      ▼                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                     NetCo Core Network                            │
│                                                                   │
│  NetCo Role:                                                      │
│  ├── Operates physical infrastructure                            │
│  ├── Runs OLT-BNG software                                       │
│  ├── Manages BGP sessions on behalf of ISPs                      │
│  └── Does NOT see subscriber traffic content                     │
│                                                                   │
│  Traffic Isolation:                                               │
│  ├── Each ISP has separate routing table                         │
│  ├── Subscriber → ISP mapping from CLSet                         │
│  ├── Policy rules enforce traffic path                           │
│  └── ISP-specific NAT pools                                      │
│                                                                   │
│  Prefix Announcements:                                            │
│  ├── NetCo aggregate: 100.64.0.0/10 (covers all sites)          │
│  ├── Per-site: 100.64.0.0/22 (from each OLT-BNG)                │
│  └── ISP-specific: Announced to respective ISP only              │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
                              │
                              │ (L2 backhaul)
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                         OLT-BNG                                   │
│                                                                   │
│  Subscriber: aa:bb:cc:dd:ee:ff                                   │
│    CLSet lookup → ispco_id = "ISP-A"                             │
│    RADIUS → ISP-A server (10.1.0.10)                             │
│    IP Pool → ISP-A pool (100.64.0.0/24)                          │
│    Routing → Table 100 (ISP-A gateway)                           │
│    NAT → ISP-A public pool (203.0.113.0/24)                      │
│                                                                   │
│  Subscriber: 11:22:33:44:55:66                                   │
│    CLSet lookup → ispco_id = "ISP-B"                             │
│    RADIUS → ISP-B server (10.2.0.10)                             │
│    IP Pool → ISP-B pool (100.64.1.0/24)                          │
│    Routing → Table 200 (ISP-B gateway)                           │
│    NAT → ISP-B public pool (198.51.100.0/24)                     │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### Resource Requirements for BGP

FRR is lightweight and easily runs alongside BNG functions:

| Component | CPU | Memory | Notes |
|-----------|-----|--------|-------|
| FRR bgpd (few sessions) | ~1% | ~50 MB | 2-4 BGP sessions, default routes only |
| FRR bgpd (full table) | ~5% | ~500 MB | Receiving full internet routing table |
| BFD daemon | <1% | ~10 MB | For sub-second failover |
| **Typical edge deployment** | **~2%** | **~100 MB** | Just default routes + local prefixes |

The OLT hardware (typically 8+ cores, 16+ GB RAM) has plenty of capacity for BGP.

---

## Glossary

| Term | Definition |
|------|------------|
| **BFD** | Bidirectional Forwarding Detection - fast failure detection |
| **BGP** | Border Gateway Protocol - inter-domain routing |
| **BNG** | Broadband Network Gateway |
| **CLSet** | CRDT-based distributed database |
| **CGNAT** | Carrier-Grade NAT |
| **CPE** | Customer Premises Equipment |
| **C-TAG** | Customer VLAN tag (inner) |
| **eBGP** | External BGP - between different autonomous systems |
| **ECMP** | Equal-Cost Multi-Path - load balancing across multiple routes |
| **FRR** | Free Range Routing - open source routing daemon suite |
| **GPON** | Gigabit Passive Optical Network |
| **iBGP** | Internal BGP - within the same autonomous system |
| **ISPCo** | Internet Service Provider Company |
| **NetCo** | Network Company (infrastructure) |
| **NTE** | Network Terminating Equipment |
| **OLT** | Optical Line Terminal |
| **ONU/ONT** | Optical Network Unit/Terminal |
| **PE** | Provider Edge router - ISP's border router |
| **PON** | Passive Optical Network |
| **S-TAG** | Service VLAN tag (outer) |
| **XDP** | eXpress Data Path |
| **ZTP** | Zero-Touch Provisioning |
