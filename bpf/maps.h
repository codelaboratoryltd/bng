/* eBPF Map Definitions for BNG DHCP Fast Path */

#ifndef __MAPS_H__
#define __MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Maximum entries in maps */
#define MAX_SUBSCRIBERS 1000000
#define MAX_POOLS 10000
#define MAX_VLAN_SUBSCRIBERS 100000

/* ========================================================================
 * DHCP Option Parsing Definitions (Issue #14)
 * ======================================================================== */

/* Maximum DHCP options to iterate over (eBPF verifier constraint) */
#define MAX_DHCP_OPTIONS_ITER 64

/* Maximum bytes to scan in DHCP options area */
#define MAX_DHCP_OPTIONS_SCAN_LEN 312

/* DHCP Option codes */
#define DHCP_OPT_PAD              0
#define DHCP_OPT_SUBNET_MASK      1
#define DHCP_OPT_ROUTER           3
#define DHCP_OPT_DNS              6
#define DHCP_OPT_HOSTNAME         12
#define DHCP_OPT_VENDOR_SPECIFIC  43
#define DHCP_OPT_REQUESTED_IP     50
#define DHCP_OPT_LEASE_TIME       51
#define DHCP_OPT_MSG_TYPE         53
#define DHCP_OPT_SERVER_ID        54
#define DHCP_OPT_PARAM_REQ_LIST   55
#define DHCP_OPT_RENEWAL_TIME     58
#define DHCP_OPT_REBIND_TIME      59
#define DHCP_OPT_VENDOR_CLASS_ID  60
#define DHCP_OPT_CLIENT_ID        61
#define DHCP_OPT_RELAY_AGENT_INFO 82
#define DHCP_OPT_END              255

/* ========================================================================
 * Option 82 (Relay Agent Information) Definitions (Issue #15)
 * ======================================================================== */

/* Option 82 sub-option types */
#define OPT82_CIRCUIT_ID   1
#define OPT82_REMOTE_ID    2

/* Maximum lengths for Option 82 sub-options (must match buffer sizes below) */
#define MAX_CIRCUIT_ID_LEN 64
#define MAX_REMOTE_ID_LEN  64

/* Parsed DHCP options structure - holds extracted option values */
struct dhcp_parsed_options {
	__u8  msg_type;              /* DHCP message type (Option 53) */
	__u8  has_option82;          /* Flag: Option 82 present */
	__u8  circuit_id_len;        /* Length of circuit-id */
	__u8  remote_id_len;         /* Length of remote-id */
	__u8  circuit_id[MAX_CIRCUIT_ID_LEN];  /* Circuit-ID value (Option 82.1) */
	__u8  remote_id[MAX_REMOTE_ID_LEN];    /* Remote-ID value (Option 82.2) */
	__u32 requested_ip;          /* Requested IP address (Option 50) */
	__u8  client_id_len;         /* Length of client identifier */
	__u8  client_id[64];         /* Client identifier (Option 61) */
} __attribute__((packed));

/* Subscriber key types for map lookup */
#define KEY_TYPE_MAC       0
#define KEY_TYPE_CIRCUIT   1

/* Subscriber lookup key - supports both MAC and circuit-id based lookup */
struct subscriber_key {
	__u8 key_type;              /* 0=MAC, 1=circuit-id */
	__u8 _pad[7];               /* Padding for alignment */
	union {
		__u64 mac;              /* MAC address as uint64 */
		struct {
			__u8 circuit_id[32];  /* Circuit-ID (truncated/hashed if longer) */
			__u8 remote_id[16];   /* Remote-ID prefix */
		};
	};
} __attribute__((packed));

/* Subscriber pool assignment
 * Key: MAC address (u64, 6 bytes padded)
 * Value: pool_assignment struct
 */
struct pool_assignment {
	__u32 pool_id;          /* Which IP pool */
	__u32 allocated_ip;     /* Currently assigned IP (network byte order) */
	__u32 vlan_id;          /* VLAN tag for subscriber (deprecated, use s_tag/c_tag) */
	__u8  client_class;     /* Residential=1, Business=2, etc. */
	__u64 lease_expiry;     /* Unix timestamp (seconds) */
	__u8  flags;            /* Static IP flag, etc. */
	__u8  _pad[3];          /* Padding for alignment */
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SUBSCRIBERS);
	__type(key, __u64);   /* MAC address */
	__type(value, struct pool_assignment);
} subscriber_pools SEC(".maps");

/* QinQ (802.1ad) VLAN key for subscriber lookup
 * Used in European PoI deployments where subscribers are identified by
 * S-VLAN (outer) + C-VLAN (inner) combination instead of MAC
 */
struct vlan_key {
	__u16 s_tag;           /* Service VLAN (outer, 802.1ad) */
	__u16 c_tag;           /* Customer VLAN (inner, 802.1Q) */
} __attribute__((packed));

/* VLAN-based subscriber assignment
 * Key: vlan_key (S-TAG, C-TAG tuple)
 * Value: pool_assignment struct
 *
 * This map is used for QinQ deployments where each subscriber is identified
 * by their unique VLAN combination. In this model:
 * - S-TAG identifies the service provider or PoI
 * - C-TAG identifies the individual subscriber within that service
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_VLAN_SUBSCRIBERS);
	__type(key, struct vlan_key);
	__type(value, struct pool_assignment);
} vlan_subscriber_pools SEC(".maps");

/* IP pool metadata
 * Key: pool_id (u32)
 * Value: ip_pool struct
 */
struct ip_pool {
	__u32 network;          /* Network address (e.g., 10.0.0.0) */
	__u8  prefix_len;       /* CIDR prefix (e.g., 24 for /24) */
	__u8  _pad1[3];
	__u32 gateway;          /* Default gateway for pool */
	__u32 dns_primary;      /* Primary DNS server */
	__u32 dns_secondary;    /* Secondary DNS server */
	__u32 lease_time;       /* Default lease duration (seconds) */
	__u32 _pad2;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_POOLS);
	__type(key, __u32);   /* pool_id */
	__type(value, struct ip_pool);
} ip_pools SEC(".maps");

/* DHCP server configuration */
struct dhcp_server_config {
	__u8  server_mac[6];    /* Server's MAC address */
	__u8  _pad[2];
	__u32 server_ip;        /* Server's IP address (network byte order) */
	__u32 interface_index;  /* Interface index for XDP */
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);   /* Always 0 */
	__type(value, struct dhcp_server_config);
} server_config SEC(".maps");

/* Performance counters - not packed to ensure proper alignment for atomic ops
 * NOTE: This struct must match the layout of DHCPStats in pkg/ebpf/loader.go
 */
struct dhcp_stats {
	__u64 total_requests;
	__u64 fastpath_hits;
	__u64 fastpath_misses;
	__u64 errors;
	__u64 cache_expired;
	/* Option 82 statistics (Issue #15) */
	__u64 option82_present;
	__u64 option82_absent;
	/* L2 header statistics (Issue #17) */
	__u64 broadcast_replies;
	__u64 unicast_replies;
	__u64 vlan_packets;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);   /* Always 0 */
	__type(value, struct dhcp_stats);
} stats_map SEC(".maps");

/* Circuit-ID to subscriber mapping (Issue #15)
 * Key: hash of circuit-id
 * Value: MAC address (uint64)
 * Used when Option 82 is present to find subscriber by circuit-id
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SUBSCRIBERS);
	__type(key, __u64);   /* FNV-1a hash of circuit-id */
	__type(value, __u64); /* MAC address to use for subscriber lookup */
} circuit_id_map SEC(".maps");

/* ========================================================================
 * Fixed-Size Circuit-ID Subscriber Lookup (Issue #56)
 *
 * Re-implemented Option 82 circuit-ID support using fixed-size keys
 * to avoid eBPF verifier issues with variable-length hashing loops.
 * ======================================================================== */

/* Fixed-size circuit-ID key for direct lookup (Issue #56)
 * Circuit-IDs longer than 32 bytes are truncated
 * Shorter circuit-IDs are zero-padded
 */
#define CIRCUIT_ID_KEY_LEN 32

struct circuit_id_key {
	__u8 data[CIRCUIT_ID_KEY_LEN];
} __attribute__((packed));

/* Circuit-ID to pool assignment direct mapping (Issue #56)
 * Key: Fixed 32-byte circuit-id (padded/truncated)
 * Value: pool_assignment struct (same as subscriber_pools)
 *
 * Populated by slow path when Option 82 is seen.
 * Enables fast-path lookup by circuit-ID without hashing.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SUBSCRIBERS);
	__type(key, struct circuit_id_key);
	__type(value, struct pool_assignment);
} circuit_id_subscribers SEC(".maps");

#endif /* __MAPS_H__ */
