/* eBPF Map Definitions for BNG DHCP Fast Path */

#ifndef __MAPS_H__
#define __MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Maximum entries in maps */
#define MAX_SUBSCRIBERS 1000000
#define MAX_POOLS 10000

/* Subscriber pool assignment
 * Key: MAC address (u64, 6 bytes padded)
 * Value: pool_assignment struct
 */
struct pool_assignment {
	__u32 pool_id;          /* Which IP pool */
	__u32 allocated_ip;     /* Currently assigned IP (network byte order) */
	__u32 vlan_id;          /* VLAN tag for subscriber */
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

/* Performance counters */
struct dhcp_stats {
	__u64 total_requests;
	__u64 fastpath_hits;
	__u64 fastpath_misses;
	__u64 errors;
	__u64 cache_expired;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);   /* Always 0 */
	__type(value, struct dhcp_stats);
} stats_map SEC(".maps");

#endif /* __MAPS_H__ */
