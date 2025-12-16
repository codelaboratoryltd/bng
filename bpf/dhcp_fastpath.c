/* DHCP Fast Path - XDP Program
 *
 * eBPF/XDP program for high-performance DHCP response caching
 * Handles DHCP DISCOVER/REQUEST for known subscribers entirely in kernel
 *
 * Fast path: Reply from cache (~10μs latency)
 * Slow path: Pass to userspace for new allocations (XDP_PASS)
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"

/* DHCP packet structure (simplified) */
struct dhcp_packet {
	__u8  op;           /* 1 = BOOTREQUEST, 2 = BOOTREPLY */
	__u8  htype;        /* Hardware address type (1 = Ethernet) */
	__u8  hlen;         /* Hardware address length (6 for MAC) */
	__u8  hops;         /* Hops */
	__u32 xid;          /* Transaction ID */
	__u16 secs;         /* Seconds elapsed */
	__u16 flags;        /* Flags */
	__u32 ciaddr;       /* Client IP address */
	__u32 yiaddr;       /* Your (client) IP address */
	__u32 siaddr;       /* Server IP address */
	__u32 giaddr;       /* Gateway IP address */
	__u8  chaddr[16];   /* Client hardware address */
	__u8  sname[64];    /* Server host name */
	__u8  file[128];    /* Boot file name */
	__u32 magic;        /* Magic cookie (0x63825363) */
	__u8  options[];    /* DHCP options */
} __attribute__((packed));

/* DHCP ports */
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

/* DHCP message types (in options) */
#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_ACK      5

/* Helper macro for bounds checking (required by eBPF verifier) */
#define CHECK_BOUNDS(ptr, end, size) \
	if ((void *)(ptr) + (size) > (void *)(end)) \
		return XDP_DROP;

/* Extract MAC address from DHCP packet to u64 */
static __always_inline __u64 mac_to_u64(__u8 *mac) {
	__u64 result = 0;
	#pragma unroll
	for (int i = 0; i < 6; i++) {
		result = (result << 8) | mac[i];
	}
	return result;
}

/* Update statistics counters */
static __always_inline void update_stats(__u32 counter_type) {
	__u32 key = 0;
	struct dhcp_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
	if (!stats)
		return;

	/* counter_type: 0=total, 1=fastpath_hit, 2=fastpath_miss, 3=error */
	switch (counter_type) {
	case 0:
		__sync_fetch_and_add(&stats->total_requests, 1);
		break;
	case 1:
		__sync_fetch_and_add(&stats->fastpath_hits, 1);
		break;
	case 2:
		__sync_fetch_and_add(&stats->fastpath_misses, 1);
		break;
	case 3:
		__sync_fetch_and_add(&stats->errors, 1);
		break;
	case 4:
		__sync_fetch_and_add(&stats->cache_expired, 1);
		break;
	}
}

/* Main XDP program */
SEC("xdp")
int dhcp_fastpath_prog(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Parse Ethernet header */
	struct ethhdr *eth = data;
	CHECK_BOUNDS(eth, data_end, sizeof(*eth));

	/* Only process IPv4 */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* Parse IP header */
	struct iphdr *ip = data + sizeof(*eth);
	CHECK_BOUNDS(ip, data_end, sizeof(*ip));

	/* Only process UDP */
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* Parse UDP header */
	struct udphdr *udp = (void *)ip + (ip->ihl * 4);
	CHECK_BOUNDS(udp, data_end, sizeof(*udp));

	/* Check if DHCP (ports 67/68) */
	__u16 dest_port = bpf_ntohs(udp->dest);
	if (dest_port != DHCP_SERVER_PORT && dest_port != DHCP_CLIENT_PORT)
		return XDP_PASS;

	/* Parse DHCP packet */
	struct dhcp_packet *dhcp = (void *)udp + sizeof(*udp);
	CHECK_BOUNDS(dhcp, data_end, sizeof(struct dhcp_packet));

	/* Update total request counter */
	update_stats(0);

	/* Extract client MAC address */
	__u64 mac_addr = mac_to_u64(dhcp->chaddr);

	/* Lookup subscriber in cache */
	struct pool_assignment *assignment =
		bpf_map_lookup_elem(&subscriber_pools, &mac_addr);

	if (!assignment) {
		/* CACHE MISS - Pass to userspace (slow path) */
		update_stats(2);
		return XDP_PASS;
	}

	/* Check if lease is still valid */
	__u64 now = bpf_ktime_get_ns() / 1000000000; /* Convert to seconds */
	if (now > assignment->lease_expiry) {
		/* Lease expired - Pass to userspace for renewal */
		update_stats(4);
		return XDP_PASS;
	}

	/* CACHE HIT - Fast path! */
	update_stats(1);

	/* TODO Phase 3: Generate DHCP reply in kernel
	 * For now, pass to userspace to verify eBPF program loads correctly
	 */
	return XDP_PASS;

	/* Future implementation:
	 * 1. Lookup IP pool metadata
	 * 2. Generate DHCP OFFER or ACK
	 * 3. Swap MAC/IP addresses
	 * 4. Recalculate checksums
	 * 5. Return XDP_TX (send reply)
	 */
}

char _license[] SEC("license") = "GPL";
