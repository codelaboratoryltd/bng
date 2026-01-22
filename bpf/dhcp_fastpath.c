/* DHCP Fast Path - XDP Program
 *
 * eBPF/XDP program for high-performance DHCP response caching
 * Handles DHCP DISCOVER/REQUEST for known subscribers entirely in kernel
 *
 * Fast path: Reply from cache (~10μs latency)
 * Slow path: Pass to userspace for new allocations (XDP_PASS)
 *
 * Supports:
 * - Standard Ethernet (untagged)
 * - Single VLAN (802.1Q)
 * - Double VLAN / QinQ (802.1ad + 802.1Q)
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"

/* VLAN header structure */
struct vlan_hdr {
	__be16 h_vlan_TCI;        /* priority (3) + DEI (1) + VLAN ID (12) */
	__be16 h_vlan_encapsulated_proto;
} __attribute__((packed));

/* EtherTypes for VLAN */
#define ETH_P_8021Q  0x8100   /* 802.1Q VLAN Extended Header */
#define ETH_P_8021AD 0x88A8   /* 802.1ad Service VLAN (QinQ outer) */

/* Extract VLAN ID from TCI */
#define VLAN_VID_MASK 0x0FFF

/* VLAN parsing context */
struct vlan_info {
	__u16 s_tag;           /* Outer VLAN (S-TAG) - 0 if single-tagged or untagged */
	__u16 c_tag;           /* Inner VLAN (C-TAG) - 0 if untagged */
	__u16 proto;           /* Final protocol after VLAN headers */
	__u8  vlan_depth;      /* 0=untagged, 1=single, 2=double (QinQ) */
	__u8  _pad;
};

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

/* DHCP message types (option 53) */
#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_DECLINE  4
#define DHCP_ACK      5
#define DHCP_NAK      6
#define DHCP_RELEASE  7
#define DHCP_INFORM   8

/* DHCP option codes */
#define DHCP_OPT_PAD           0
#define DHCP_OPT_SUBNET_MASK   1
#define DHCP_OPT_ROUTER        3
#define DHCP_OPT_DNS           6
#define DHCP_OPT_HOSTNAME      12
#define DHCP_OPT_REQUESTED_IP  50
#define DHCP_OPT_LEASE_TIME    51
#define DHCP_OPT_MSG_TYPE      53
#define DHCP_OPT_SERVER_ID     54
#define DHCP_OPT_RENEWAL_TIME  58
#define DHCP_OPT_REBIND_TIME   59
#define DHCP_OPT_END           255

/* DHCP magic cookie */
#define DHCP_MAGIC_COOKIE 0x63538263  /* Network byte order: 99.130.83.99 */

/* BOOTREQUEST/BOOTREPLY */
#define BOOTREQUEST 1
#define BOOTREPLY   2

/* Maximum DHCP options we'll write */
#define MAX_DHCP_OPTIONS_LEN 64

/* Minimum DHCP packet size (with required options) */
#define MIN_DHCP_PACKET_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
                              sizeof(struct udphdr) + sizeof(struct dhcp_packet) + \
                              MAX_DHCP_OPTIONS_LEN)

/* Broadcast MAC address */
static const __u8 broadcast_mac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* Helper macro for bounds checking (required by eBPF verifier) */
#define CHECK_BOUNDS(ptr, end, size) \
	if ((void *)(ptr) + (size) > (void *)(end)) \
		return XDP_DROP;

/* Bounds check that returns XDP_PASS instead of DROP */
#define CHECK_BOUNDS_PASS(ptr, end, size) \
	if ((void *)(ptr) + (size) > (void *)(end)) \
		return XDP_PASS;

/* Extract MAC address from DHCP packet to u64 */
static __always_inline __u64 mac_to_u64(__u8 *mac) {
	__u64 result = 0;
	#pragma unroll
	for (int i = 0; i < 6; i++) {
		result = (result << 8) | mac[i];
	}
	return result;
}

/* Parse VLAN headers (supports untagged, 802.1Q, and QinQ 802.1ad)
 * Returns pointer to payload after VLAN headers, or NULL on error
 */
static __always_inline void *parse_vlan_headers(struct ethhdr *eth, void *data_end,
                                                 struct vlan_info *vinfo) {
	void *payload = (void *)(eth + 1);
	__u16 proto = bpf_ntohs(eth->h_proto);

	/* Initialize VLAN info */
	vinfo->s_tag = 0;
	vinfo->c_tag = 0;
	vinfo->vlan_depth = 0;
	vinfo->proto = proto;

	/* Check for outer VLAN tag (802.1ad S-TAG for QinQ) */
	if (proto == ETH_P_8021AD) {
		struct vlan_hdr *outer_vlan = payload;
		if ((void *)(outer_vlan + 1) > data_end)
			return NULL;

		vinfo->s_tag = bpf_ntohs(outer_vlan->h_vlan_TCI) & VLAN_VID_MASK;
		proto = bpf_ntohs(outer_vlan->h_vlan_encapsulated_proto);
		payload = (void *)(outer_vlan + 1);
		vinfo->vlan_depth = 1;
	}

	/* Check for inner VLAN tag (802.1Q C-TAG) */
	if (proto == ETH_P_8021Q) {
		struct vlan_hdr *inner_vlan = payload;
		if ((void *)(inner_vlan + 1) > data_end)
			return NULL;

		/* If we already have an outer tag, this is the C-TAG
		 * If not, treat this as a single-tagged frame (C-TAG only) */
		__u16 vid = bpf_ntohs(inner_vlan->h_vlan_TCI) & VLAN_VID_MASK;
		if (vinfo->vlan_depth == 0) {
			/* Single-tagged: this is the C-TAG */
			vinfo->c_tag = vid;
			vinfo->vlan_depth = 1;
		} else {
			/* Double-tagged (QinQ): this is the C-TAG */
			vinfo->c_tag = vid;
			vinfo->vlan_depth = 2;
		}
		proto = bpf_ntohs(inner_vlan->h_vlan_encapsulated_proto);
		payload = (void *)(inner_vlan + 1);
	}

	vinfo->proto = proto;
	return payload;
}

/* Update statistics counters */
static __always_inline void update_stats(__u32 counter_type) {
	__u32 key = 0;
	struct dhcp_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
	if (!stats)
		return;

	/* counter_type: 0=total, 1=fastpath_hit, 2=fastpath_miss, 3=error, 4=expired */
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

/* Maximum DHCP options area to scan (prevents verifier issues) */
#define MAX_DHCP_OPTIONS_SCAN 128

/* Parse DHCP options to find message type
 * Uses offset-based parsing to help eBPF verifier track bounds
 */
static __always_inline __u8 get_dhcp_msg_type(struct dhcp_packet *dhcp, void *data_end) {
	__u8 *options_start = dhcp->options;
	__u32 offset = 0;

	/* Limit option parsing to prevent infinite loops (eBPF verifier) */
	#pragma unroll
	for (int i = 0; i < 32; i++) {
		/* Strict offset limit - verifier needs constant bounds */
		if (offset >= MAX_DHCP_OPTIONS_SCAN)
			return 0;

		/* Bounds check for option code */
		__u8 *opt_ptr = options_start + offset;
		if ((void *)(opt_ptr + 1) > data_end)
			return 0;

		__u8 code = *opt_ptr;
		if (code == DHCP_OPT_END)
			return 0;
		if (code == DHCP_OPT_PAD) {
			offset++;
			continue;
		}

		/* Bounds check for option length byte */
		if ((void *)(opt_ptr + 2) > data_end)
			return 0;

		__u8 len = *(opt_ptr + 1);

		/* Sanity check length - prevents offset overflow */
		if (len > 64)
			return 0;

		/* Bounds check for option data */
		if ((void *)(opt_ptr + 2 + len) > data_end)
			return 0;

		if (code == DHCP_OPT_MSG_TYPE && len == 1)
			return *(opt_ptr + 2);

		offset += 2 + len;
	}
	return 0;
}

/* Calculate IP header checksum */
static __always_inline __u16 ip_checksum(struct iphdr *ip) {
	__u32 sum = 0;
	__u16 *buf = (__u16 *)ip;

	/* IP header is 20 bytes = 10 16-bit words (assuming no options) */
	#pragma unroll
	for (int i = 0; i < 10; i++) {
		sum += buf[i];
	}

	/* Fold 32-bit sum to 16 bits */
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

/* Generate subnet mask from prefix length */
static __always_inline __u32 prefix_to_mask(__u8 prefix_len) {
	if (prefix_len == 0)
		return 0;
	if (prefix_len >= 32)
		return 0xFFFFFFFF;
	return bpf_htonl(0xFFFFFFFF << (32 - prefix_len));
}

/* Build DHCP options for reply */
static __always_inline int build_dhcp_options(__u8 *opt, void *data_end,
                                              __u8 msg_type,
                                              struct ip_pool *pool,
                                              struct pool_assignment *assignment,
                                              __u32 server_ip) {
	int offset = 0;

	/* Option 53: DHCP Message Type */
	if ((void *)(opt + offset + 3) > data_end)
		return -1;
	opt[offset++] = DHCP_OPT_MSG_TYPE;
	opt[offset++] = 1;
	opt[offset++] = msg_type;

	/* Option 54: Server Identifier */
	if ((void *)(opt + offset + 6) > data_end)
		return -1;
	opt[offset++] = DHCP_OPT_SERVER_ID;
	opt[offset++] = 4;
	*(__u32 *)(opt + offset) = server_ip;
	offset += 4;

	/* Option 51: Lease Time */
	if ((void *)(opt + offset + 6) > data_end)
		return -1;
	opt[offset++] = DHCP_OPT_LEASE_TIME;
	opt[offset++] = 4;
	*(__u32 *)(opt + offset) = bpf_htonl(pool->lease_time);
	offset += 4;

	/* Option 1: Subnet Mask */
	if ((void *)(opt + offset + 6) > data_end)
		return -1;
	opt[offset++] = DHCP_OPT_SUBNET_MASK;
	opt[offset++] = 4;
	*(__u32 *)(opt + offset) = prefix_to_mask(pool->prefix_len);
	offset += 4;

	/* Option 3: Router (Gateway) */
	if ((void *)(opt + offset + 6) > data_end)
		return -1;
	opt[offset++] = DHCP_OPT_ROUTER;
	opt[offset++] = 4;
	*(__u32 *)(opt + offset) = pool->gateway;
	offset += 4;

	/* Option 6: DNS Servers */
	if (pool->dns_primary != 0) {
		__u8 dns_len = (pool->dns_secondary != 0) ? 8 : 4;
		if ((void *)(opt + offset + 2 + dns_len) > data_end)
			return -1;
		opt[offset++] = DHCP_OPT_DNS;
		opt[offset++] = dns_len;
		*(__u32 *)(opt + offset) = pool->dns_primary;
		offset += 4;
		if (pool->dns_secondary != 0) {
			*(__u32 *)(opt + offset) = pool->dns_secondary;
			offset += 4;
		}
	}

	/* Option 58: Renewal Time (T1) - 50% of lease */
	if ((void *)(opt + offset + 6) > data_end)
		return -1;
	opt[offset++] = DHCP_OPT_RENEWAL_TIME;
	opt[offset++] = 4;
	*(__u32 *)(opt + offset) = bpf_htonl(pool->lease_time / 2);
	offset += 4;

	/* Option 59: Rebinding Time (T2) - 87.5% of lease */
	if ((void *)(opt + offset + 6) > data_end)
		return -1;
	opt[offset++] = DHCP_OPT_REBIND_TIME;
	opt[offset++] = 4;
	*(__u32 *)(opt + offset) = bpf_htonl((pool->lease_time * 7) / 8);
	offset += 4;

	/* Option 255: End */
	if ((void *)(opt + offset + 1) > data_end)
		return -1;
	opt[offset++] = DHCP_OPT_END;

	return offset;
}

/* Set MAC addresses for DHCP reply
 * - Destination: Broadcast (FF:FF:FF:FF:FF:FF) for clients without IP
 *   or unicast to client MAC if BROADCAST flag is clear
 * - Source: DHCP server's MAC address
 */
static __always_inline void set_reply_eth_addrs(struct ethhdr *eth,
                                                 struct dhcp_packet *dhcp,
                                                 __u8 *server_mac) {
	/* Check DHCP BROADCAST flag (bit 15 of flags field) */
	__u16 flags = bpf_ntohs(dhcp->flags);

	if (flags & 0x8000) {
		/* BROADCAST flag set - use broadcast MAC */
		__builtin_memcpy(eth->h_dest, broadcast_mac, ETH_ALEN);
	} else if (dhcp->ciaddr != 0) {
		/* Client has IP - send unicast to client MAC */
		__builtin_memcpy(eth->h_dest, dhcp->chaddr, ETH_ALEN);
	} else {
		/* DISCOVER/REQUEST without ciaddr - use broadcast */
		__builtin_memcpy(eth->h_dest, broadcast_mac, ETH_ALEN);
	}

	/* Source is always server MAC */
	__builtin_memcpy(eth->h_source, server_mac, ETH_ALEN);
}

/* Main XDP program */
SEC("xdp")
int dhcp_fastpath_prog(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Parse Ethernet header */
	struct ethhdr *eth = data;
	CHECK_BOUNDS(eth, data_end, sizeof(*eth));

	/* Parse VLAN headers (supports untagged, 802.1Q, QinQ) */
	struct vlan_info vinfo;
	void *l3_header = parse_vlan_headers(eth, data_end, &vinfo);
	if (!l3_header)
		return XDP_PASS;

	/* Only process IPv4 */
	if (vinfo.proto != ETH_P_IP)
		return XDP_PASS;

	/* Parse IP header */
	struct iphdr *ip = l3_header;
	CHECK_BOUNDS(ip, data_end, sizeof(*ip));

	/* Only process UDP */
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* Parse UDP header */
	struct udphdr *udp = (void *)ip + (ip->ihl * 4);
	CHECK_BOUNDS(udp, data_end, sizeof(*udp));

	/* Check if DHCP request (dest port 67) */
	if (udp->dest != bpf_htons(DHCP_SERVER_PORT))
		return XDP_PASS;

	/* Parse DHCP packet */
	struct dhcp_packet *dhcp = (void *)udp + sizeof(*udp);
	CHECK_BOUNDS(dhcp, data_end, sizeof(struct dhcp_packet));

	/* Verify BOOTREQUEST */
	if (dhcp->op != BOOTREQUEST)
		return XDP_PASS;

	/* Verify DHCP magic cookie */
	if (dhcp->magic != bpf_htonl(0x63825363))
		return XDP_PASS;

	/* Update total request counter */
	update_stats(0);

	/* Extract DHCP message type */
	__u8 msg_type = get_dhcp_msg_type(dhcp, data_end);
	if (msg_type != DHCP_DISCOVER && msg_type != DHCP_REQUEST) {
		/* Other message types (RELEASE, INFORM, etc.) go to slow path */
		update_stats(2);
		return XDP_PASS;
	}

	/* Extract client MAC address */
	__u64 mac_addr = mac_to_u64(dhcp->chaddr);

	/* Lookup subscriber in cache
	 * Strategy:
	 * 1. If packet has VLAN tags, try VLAN-based lookup first (QinQ mode)
	 * 2. Fall back to MAC-based lookup
	 */
	struct pool_assignment *assignment = NULL;

	/* For tagged packets, try VLAN-based lookup first */
	if (vinfo.vlan_depth > 0) {
		struct vlan_key vkey = {
			.s_tag = vinfo.s_tag,
			.c_tag = vinfo.c_tag,
		};
		assignment = bpf_map_lookup_elem(&vlan_subscriber_pools, &vkey);
	}

	/* Fall back to MAC-based lookup */
	if (!assignment) {
		assignment = bpf_map_lookup_elem(&subscriber_pools, &mac_addr);
	}

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

	/* Lookup pool metadata */
	struct ip_pool *pool = bpf_map_lookup_elem(&ip_pools, &assignment->pool_id);
	if (!pool) {
		/* Pool not found - error */
		update_stats(3);
		return XDP_PASS;
	}

	/* CACHE HIT - Fast path! Generate reply in kernel */
	update_stats(1);

	/* Get server configuration */
	__u32 config_key = 0;
	struct dhcp_server_config *config = bpf_map_lookup_elem(&server_config, &config_key);
	if (!config) {
		/* No server config - can't generate reply */
		update_stats(3);
		return XDP_PASS;
	}

	/* Determine reply type */
	__u8 reply_type = (msg_type == DHCP_DISCOVER) ? DHCP_OFFER : DHCP_ACK;

	/* === Build DHCP Reply === */

	/* Set proper MAC addresses for reply */
	set_reply_eth_addrs(eth, dhcp, config->server_mac);

	/* Server IP - use config if set, otherwise pool gateway */
	__u32 server_ip = (config->server_ip != 0) ? config->server_ip : pool->gateway;

	/* Build IP header for reply */
	ip->saddr = server_ip;
	ip->daddr = 0xFFFFFFFF;     /* Broadcast */
	ip->ttl = 64;
	ip->check = 0;

	/* Swap UDP ports */
	udp->source = bpf_htons(DHCP_SERVER_PORT);
	udp->dest = bpf_htons(DHCP_CLIENT_PORT);
	udp->check = 0;  /* UDP checksum optional for IPv4 */

	/* Build DHCP reply */
	dhcp->op = BOOTREPLY;
	dhcp->hops = 0;
	dhcp->yiaddr = assignment->allocated_ip;  /* Your IP address */
	dhcp->siaddr = server_ip;                 /* Server IP */
	/* Clear sname and file to avoid leaking request data */
	__builtin_memset(dhcp->sname, 0, sizeof(dhcp->sname));
	__builtin_memset(dhcp->file, 0, sizeof(dhcp->file));

	/* Build DHCP options */
	/* Ensure we have room for options (at least 64 bytes) */
	CHECK_BOUNDS_PASS(dhcp->options, data_end, MAX_DHCP_OPTIONS_LEN);

	int opt_len = build_dhcp_options(dhcp->options, data_end,
	                                  reply_type, pool, assignment,
	                                  server_ip);
	if (opt_len < 0) {
		update_stats(3);
		return XDP_PASS;
	}

	/* Calculate total packet size */
	__u16 dhcp_len = sizeof(struct dhcp_packet) + opt_len;
	__u16 udp_len = sizeof(struct udphdr) + dhcp_len;
	__u16 ip_len = sizeof(struct iphdr) + udp_len;
	__u16 total_len = sizeof(struct ethhdr) + ip_len;

	/* Calculate original packet size */
	__u16 orig_len = (__u16)((long)data_end - (long)data);

	/* Adjust packet tail if needed */
	int delta = (int)total_len - (int)orig_len;
	if (delta != 0) {
		if (bpf_xdp_adjust_tail(ctx, delta) != 0) {
			/* Failed to adjust - fall back to slow path */
			update_stats(3);
			return XDP_PASS;
		}
		/* Re-fetch data_end after adjustment */
		data_end = (void *)(long)ctx->data_end;
	}

	/* Update lengths in headers */
	ip->tot_len = bpf_htons(ip_len);
	udp->len = bpf_htons(udp_len);

	/* Calculate IP checksum */
	ip->check = ip_checksum(ip);

	/* UDP checksum is optional for IPv4, set to 0 */
	udp->check = 0;

	/* Transmit reply */
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
