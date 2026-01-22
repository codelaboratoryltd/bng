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
 *
 * Implements:
 * - Issue #14: Variable-length DHCP option parsing
 * - Issue #15: Option 82 (Relay Agent Information) support
 * - Issue #17: Proper L2 header construction for XDP_TX
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"

/* ========================================================================
 * Constants and Structures
 * ======================================================================== */

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

/* DHCP packet structure (fixed portion before options) */
struct dhcp_packet {
	__u8  op;           /* 1 = BOOTREQUEST, 2 = BOOTREPLY */
	__u8  htype;        /* Hardware address type (1 = Ethernet) */
	__u8  hlen;         /* Hardware address length (6 for MAC) */
	__u8  hops;         /* Hops */
	__u32 xid;          /* Transaction ID */
	__u16 secs;         /* Seconds elapsed */
	__u16 flags;        /* Flags (bit 15 = broadcast) */
	__u32 ciaddr;       /* Client IP address */
	__u32 yiaddr;       /* Your (client) IP address */
	__u32 siaddr;       /* Server IP address */
	__u32 giaddr;       /* Gateway IP address */
	__u8  chaddr[16];   /* Client hardware address */
	__u8  sname[64];    /* Server host name */
	__u8  file[128];    /* Boot file name */
	__u32 magic;        /* Magic cookie (0x63825363) */
	__u8  options[];    /* DHCP options (variable length) */
} __attribute__((packed));

/* DHCP ports */
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

/* DHCP message types */
#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_DECLINE  4
#define DHCP_ACK      5
#define DHCP_NAK      6
#define DHCP_RELEASE  7
#define DHCP_INFORM   8

/* DHCP magic cookie (network byte order) */
#define DHCP_MAGIC_COOKIE_NET 0x63538263

/* BOOTREQUEST/BOOTREPLY */
#define BOOTREQUEST 1
#define BOOTREPLY   2

/* Maximum DHCP options we'll write in reply */
#define MAX_DHCP_REPLY_OPTIONS_LEN 64

/* DHCP broadcast flag (bit 15) */
#define DHCP_FLAG_BROADCAST 0x8000

/* Broadcast MAC address */
static const __u8 BROADCAST_MAC[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* ========================================================================
 * Helper Macros (eBPF Verifier Safe)
 * ======================================================================== */

/* Bounds check that returns XDP_DROP on failure */
#define CHECK_BOUNDS_DROP(ptr, end, size) \
	if ((void *)(ptr) + (size) > (void *)(end)) \
		return XDP_DROP

/* Bounds check that returns XDP_PASS on failure (go to slow path) */
#define CHECK_BOUNDS_PASS(ptr, end, size) \
	if ((void *)(ptr) + (size) > (void *)(end)) \
		return XDP_PASS

/* ========================================================================
 * Statistics Helper
 * ======================================================================== */

/* Statistics counter indices */
enum stat_counter {
	STAT_TOTAL_REQUESTS = 0,
	STAT_FASTPATH_HIT,
	STAT_FASTPATH_MISS,
	STAT_ERROR,
	STAT_CACHE_EXPIRED,
	STAT_OPTION82_PRESENT,
	STAT_OPTION82_ABSENT,
	STAT_BROADCAST_REPLY,
	STAT_UNICAST_REPLY,
	STAT_VLAN_PACKET,
};

static __always_inline void update_stat(enum stat_counter counter) {
	__u32 key = 0;
	struct dhcp_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
	if (!stats)
		return;

	switch (counter) {
	case STAT_TOTAL_REQUESTS:
		__sync_fetch_and_add(&stats->total_requests, 1);
		break;
	case STAT_FASTPATH_HIT:
		__sync_fetch_and_add(&stats->fastpath_hits, 1);
		break;
	case STAT_FASTPATH_MISS:
		__sync_fetch_and_add(&stats->fastpath_misses, 1);
		break;
	case STAT_ERROR:
		__sync_fetch_and_add(&stats->errors, 1);
		break;
	case STAT_CACHE_EXPIRED:
		__sync_fetch_and_add(&stats->cache_expired, 1);
		break;
	case STAT_OPTION82_PRESENT:
		__sync_fetch_and_add(&stats->option82_present, 1);
		break;
	case STAT_OPTION82_ABSENT:
		__sync_fetch_and_add(&stats->option82_absent, 1);
		break;
	case STAT_BROADCAST_REPLY:
		__sync_fetch_and_add(&stats->broadcast_replies, 1);
		break;
	case STAT_UNICAST_REPLY:
		__sync_fetch_and_add(&stats->unicast_replies, 1);
		break;
	case STAT_VLAN_PACKET:
		__sync_fetch_and_add(&stats->vlan_packets, 1);
		break;
	}
}

/* ========================================================================
 * FNV-1a Hash for Circuit-ID (Issue #15)
 * ======================================================================== */

#define FNV1A_64_INIT  0xcbf29ce484222325ULL
#define FNV1A_64_PRIME 0x100000001b3ULL

/* Compute FNV-1a hash of buffer - verifier-safe bounded version */
static __always_inline __u64 fnv1a_hash(__u8 *data, __u8 len, void *data_end) {
	__u64 hash = FNV1A_64_INIT;

	/* Bound the loop for eBPF verifier */
	#pragma unroll
	for (int i = 0; i < MAX_CIRCUIT_ID_LEN; i++) {
		if (i >= len)
			break;
		if ((void *)(data + i + 1) > data_end)
			break;
		hash ^= data[i];
		hash *= FNV1A_64_PRIME;
	}

	return hash;
}

/* ========================================================================
 * MAC Address Utilities
 * ======================================================================== */

/* Convert MAC address bytes to u64 */
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

/* Update statistics counters (legacy interface) */
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

/* Copy MAC address with proper bounds checking */
static __always_inline void copy_mac(__u8 *dst, const __u8 *src) {
	#pragma unroll
	for (int i = 0; i < ETH_ALEN; i++) {
		dst[i] = src[i];
	}
}

/* Check if MAC is all zeros */
static __always_inline int is_zero_mac(__u8 *mac) {
	#pragma unroll
	for (int i = 0; i < ETH_ALEN; i++) {
		if (mac[i] != 0)
			return 0;
	}
	return 1;
}

/* ========================================================================
 * Issue #14: Variable-Length DHCP Option Parsing
 *
 * Implements safe, bounded option parsing that satisfies the eBPF verifier.
 * Supports:
 * - Option 53 (Message Type)
 * - Option 50 (Requested IP)
 * - Option 61 (Client Identifier)
 * - Option 82 (Relay Agent Information) with sub-options
 * - Proper handling of PAD (0) and END (255) options
 * ======================================================================== */

/* Parse Option 82 sub-options (Issue #15)
 * Called when Option 82 is found in the main option loop
 */
static __always_inline void parse_option82(__u8 *opt82_data, __u8 opt82_len,
                                           void *data_end,
                                           struct dhcp_parsed_options *opts) {
	__u32 offset = 0;

	/* Bound to maximum reasonable Option 82 size */
	if (opt82_len > 128)
		opt82_len = 128;

	/* Parse sub-options within Option 82 */
	#pragma unroll
	for (int i = 0; i < 16; i++) {
		/* Check if we've parsed all sub-options */
		if (offset >= opt82_len)
			break;

		/* Bounds check for sub-option type */
		__u8 *subopt_ptr = opt82_data + offset;
		if ((void *)(subopt_ptr + 2) > data_end)
			break;

		__u8 subopt_type = *subopt_ptr;
		__u8 subopt_len = *(subopt_ptr + 1);

		/* Sanity check sub-option length */
		if (subopt_len > 64 || offset + 2 + subopt_len > opt82_len)
			break;

		/* Bounds check for sub-option data */
		if ((void *)(subopt_ptr + 2 + subopt_len) > data_end)
			break;

		__u8 *subopt_data = subopt_ptr + 2;

		switch (subopt_type) {
		case OPT82_CIRCUIT_ID:
			/* Copy circuit-id (truncate if too long) */
			opts->circuit_id_len = (subopt_len > MAX_CIRCUIT_ID_LEN)
			                        ? MAX_CIRCUIT_ID_LEN : subopt_len;
			#pragma unroll
			for (int j = 0; j < MAX_CIRCUIT_ID_LEN; j++) {
				if (j >= opts->circuit_id_len)
					break;
				if ((void *)(subopt_data + j + 1) > data_end)
					break;
				opts->circuit_id[j] = subopt_data[j];
			}
			break;

		case OPT82_REMOTE_ID:
			/* Copy remote-id (truncate if too long) */
			opts->remote_id_len = (subopt_len > MAX_REMOTE_ID_LEN)
			                       ? MAX_REMOTE_ID_LEN : subopt_len;
			#pragma unroll
			for (int j = 0; j < MAX_REMOTE_ID_LEN; j++) {
				if (j >= opts->remote_id_len)
					break;
				if ((void *)(subopt_data + j + 1) > data_end)
					break;
				opts->remote_id[j] = subopt_data[j];
			}
			break;
		}

		offset += 2 + subopt_len;
	}
}

/* Parse all DHCP options from packet
 * Returns 0 on success, -1 on error
 */
static __always_inline int parse_dhcp_options(struct dhcp_packet *dhcp,
                                               void *data_end,
                                               struct dhcp_parsed_options *opts) {
	/* Initialize output structure */
	opts->msg_type = 0;
	opts->has_option82 = 0;
	opts->circuit_id_len = 0;
	opts->remote_id_len = 0;
	opts->requested_ip = 0;
	opts->client_id_len = 0;

	__u8 *options_start = dhcp->options;
	__u32 offset = 0;

	/*
	 * Bounded loop for eBPF verifier (Issue #14)
	 * We iterate up to MAX_DHCP_OPTIONS_ITER times, which is sufficient
	 * for real-world DHCP packets. The offset check ensures we don't
	 * read beyond the options area.
	 */
	#pragma unroll
	for (int i = 0; i < MAX_DHCP_OPTIONS_ITER; i++) {
		/* Stop if we've exceeded maximum scan length */
		if (offset >= MAX_DHCP_OPTIONS_SCAN_LEN)
			break;

		/* Bounds check for option code byte */
		__u8 *opt_ptr = options_start + offset;
		if ((void *)(opt_ptr + 1) > data_end)
			break;

		__u8 opt_code = *opt_ptr;

		/* Check for END option */
		if (opt_code == DHCP_OPT_END)
			break;

		/* Handle PAD option (single byte, no length field) */
		if (opt_code == DHCP_OPT_PAD) {
			offset++;
			continue;
		}

		/* Bounds check for option length byte */
		if ((void *)(opt_ptr + 2) > data_end)
			break;

		__u8 opt_len = *(opt_ptr + 1);

		/* Sanity check: option length shouldn't exceed reasonable bounds */
		if (opt_len > 255 || offset + 2 + opt_len > MAX_DHCP_OPTIONS_SCAN_LEN)
			break;

		/* Bounds check for option data */
		if ((void *)(opt_ptr + 2 + opt_len) > data_end)
			break;

		__u8 *opt_data = opt_ptr + 2;

		/* Process specific options */
		switch (opt_code) {
		case DHCP_OPT_MSG_TYPE:
			/* Option 53: DHCP Message Type (1 byte) */
			if (opt_len >= 1)
				opts->msg_type = *opt_data;
			break;

		case DHCP_OPT_REQUESTED_IP:
			/* Option 50: Requested IP Address (4 bytes) */
			if (opt_len >= 4 && (void *)(opt_data + 4) <= data_end)
				opts->requested_ip = *(__u32 *)opt_data;
			break;

		case DHCP_OPT_CLIENT_ID:
			/* Option 61: Client Identifier (variable) */
			opts->client_id_len = (opt_len > 64) ? 64 : opt_len;
			#pragma unroll
			for (int j = 0; j < 64; j++) {
				if (j >= opts->client_id_len)
					break;
				if ((void *)(opt_data + j + 1) > data_end)
					break;
				opts->client_id[j] = opt_data[j];
			}
			break;

		case DHCP_OPT_RELAY_AGENT_INFO:
			/* Option 82: Relay Agent Information (Issue #15) */
			opts->has_option82 = 1;
			parse_option82(opt_data, opt_len, data_end, opts);
			break;
		}

		/* Advance to next option */
		offset += 2 + opt_len;
	}

	return 0;
}

/* ========================================================================
 * Issue #17: L2 Header Construction for XDP_TX
 *
 * Proper handling of:
 * - MAC address swapping for unicast vs broadcast
 * - VLAN tag preservation
 * - DHCP broadcast flag respect
 * - Interface MAC discovery from server config
 * ======================================================================== */

/* Packet context structure to track headers after VLAN parsing */
struct pkt_ctx {
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct dhcp_packet *dhcp;
	void *data_end;
	__u16 vlan_id;           /* Outer VLAN ID (0 if untagged) */
	__u16 inner_vlan_id;     /* Inner VLAN ID for QinQ (0 if single-tagged) */
	int vlan_offset;         /* Bytes to skip for VLAN headers */
	int is_vlan_tagged;      /* Flag: packet has VLAN tag */
	int is_qinq;             /* Flag: packet has double VLAN tags */
};

/* Parse packet headers with VLAN support (Issue #17)
 * Returns 0 on success, -1 if not a DHCP packet
 */
static __always_inline int parse_packet_headers(struct xdp_md *ctx,
                                                 struct pkt_ctx *pkt) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	pkt->data_end = data_end;
	pkt->vlan_id = 0;
	pkt->inner_vlan_id = 0;
	pkt->vlan_offset = 0;
	pkt->is_vlan_tagged = 0;
	pkt->is_qinq = 0;

	/* Parse Ethernet header */
	pkt->eth = data;
	if ((void *)(pkt->eth + 1) > data_end)
		return -1;

	__be16 eth_proto = pkt->eth->h_proto;
	void *l3_start = (void *)(pkt->eth + 1);

	/* Handle VLAN tags (802.1Q and QinQ) */
	if (eth_proto == bpf_htons(ETH_P_8021Q) || eth_proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr = l3_start;
		if ((void *)(vhdr + 1) > data_end)
			return -1;

		pkt->is_vlan_tagged = 1;
		pkt->vlan_id = bpf_ntohs(vhdr->h_vlan_TCI) & 0x0FFF;
		pkt->vlan_offset = sizeof(struct vlan_hdr);
		eth_proto = vhdr->h_vlan_encapsulated_proto;
		l3_start = (void *)(vhdr + 1);

		update_stat(STAT_VLAN_PACKET);

		/* Check for QinQ (double tagging) */
		if (eth_proto == bpf_htons(ETH_P_8021Q)) {
			struct vlan_hdr *inner_vhdr = l3_start;
			if ((void *)(inner_vhdr + 1) > data_end)
				return -1;

			pkt->is_qinq = 1;
			pkt->inner_vlan_id = bpf_ntohs(inner_vhdr->h_vlan_TCI) & 0x0FFF;
			pkt->vlan_offset += sizeof(struct vlan_hdr);
			eth_proto = inner_vhdr->h_vlan_encapsulated_proto;
			l3_start = (void *)(inner_vhdr + 1);
		}
	}

	/* Only process IPv4 */
	if (eth_proto != bpf_htons(ETH_P_IP))
		return -1;

	/* Parse IP header */
	pkt->ip = l3_start;
	if ((void *)(pkt->ip + 1) > data_end)
		return -1;

	/* Only process UDP */
	if (pkt->ip->protocol != IPPROTO_UDP)
		return -1;

	/* Parse UDP header (account for IP header length) */
	pkt->udp = (void *)pkt->ip + (pkt->ip->ihl * 4);
	if ((void *)(pkt->udp + 1) > data_end)
		return -1;

	/* Check if DHCP request (dest port 67) */
	if (pkt->udp->dest != bpf_htons(DHCP_SERVER_PORT))
		return -1;

	/* Parse DHCP packet */
	pkt->dhcp = (void *)(pkt->udp + 1);
	if ((void *)(pkt->dhcp + 1) > data_end)
		return -1;

	return 0;
}

/* Set up L2 headers for DHCP reply (Issue #17)
 * Handles broadcast vs unicast based on:
 * 1. DHCP broadcast flag
 * 2. Client IP (ciaddr) - if set, use unicast
 * 3. Client MAC validity
 */
static __always_inline void setup_reply_l2_headers(struct pkt_ctx *pkt,
                                                    struct dhcp_server_config *config) {
	/* Get DHCP flags */
	__u16 flags = bpf_ntohs(pkt->dhcp->flags);
	int use_broadcast = 0;

	/* Determine if we should use broadcast (Issue #17) */
	if (flags & DHCP_FLAG_BROADCAST) {
		/* Client explicitly requested broadcast */
		use_broadcast = 1;
	} else if (pkt->dhcp->ciaddr == 0) {
		/* Client doesn't have an IP yet - typically DISCOVER/initial REQUEST */
		/* Check if client MAC is valid */
		if (is_zero_mac(pkt->dhcp->chaddr)) {
			/* Invalid client MAC - must use broadcast */
			use_broadcast = 1;
		} else {
			/*
			 * Client MAC is valid but no IP assigned yet.
			 * Some clients can receive unicast even without IP.
			 * For maximum compatibility, use broadcast for DISCOVER responses.
			 * The client can request unicast via the broadcast flag.
			 */
			use_broadcast = 1;
		}
	}
	/* else: ciaddr is set, client has IP, use unicast to client MAC */

	if (use_broadcast) {
		/* Set destination to broadcast MAC */
		copy_mac(pkt->eth->h_dest, BROADCAST_MAC);
		update_stat(STAT_BROADCAST_REPLY);
	} else {
		/* Set destination to client's MAC from DHCP chaddr field */
		copy_mac(pkt->eth->h_dest, pkt->dhcp->chaddr);
		update_stat(STAT_UNICAST_REPLY);
	}

	/* Set source MAC to server's MAC (Issue #17: use config, not hardcoded) */
	copy_mac(pkt->eth->h_source, config->server_mac);

	/*
	 * VLAN tags are preserved automatically with XDP_TX since we're
	 * modifying the packet in-place. The kernel maintains the VLAN
	 * headers we parsed earlier.
	 */
}

/* ========================================================================
 * IP Checksum Calculation
 * ======================================================================== */

static __always_inline __u16 ip_checksum(struct iphdr *ip) {
	__u32 sum = 0;
	__u16 *buf = (__u16 *)ip;

	/* IP header is 20 bytes = 10 16-bit words (assuming no IP options) */
	#pragma unroll
	for (int i = 0; i < 10; i++) {
		sum += buf[i];
	}

	/* Fold 32-bit sum to 16 bits */
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

/* ========================================================================
 * Helper Functions
 * ======================================================================== */

/* Generate subnet mask from prefix length */
static __always_inline __u32 prefix_to_mask(__u8 prefix_len) {
	if (prefix_len == 0)
		return 0;
	if (prefix_len >= 32)
		return 0xFFFFFFFF;
	return bpf_htonl(0xFFFFFFFF << (32 - prefix_len));
}

/* Build DHCP options for reply packet */
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

/* ========================================================================
 * Subscriber Lookup (Issue #15: Circuit-ID Support)
 * ======================================================================== */

/* Look up subscriber - tries circuit-id first if present, then MAC */
static __always_inline struct pool_assignment *lookup_subscriber(
		struct dhcp_packet *dhcp,
		struct dhcp_parsed_options *opts,
		void *data_end) {

	struct pool_assignment *assignment = NULL;

	/* If Option 82 present with circuit-id, try that first (Issue #15) */
	if (opts->has_option82 && opts->circuit_id_len > 0) {
		/* Hash the circuit-id for lookup */
		__u64 circuit_hash = fnv1a_hash(opts->circuit_id, opts->circuit_id_len, data_end);

		/* Look up MAC address associated with this circuit-id */
		__u64 *mac_ptr = bpf_map_lookup_elem(&circuit_id_map, &circuit_hash);
		if (mac_ptr) {
			/* Found circuit-id mapping, lookup subscriber by that MAC */
			assignment = bpf_map_lookup_elem(&subscriber_pools, mac_ptr);
			if (assignment)
				return assignment;
		}
		/* Circuit-id not found in map, fall through to MAC lookup */
	}

	/* Fall back to MAC-based lookup */
	__u64 mac_addr = mac_to_u64(dhcp->chaddr);
	assignment = bpf_map_lookup_elem(&subscriber_pools, &mac_addr);

	return assignment;
}

/* ========================================================================
 * Main XDP Program
 * ======================================================================== */

SEC("xdp")
int dhcp_fastpath_prog(struct xdp_md *ctx) {
	struct pkt_ctx pkt = {};

	/* Parse all packet headers with VLAN support (Issue #17) */
	if (parse_packet_headers(ctx, &pkt) < 0)
		return XDP_PASS;  /* Not a DHCP packet */

	/* Verify BOOTREQUEST */
	if (pkt.dhcp->op != BOOTREQUEST)
		return XDP_PASS;

	/* Verify DHCP magic cookie */
	if (pkt.dhcp->magic != bpf_htonl(0x63825363))
		return XDP_PASS;

	/* Update total request counter */
	update_stat(STAT_TOTAL_REQUESTS);

	/* Parse DHCP options (Issue #14: variable-length support) */
	struct dhcp_parsed_options opts = {};
	if (parse_dhcp_options(pkt.dhcp, pkt.data_end, &opts) < 0) {
		update_stat(STAT_ERROR);
		return XDP_PASS;
	}

	/* Only handle DISCOVER and REQUEST on fast path */
	if (opts.msg_type != DHCP_DISCOVER && opts.msg_type != DHCP_REQUEST) {
		update_stat(STAT_FASTPATH_MISS);
		return XDP_PASS;
	}

	/* Update Option 82 statistics (Issue #15) */
	if (opts.has_option82) {
		update_stat(STAT_OPTION82_PRESENT);
	} else {
		update_stat(STAT_OPTION82_ABSENT);
	}

	/* Lookup subscriber in cache
	 * Strategy:
	 * 1. If packet has VLAN tags, try VLAN-based lookup first (QinQ mode)
	 * 2. Try circuit-id lookup if Option 82 present (Issue #15)
	 * 3. Fall back to MAC-based lookup
	 */
	struct pool_assignment *assignment = NULL;

	/* For tagged packets, try VLAN-based lookup first */
	if (pkt.is_vlan_tagged) {
		struct vlan_key vkey = {
			.s_tag = pkt.vlan_id,
			.c_tag = pkt.inner_vlan_id,
		};
		assignment = bpf_map_lookup_elem(&vlan_subscriber_pools, &vkey);
	}

	/* If no VLAN match, try circuit-id or MAC lookup */
	if (!assignment) {
		assignment = lookup_subscriber(pkt.dhcp, &opts, pkt.data_end);
	}

	if (!assignment) {
		/* CACHE MISS - Pass to userspace (slow path) */
		update_stat(STAT_FASTPATH_MISS);
		return XDP_PASS;
	}

	/* Check if lease is still valid */
	__u64 now = bpf_ktime_get_ns() / 1000000000;  /* Convert to seconds */
	if (now > assignment->lease_expiry) {
		/* Lease expired - Pass to userspace for renewal */
		update_stat(STAT_CACHE_EXPIRED);
		return XDP_PASS;
	}

	/* Look up pool metadata */
	struct ip_pool *pool = bpf_map_lookup_elem(&ip_pools, &assignment->pool_id);
	if (!pool) {
		update_stat(STAT_ERROR);
		return XDP_PASS;
	}

	/* CACHE HIT - Fast path! Generate reply in kernel */
	update_stat(STAT_FASTPATH_HIT);

	/* Get server configuration (Issue #17: use for MAC address) */
	__u32 config_key = 0;
	struct dhcp_server_config *config = bpf_map_lookup_elem(&server_config, &config_key);
	if (!config) {
		update_stat(STAT_ERROR);
		return XDP_PASS;
	}

	/* Determine reply type */
	__u8 reply_type = (opts.msg_type == DHCP_DISCOVER) ? DHCP_OFFER : DHCP_ACK;

	/* === Build DHCP Reply === */

	/* Set up L2 headers for reply (Issue #17) */
	setup_reply_l2_headers(&pkt, config);

	/* Server IP - use config if set, otherwise pool gateway */
	__u32 server_ip = (config->server_ip != 0) ? config->server_ip : pool->gateway;

	/* Build IP header for reply */
	pkt.ip->saddr = server_ip;
	pkt.ip->daddr = 0xFFFFFFFF;  /* Broadcast at IP layer */
	pkt.ip->ttl = 64;
	pkt.ip->check = 0;

	/* Swap UDP ports */
	pkt.udp->source = bpf_htons(DHCP_SERVER_PORT);
	pkt.udp->dest = bpf_htons(DHCP_CLIENT_PORT);
	pkt.udp->check = 0;  /* UDP checksum optional for IPv4 */

	/* Build DHCP reply */
	pkt.dhcp->op = BOOTREPLY;
	pkt.dhcp->hops = 0;
	pkt.dhcp->yiaddr = assignment->allocated_ip;  /* Your IP address */
	pkt.dhcp->siaddr = server_ip;                 /* Server IP */

	/* Clear sname and file to avoid leaking request data */
	__builtin_memset(pkt.dhcp->sname, 0, sizeof(pkt.dhcp->sname));
	__builtin_memset(pkt.dhcp->file, 0, sizeof(pkt.dhcp->file));

	/* Build DHCP options */
	CHECK_BOUNDS_PASS(pkt.dhcp->options, pkt.data_end, MAX_DHCP_REPLY_OPTIONS_LEN);

	int opt_len = build_dhcp_options(pkt.dhcp->options, pkt.data_end,
	                                  reply_type, pool, assignment,
	                                  server_ip);
	if (opt_len < 0) {
		update_stat(STAT_ERROR);
		return XDP_PASS;
	}

	/* Calculate total packet size */
	__u16 dhcp_len = sizeof(struct dhcp_packet) + opt_len;
	__u16 udp_len = sizeof(struct udphdr) + dhcp_len;
	__u16 ip_len = sizeof(struct iphdr) + udp_len;
	__u16 l2_len = sizeof(struct ethhdr) + pkt.vlan_offset;
	__u16 total_len = l2_len + ip_len;

	/* Calculate original packet size */
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u16 orig_len = (__u16)((long)data_end - (long)data);

	/* Adjust packet tail if needed */
	int delta = (int)total_len - (int)orig_len;
	if (delta != 0) {
		if (bpf_xdp_adjust_tail(ctx, delta) != 0) {
			update_stat(STAT_ERROR);
			return XDP_PASS;
		}
		/* Note: After adjust_tail, we should re-validate pointers.
		 * However, since we're returning immediately after XDP_TX,
		 * and we've already built the reply content, this is safe.
		 */
	}

	/* Update lengths in headers */
	pkt.ip->tot_len = bpf_htons(ip_len);
	pkt.udp->len = bpf_htons(udp_len);

	/* Calculate IP checksum */
	pkt.ip->check = ip_checksum(pkt.ip);

	/* Transmit reply back on same interface */
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
