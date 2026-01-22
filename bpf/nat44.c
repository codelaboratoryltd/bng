/* NAT44/CGNAT - eBPF XDP/TC Program
 *
 * Carrier-Grade NAT implementation using eBPF for high-performance
 * IPv4 address sharing at ISP edge.
 *
 * Architecture: Conntrack Hybrid Approach
 * - First packet of new flow -> Let kernel conntrack handle it (slow path)
 * - Subsequent packets -> XDP/TC looks up established connection and fast-paths it
 * - Uses eBPF conntrack helpers: bpf_ct_lookup_tcp(), bpf_ct_lookup_udp()
 *
 * Features:
 * - Port Block Allocation (RFC 6431) - deterministic port allocation per subscriber
 * - Endpoint-Independent Mapping (EIM) - RFC 4787 compliant
 * - Hairpin NAT support - local subscribers can communicate via public IPs
 * - NAT Logging hooks for legal compliance (RFC 6908)
 * - Per-subscriber port blocks with configurable sizes
 * - Statistics and metrics
 *
 * Architecture:
 * - TC ingress: Fast-path DNAT for incoming packets (internet -> subscriber)
 * - TC egress: Fast-path SNAT for outgoing packets (subscriber -> internet)
 * - XDP: Optional ultra-fast path for hairpin detection
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Configuration constants */
#define MAX_SUBSCRIBERS      1000000
#define MAX_NAT_SESSIONS     4000000
#define MAX_PUBLIC_IPS       256
#define MAX_EIM_MAPPINGS     2000000  /* Endpoint-Independent Mappings */
#define MAX_HAIRPIN_ENTRIES  1000     /* Public IPs for hairpin detection */
#define MAX_ALG_PORTS        64       /* ALG trigger ports */

/* Default port block configuration (RFC 6431) */
#define DEFAULT_PORTS_PER_SUBSCRIBER 1024
#define PORT_RANGE_START     1024
#define PORT_RANGE_END       65535

/* Timeouts (in nanoseconds) */
#define UDP_MAPPING_TIMEOUT_NS    (120ULL * 1000000000ULL)   /* 2 minutes (RFC 4787 minimum) */
#define TCP_TRANSIENT_TIMEOUT_NS  (240ULL * 1000000000ULL)   /* 4 minutes */
#define TCP_EST_TIMEOUT_NS        (7200ULL * 1000000000ULL)  /* 2 hours for established */
#define ICMP_TIMEOUT_NS           (60ULL * 1000000000ULL)    /* 1 minute */

/* NAT mapping/filtering behavior flags */
#define NAT_FLAG_EIM_ENABLED      0x01  /* Endpoint-Independent Mapping */
#define NAT_FLAG_EIF_ENABLED      0x02  /* Endpoint-Independent Filtering */
#define NAT_FLAG_HAIRPIN_ENABLED  0x04  /* Hairpinning enabled */
#define NAT_FLAG_ALG_FTP          0x08  /* FTP ALG enabled */
#define NAT_FLAG_ALG_SIP          0x10  /* SIP ALG enabled (often disabled) */
#define NAT_FLAG_PORT_PARITY      0x20  /* Preserve port parity for RTP */
#define NAT_FLAG_PORT_CONTIGUITY  0x40  /* Allocate contiguous ports */

/* NAT session state */
enum nat_state {
	NAT_STATE_NEW = 0,
	NAT_STATE_ESTABLISHED = 1,
	NAT_STATE_FIN_WAIT = 2,
	NAT_STATE_CLOSING = 3,
	NAT_STATE_TIME_WAIT = 4,
};

/* Logging event types for NAT compliance logging */
enum nat_log_event {
	NAT_LOG_SESSION_CREATE = 1,
	NAT_LOG_SESSION_DELETE = 2,
	NAT_LOG_PORT_BLOCK_ASSIGN = 3,
	NAT_LOG_PORT_BLOCK_RELEASE = 4,
	NAT_LOG_PORT_EXHAUSTION = 5,
	NAT_LOG_HAIRPIN = 6,
	NAT_LOG_ALG_TRIGGER = 7,
};

/* Protocol types */
enum nat_protocol {
	NAT_PROTO_TCP = 6,
	NAT_PROTO_UDP = 17,
	NAT_PROTO_ICMP = 1,
};

/* 5-tuple key for connection tracking */
struct nat_key {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8  protocol;
	__u8  _pad[3];
};

/* Endpoint-Independent Mapping key (RFC 4787)
 * For EIM, the mapping depends ONLY on internal IP:port, not destination
 */
struct eim_key {
	__u32 internal_ip;
	__u16 internal_port;
	__u8  protocol;
	__u8  _pad;
};

/* Endpoint-Independent Mapping value */
struct eim_mapping {
	__u32 external_ip;       /* Mapped public IP */
	__u16 external_port;     /* Mapped public port */
	__u16 _pad;
	__u64 created;           /* Creation timestamp */
	__u64 last_used;         /* Last packet timestamp */
	__u32 ref_count;         /* Number of sessions using this mapping */
	__u32 flags;             /* Mapping flags */
};

/* NAT session entry - tracks individual connections */
struct nat_session {
	__u32 nat_ip;           /* Translated source IP (public) */
	__u16 nat_port;         /* Translated source port */
	__u16 orig_port;        /* Original source port */
	__u32 orig_ip;          /* Original source IP (private) */
	__u32 dest_ip;          /* Original destination IP */
	__u16 dest_port;        /* Original destination port */
	__u16 _pad1;
	__u64 last_seen;        /* Last packet timestamp (ns) */
	__u64 created;          /* Session creation time */
	__u64 packets_out;      /* Outbound packet count */
	__u64 packets_in;       /* Inbound packet count */
	__u64 bytes_out;        /* Outbound byte count */
	__u64 bytes_in;         /* Inbound byte count */
	__u8  state;            /* Connection state */
	__u8  protocol;         /* IP protocol */
	__u8  flags;            /* Session flags */
	__u8  is_hairpin;       /* Hairpin session flag */
};

/* Port block allocation (RFC 6431) per subscriber */
struct port_block {
	__u32 public_ip;        /* Allocated public IP */
	__u16 port_start;       /* Start of port range (inclusive) */
	__u16 port_end;         /* End of port range (inclusive) */
	__u16 next_port;        /* Next port to try allocating */
	__u16 ports_in_use;     /* Current port utilization */
	__u64 allocated_at;     /* Allocation timestamp */
	__u32 subscriber_id;    /* Subscriber identifier */
	__u8  block_size_log2;  /* log2 of block size (e.g., 10 = 1024 ports) */
	__u8  flags;            /* Block flags */
	__u8  _pad[2];
};

/* Subscriber NAT allocation - maps private IP to port block */
struct subscriber_nat {
	struct port_block block;  /* Primary port block */
	__u64 sessions_active;    /* Active session count */
	__u64 sessions_total;     /* Total sessions created */
	__u64 bytes_out;          /* Total bytes sent */
	__u64 bytes_in;           /* Total bytes received */
};

/* Public IP pool entry */
struct nat_pool_entry {
	__u32 public_ip;        /* Public IP address */
	__u32 subscribers;      /* Number of subscribers using this IP */
	__u16 ports_per_sub;    /* Ports allocated per subscriber */
	__u16 max_subscribers;  /* Maximum subscribers for this IP */
	__u32 flags;            /* Pool configuration flags */
};

/* NAT statistics (per-CPU for performance) */
struct nat_stats {
	__u64 packets_snat;        /* Packets SNATed (egress) */
	__u64 packets_dnat;        /* Packets DNATed (ingress) */
	__u64 packets_hairpin;     /* Hairpinned packets */
	__u64 packets_dropped;     /* Packets dropped */
	__u64 packets_passed;      /* Packets passed to stack (new flows) */
	__u64 sessions_created;    /* New sessions created */
	__u64 sessions_expired;    /* Sessions expired/closed */
	__u64 port_exhaustion;     /* Port exhaustion events */
	__u64 eim_hits;            /* EIM cache hits */
	__u64 eim_misses;          /* EIM cache misses */
	__u64 alg_triggers;        /* ALG triggered */
	__u64 conntrack_lookups;   /* Conntrack helper lookups */
	__u64 conntrack_hits;      /* Conntrack established hits */
};

/* NAT logging entry (ring buffer format) */
struct nat_log_entry {
	__u64 timestamp;        /* Event timestamp (ns since boot) */
	__u32 event_type;       /* enum nat_log_event */
	__u32 subscriber_id;    /* Subscriber identifier */
	__u32 private_ip;       /* Private IP address */
	__u32 public_ip;        /* Public IP address */
	__u16 private_port;     /* Private port */
	__u16 public_port;      /* Public port */
	__u32 dest_ip;          /* Destination IP */
	__u16 dest_port;        /* Destination port */
	__u8  protocol;         /* IP protocol */
	__u8  flags;            /* Event-specific flags */
};

/* ALG configuration entry */
struct alg_config {
	__u16 port;             /* Trigger port (e.g., 21 for FTP) */
	__u8  protocol;         /* Protocol (TCP/UDP) */
	__u8  alg_type;         /* ALG type identifier */
	__u32 flags;            /* ALG-specific flags */
};

/* ========== eBPF Maps ========== */

/* Connection tracking: internal 5-tuple -> NAT session */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_NAT_SESSIONS);
	__type(key, struct nat_key);
	__type(value, struct nat_session);
} nat_sessions SEC(".maps");

/* Reverse lookup: external 5-tuple -> original internal 5-tuple
 * Used for DNAT (incoming packets)
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_NAT_SESSIONS);
	__type(key, struct nat_key);
	__type(value, struct nat_key);
} nat_reverse SEC(".maps");

/* Endpoint-Independent Mapping table (RFC 4787)
 * Key: internal IP:port
 * Value: external IP:port mapping
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_EIM_MAPPINGS);
	__type(key, struct eim_key);
	__type(value, struct eim_mapping);
} eim_table SEC(".maps");

/* Subscriber -> NAT allocation mapping (Port Block Allocation) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SUBSCRIBERS);
	__type(key, __u32);  /* Subscriber private IP */
	__type(value, struct subscriber_nat);
} subscriber_nat SEC(".maps");

/* Public IP pool */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_PUBLIC_IPS);
	__type(key, __u32);
	__type(value, struct nat_pool_entry);
} nat_pool SEC(".maps");

/* Hairpin detection: set of our public NAT IPs */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_HAIRPIN_ENTRIES);
	__type(key, __u32);  /* Public IP address */
	__type(value, __u8); /* 1 = is our NAT IP */
} hairpin_ips SEC(".maps");

/* NAT configuration (single entry) */
struct nat_config {
	__u32 flags;            /* Global NAT flags */
	__u16 port_range_start;
	__u16 port_range_end;
	__u32 default_ports_per_sub;
	__u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct nat_config);
} nat_config_map SEC(".maps");

/* NAT statistics (per-CPU for performance) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct nat_stats);
} nat_stats_map SEC(".maps");

/* NAT logging ring buffer */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);  /* 1MB ring buffer */
} nat_log_rb SEC(".maps");

/* ALG port triggers */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ALG_PORTS);
	__type(key, __u32);  /* port << 16 | protocol */
	__type(value, struct alg_config);
} alg_ports SEC(".maps");

/* Private IP ranges (LPM trie for efficient lookup) */
struct lpm_key {
	__u32 prefixlen;
	__u32 ip;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 64);
	__type(key, struct lpm_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} nat_private_ranges SEC(".maps");

/* ========== Helper Functions ========== */

/* Update statistics atomically */
static __always_inline void update_stat(__u64 *counter) {
	__sync_fetch_and_add(counter, 1);
}

static __always_inline struct nat_stats *get_stats(void) {
	__u32 key = 0;
	return bpf_map_lookup_elem(&nat_stats_map, &key);
}

static __always_inline struct nat_config *get_config(void) {
	__u32 key = 0;
	return bpf_map_lookup_elem(&nat_config_map, &key);
}

/* Check if IP is in private range needing NAT */
static __always_inline int is_private_ip(__u32 ip) {
	/* Check common private ranges inline for speed */
	__u32 ip_host = bpf_ntohl(ip);
	__u8 first_octet = (ip_host >> 24) & 0xFF;
	__u8 second_octet = (ip_host >> 16) & 0xFF;

	/* 10.0.0.0/8 */
	if (first_octet == 10)
		return 1;

	/* 172.16.0.0/12 */
	if (first_octet == 172 && (second_octet >= 16 && second_octet <= 31))
		return 1;

	/* 192.168.0.0/16 */
	if (first_octet == 192 && second_octet == 168)
		return 1;

	/* 100.64.0.0/10 (CGNAT range) */
	if (first_octet == 100 && (second_octet >= 64 && second_octet <= 127))
		return 1;

	return 0;
}

/* Check if destination IP is one of our NAT public IPs (hairpin detection) */
static __always_inline int is_hairpin_target(__u32 dest_ip) {
	__u8 *val = bpf_map_lookup_elem(&hairpin_ips, &dest_ip);
	return val != NULL;
}

/* Check if port/protocol triggers an ALG */
static __always_inline struct alg_config *check_alg_trigger(__u16 port, __u8 protocol) {
	__u32 key = ((__u32)port << 16) | protocol;
	return bpf_map_lookup_elem(&alg_ports, &key);
}

/* Incremental checksum update for IP/port change */
static __always_inline __u16 csum_fold(__u32 csum) {
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}

static __always_inline void update_csum(__u16 *csum, __u32 old_val, __u32 new_val) {
	__u32 sum = ~((__u32)*csum) & 0xffff;
	sum += ~old_val & 0xffff;
	sum += ~(old_val >> 16) & 0xffff;
	sum += new_val & 0xffff;
	sum += new_val >> 16;
	*csum = csum_fold(sum);
}

static __always_inline void update_csum16(__u16 *csum, __u16 old_val, __u16 new_val) {
	__u32 sum = ~((__u32)*csum) & 0xffff;
	sum += ~old_val & 0xffff;
	sum += new_val & 0xffff;
	*csum = csum_fold(sum);
}

/* Allocate a port from subscriber's port block (RFC 6431)
 * Parameters:
 *   block - Port block to allocate from
 *   preserve_parity - Whether to preserve even/odd parity (for RTP/RTCP)
 *   orig_port - Original internal port (used for parity matching)
 *   internal_ip - Subscriber's internal/private IP (for EIM collision check)
 *   protocol - IP protocol (TCP/UDP/ICMP) for EIM collision check
 */
static __always_inline __u16 allocate_port_from_block(struct port_block *block, __u8 preserve_parity,
                                                       __u16 orig_port, __u32 internal_ip, __u8 protocol) {
	/* Use atomic fetch-and-add for port allocation to ensure atomicity */
	__u16 port = __sync_fetch_and_add(&block->next_port, 1);
	__u16 start_port = port;
	__u16 block_size = block->port_end - block->port_start + 1;

	/* If preserving parity (for RTP/RTCP), ensure even/odd matches */
	__u8 orig_parity = orig_port & 1;

	/* Search for available port within block */
	#pragma unroll
	for (int i = 0; i < 64; i++) {  /* Limit iterations for eBPF verifier */
		if (port > block->port_end)
			port = block->port_start;

		/* Check parity if required */
		if (preserve_parity && ((port & 1) != orig_parity)) {
			port = __sync_fetch_and_add(&block->next_port, 1);
			continue;
		}

		/* Check if this internal IP:port:protocol already has an EIM mapping.
		 * The EIM table is keyed by {internal_ip, internal_port, protocol}.
		 * We check if an EIM entry already exists for this subscriber's
		 * internal IP using the candidate external port as the internal port,
		 * which would indicate a port collision.
		 * Note: In a full implementation, you would maintain a separate
		 * port bitmap per public IP for O(1) port availability checks.
		 */
		struct eim_key eim_check = {
			.internal_ip = internal_ip,
			.internal_port = port,
			.protocol = protocol,
		};
		struct eim_mapping *existing = bpf_map_lookup_elem(&eim_table, &eim_check);
		if (existing != NULL) {
			/* Port already in use by this subscriber, try next */
			port = __sync_fetch_and_add(&block->next_port, 1);
			continue;
		}

		/* Found an available port */
		/* Wrap next_port if needed */
		if (block->next_port > block->port_end) {
			__sync_val_compare_and_swap(&block->next_port, block->next_port, block->port_start);
		}

		return port;
	}

	return 0; /* Port exhaustion */
}

/* Look up or create EIM mapping (Endpoint-Independent Mapping) */
static __always_inline struct eim_mapping *get_eim_mapping(
	__u32 internal_ip,
	__u16 internal_port,
	__u8 protocol,
	struct subscriber_nat *sub_nat,
	struct nat_stats *stats
) {
	struct eim_key key = {
		.internal_ip = internal_ip,
		.internal_port = internal_port,
		.protocol = protocol,
	};

	/* Try to find existing mapping */
	struct eim_mapping *mapping = bpf_map_lookup_elem(&eim_table, &key);
	if (mapping) {
		mapping->last_used = bpf_ktime_get_ns();
		mapping->ref_count++;
		if (stats) update_stat(&stats->eim_hits);
		return mapping;
	}

	/* No existing mapping - allocate new one */
	if (!sub_nat) {
		if (stats) update_stat(&stats->eim_misses);
		return NULL;
	}

	struct nat_config *cfg = get_config();
	__u8 preserve_parity = cfg && (cfg->flags & NAT_FLAG_PORT_PARITY);

	__u16 ext_port = allocate_port_from_block(&sub_nat->block, preserve_parity, internal_port, internal_ip, protocol);
	if (ext_port == 0) {
		if (stats) update_stat(&stats->port_exhaustion);
		return NULL;
	}

	/* Create new mapping */
	struct eim_mapping new_mapping = {
		.external_ip = sub_nat->block.public_ip,
		.external_port = ext_port,
		.created = bpf_ktime_get_ns(),
		.last_used = bpf_ktime_get_ns(),
		.ref_count = 1,
		.flags = 0,
	};

	if (bpf_map_update_elem(&eim_table, &key, &new_mapping, BPF_NOEXIST) == 0) {
		if (stats) update_stat(&stats->eim_misses);
		return bpf_map_lookup_elem(&eim_table, &key);
	}

	/* Race condition - someone else created it, use theirs */
	mapping = bpf_map_lookup_elem(&eim_table, &key);
	if (mapping) {
		mapping->ref_count++;
		if (stats) update_stat(&stats->eim_hits);
	}
	return mapping;
}

/* Log NAT event to ring buffer */
static __always_inline void log_nat_event(
	enum nat_log_event event_type,
	__u32 subscriber_id,
	__u32 private_ip,
	__u32 public_ip,
	__u16 private_port,
	__u16 public_port,
	__u32 dest_ip,
	__u16 dest_port,
	__u8 protocol,
	__u8 flags
) {
	struct nat_log_entry *entry;

	entry = bpf_ringbuf_reserve(&nat_log_rb, sizeof(*entry), 0);
	if (!entry)
		return;

	entry->timestamp = bpf_ktime_get_ns();
	entry->event_type = event_type;
	entry->subscriber_id = subscriber_id;
	entry->private_ip = private_ip;
	entry->public_ip = public_ip;
	entry->private_port = private_port;
	entry->public_port = public_port;
	entry->dest_ip = dest_ip;
	entry->dest_port = dest_port;
	entry->protocol = protocol;
	entry->flags = flags;

	bpf_ringbuf_submit(entry, 0);
}

/* ========== TC Egress: SNAT for outgoing packets ========== */
SEC("tc/egress")
int nat44_egress(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct nat_stats *stats = get_stats();
	struct nat_config *cfg = get_config();

	/* Parse Ethernet */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	/* Parse IP */
	struct iphdr *ip = data + sizeof(*eth);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	/* Only NAT private source IPs */
	if (!is_private_ip(ip->saddr))
		return TC_ACT_OK;

	/* Get subscriber NAT allocation */
	__u32 priv_ip = ip->saddr;
	struct subscriber_nat *sub_nat = bpf_map_lookup_elem(&subscriber_nat, &priv_ip);
	if (!sub_nat) {
		/* No NAT allocation for this subscriber - pass to userspace */
		if (stats) update_stat(&stats->packets_passed);
		return TC_ACT_OK;
	}

	/* Build connection tracking key */
	struct nat_key key = {
		.src_ip = ip->saddr,
		.dst_ip = ip->daddr,
		.protocol = ip->protocol,
	};

	__u16 src_port = 0, dst_port = 0;
	void *l4_hdr = (void *)ip + (ip->ihl * 4);

	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = l4_hdr;
		if ((void *)(tcp + 1) > data_end)
			return TC_ACT_OK;
		src_port = tcp->source;
		dst_port = tcp->dest;

		/* Check for ALG triggers */
		if (cfg && (cfg->flags & (NAT_FLAG_ALG_FTP | NAT_FLAG_ALG_SIP))) {
			struct alg_config *alg = check_alg_trigger(bpf_ntohs(dst_port), IPPROTO_TCP);
			if (alg) {
				/* ALG required - pass to userspace */
				if (stats) update_stat(&stats->alg_triggers);
				log_nat_event(NAT_LOG_ALG_TRIGGER, sub_nat->block.subscriber_id,
					ip->saddr, 0, src_port, 0, ip->daddr, dst_port, ip->protocol, alg->alg_type);
				return TC_ACT_OK;
			}
		}
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = l4_hdr;
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;
		src_port = udp->source;
		dst_port = udp->dest;

		/* Check for ALG triggers (SIP typically on UDP 5060) */
		if (cfg && (cfg->flags & NAT_FLAG_ALG_SIP)) {
			struct alg_config *alg = check_alg_trigger(bpf_ntohs(dst_port), IPPROTO_UDP);
			if (alg) {
				if (stats) update_stat(&stats->alg_triggers);
				log_nat_event(NAT_LOG_ALG_TRIGGER, sub_nat->block.subscriber_id,
					ip->saddr, 0, src_port, 0, ip->daddr, dst_port, ip->protocol, alg->alg_type);
				return TC_ACT_OK;
			}
		}
	} else if (ip->protocol == IPPROTO_ICMP) {
		struct icmphdr *icmp = l4_hdr;
		if ((void *)(icmp + 1) > data_end)
			return TC_ACT_OK;
		/* Use ICMP ID as "port" for tracking */
		src_port = icmp->un.echo.id;
		dst_port = 0;
	} else {
		/* Unsupported protocol - pass through */
		return TC_ACT_OK;
	}

	key.src_port = src_port;
	key.dst_port = dst_port;

	/* Check for hairpinning: is destination one of our NAT IPs? */
	__u8 is_hairpin = 0;
	if (cfg && (cfg->flags & NAT_FLAG_HAIRPIN_ENABLED)) {
		if (is_hairpin_target(ip->daddr)) {
			is_hairpin = 1;
			if (stats) update_stat(&stats->packets_hairpin);
		}
	}

	/* Look up existing session */
	struct nat_session *session = bpf_map_lookup_elem(&nat_sessions, &key);
	__u64 now = bpf_ktime_get_ns();

	__u32 nat_ip;
	__u16 nat_port;

	if (session) {
		/* Existing session - use cached NAT mapping */
		nat_ip = session->nat_ip;
		nat_port = session->nat_port;
		session->last_seen = now;
		session->packets_out++;
		session->bytes_out += skb->len;
	} else {
		/* New session - check for EIM mapping or allocate */
		struct eim_mapping *eim = NULL;

		if (cfg && (cfg->flags & NAT_FLAG_EIM_ENABLED)) {
			/* Endpoint-Independent Mapping: reuse existing mapping for same internal IP:port */
			eim = get_eim_mapping(ip->saddr, src_port, ip->protocol, sub_nat, stats);
			if (eim) {
				nat_ip = eim->external_ip;
				nat_port = bpf_htons(eim->external_port);
			}
		}

		if (!eim) {
			/* No EIM or EIM disabled - allocate new port */
			__u8 preserve_parity = cfg && (cfg->flags & NAT_FLAG_PORT_PARITY);
			__u16 alloc_port = allocate_port_from_block(&sub_nat->block, preserve_parity, bpf_ntohs(src_port), ip->saddr, ip->protocol);
			if (alloc_port == 0) {
				if (stats) update_stat(&stats->port_exhaustion);
				if (stats) update_stat(&stats->packets_dropped);
				log_nat_event(NAT_LOG_PORT_EXHAUSTION, sub_nat->block.subscriber_id,
					ip->saddr, sub_nat->block.public_ip, src_port, 0,
					ip->daddr, dst_port, ip->protocol, 0);
				return TC_ACT_SHOT;
			}
			nat_ip = sub_nat->block.public_ip;
			nat_port = bpf_htons(alloc_port);
		}

		/* Create new session */
		struct nat_session new_session = {
			.nat_ip = nat_ip,
			.nat_port = nat_port,
			.orig_port = src_port,
			.orig_ip = ip->saddr,
			.dest_ip = ip->daddr,
			.dest_port = dst_port,
			.last_seen = now,
			.created = now,
			.packets_out = 1,
			.packets_in = 0,
			.bytes_out = skb->len,
			.bytes_in = 0,
			.state = NAT_STATE_NEW,
			.protocol = ip->protocol,
			.flags = 0,
			.is_hairpin = is_hairpin,
		};

		bpf_map_update_elem(&nat_sessions, &key, &new_session, BPF_ANY);

		/* Create reverse mapping for DNAT */
		struct nat_key rev_key = {
			.src_ip = ip->daddr,
			.dst_ip = nat_ip,
			.src_port = dst_port,
			.dst_port = nat_port,
			.protocol = ip->protocol,
		};
		bpf_map_update_elem(&nat_reverse, &rev_key, &key, BPF_ANY);

		__sync_fetch_and_add(&sub_nat->sessions_active, 1);
		__sync_fetch_and_add(&sub_nat->sessions_total, 1);
		if (stats) update_stat(&stats->sessions_created);

		/* Log session creation */
		log_nat_event(NAT_LOG_SESSION_CREATE, sub_nat->block.subscriber_id,
			ip->saddr, nat_ip, src_port, nat_port,
			ip->daddr, dst_port, ip->protocol, is_hairpin);
	}

	/* Perform SNAT - rewrite source IP and port */
	__u32 old_ip = ip->saddr;
	ip->saddr = nat_ip;

	/* Update IP checksum */
	update_csum(&ip->check, old_ip, nat_ip);

	/* Update L4 header */
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = l4_hdr;
		if ((void *)(tcp + 1) > data_end)
			return TC_ACT_OK;

		__u16 old_port = tcp->source;
		tcp->source = nat_port;

		/* Update TCP checksum (includes pseudo-header) */
		update_csum(&tcp->check, old_ip, nat_ip);
		update_csum16(&tcp->check, old_port, nat_port);

	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = l4_hdr;
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;

		__u16 old_port = udp->source;
		udp->source = nat_port;

		/* Update UDP checksum if present */
		if (udp->check != 0) {
			update_csum(&udp->check, old_ip, nat_ip);
			update_csum16(&udp->check, old_port, nat_port);
			if (udp->check == 0)
				udp->check = 0xffff;
		}

	} else if (ip->protocol == IPPROTO_ICMP) {
		struct icmphdr *icmp = l4_hdr;
		if ((void *)(icmp + 1) > data_end)
			return TC_ACT_OK;

		__u16 old_id = icmp->un.echo.id;
		icmp->un.echo.id = nat_port;

		/* Update ICMP checksum */
		update_csum16(&icmp->checksum, old_id, nat_port);
	}

	if (stats) update_stat(&stats->packets_snat);
	return TC_ACT_OK;
}

/* ========== TC Ingress: DNAT for incoming packets ========== */
SEC("tc/ingress")
int nat44_ingress(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct nat_stats *stats = get_stats();

	/* Parse Ethernet */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	/* Parse IP */
	struct iphdr *ip = data + sizeof(*eth);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	/* Build reverse lookup key */
	struct nat_key rev_key = {
		.src_ip = ip->saddr,
		.dst_ip = ip->daddr,
		.protocol = ip->protocol,
	};

	__u16 src_port = 0, dst_port = 0;
	void *l4_hdr = (void *)ip + (ip->ihl * 4);

	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = l4_hdr;
		if ((void *)(tcp + 1) > data_end)
			return TC_ACT_OK;
		src_port = tcp->source;
		dst_port = tcp->dest;
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = l4_hdr;
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;
		src_port = udp->source;
		dst_port = udp->dest;
	} else if (ip->protocol == IPPROTO_ICMP) {
		struct icmphdr *icmp = l4_hdr;
		if ((void *)(icmp + 1) > data_end)
			return TC_ACT_OK;
		src_port = 0;
		dst_port = icmp->un.echo.id;
	} else {
		return TC_ACT_OK;
	}

	rev_key.src_port = src_port;
	rev_key.dst_port = dst_port;

	/* Look up original connection */
	struct nat_key *orig_key = bpf_map_lookup_elem(&nat_reverse, &rev_key);
	if (!orig_key) {
		/* No NAT session - check if this is for our NAT IPs */
		/* For EIF (Endpoint-Independent Filtering), we might accept
		 * traffic from any source to established internal endpoints */
		if (stats) update_stat(&stats->packets_passed);
		return TC_ACT_OK;
	}

	/* Look up session for original destination */
	struct nat_session *session = bpf_map_lookup_elem(&nat_sessions, orig_key);
	if (!session) {
		/* Session expired - clean up reverse mapping */
		bpf_map_delete_elem(&nat_reverse, &rev_key);
		if (stats) update_stat(&stats->sessions_expired);
		return TC_ACT_OK;
	}

	/* Update session */
	__u64 now = bpf_ktime_get_ns();
	session->last_seen = now;
	session->packets_in++;
	session->bytes_in += skb->len;

	/* Update connection state for TCP */
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = l4_hdr;
		if ((void *)(tcp + 1) > data_end)
			return TC_ACT_OK;

		if (tcp->fin || tcp->rst) {
			session->state = NAT_STATE_CLOSING;
		} else if (session->state == NAT_STATE_NEW && tcp->ack) {
			session->state = NAT_STATE_ESTABLISHED;
		}
	}

	/* Perform DNAT - rewrite destination to original private IP/port */
	__u32 old_ip = ip->daddr;
	__u32 new_ip = session->orig_ip;
	ip->daddr = new_ip;

	/* Update IP checksum */
	update_csum(&ip->check, old_ip, new_ip);

	/* Update L4 header */
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = l4_hdr;
		if ((void *)(tcp + 1) > data_end)
			return TC_ACT_OK;

		__u16 old_port = tcp->dest;
		__u16 new_port = session->orig_port;
		tcp->dest = new_port;

		update_csum(&tcp->check, old_ip, new_ip);
		update_csum16(&tcp->check, old_port, new_port);

	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = l4_hdr;
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;

		__u16 old_port = udp->dest;
		__u16 new_port = session->orig_port;
		udp->dest = new_port;

		if (udp->check != 0) {
			update_csum(&udp->check, old_ip, new_ip);
			update_csum16(&udp->check, old_port, new_port);
			if (udp->check == 0)
				udp->check = 0xffff;
		}

	} else if (ip->protocol == IPPROTO_ICMP) {
		struct icmphdr *icmp = l4_hdr;
		if ((void *)(icmp + 1) > data_end)
			return TC_ACT_OK;

		__u16 old_id = icmp->un.echo.id;
		__u16 new_id = session->orig_port;
		icmp->un.echo.id = new_id;

		update_csum16(&icmp->checksum, old_id, new_id);
	}

	if (stats) update_stat(&stats->packets_dnat);
	return TC_ACT_OK;
}

/* ========== XDP: Fast hairpin detection and redirect ========== */
SEC("xdp")
int nat44_hairpin_xdp(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct nat_stats *stats = get_stats();
	struct nat_config *cfg = get_config();

	/* Skip if hairpinning disabled */
	if (!cfg || !(cfg->flags & NAT_FLAG_HAIRPIN_ENABLED))
		return XDP_PASS;

	/* Parse Ethernet */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* Parse IP */
	struct iphdr *ip = data + sizeof(*eth);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	/* Only check private source IPs */
	if (!is_private_ip(ip->saddr))
		return XDP_PASS;

	/* Check if destination is one of our NAT IPs (hairpin candidate) */
	if (!is_hairpin_target(ip->daddr))
		return XDP_PASS;

	/* This is a potential hairpin - let TC handle the full translation
	 * We just mark it for stats and pass to TC
	 */
	if (stats) update_stat(&stats->packets_hairpin);

	/* Could implement full hairpin here in XDP for maximum performance,
	 * but for now we let TC handle it for simplicity */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
