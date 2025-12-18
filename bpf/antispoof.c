/* Anti-Spoofing / Source Address Validation - eBPF TC Program
 *
 * Implements uRPF (Unicast Reverse Path Forwarding) style source
 * address validation to prevent IP spoofing attacks.
 *
 * For BNG:
 * - Subscribers can only send packets from their assigned IP
 * - Prevents DoS amplification attacks
 * - Prevents source address spoofing
 *
 * Modes:
 * - Strict: Source IP must match subscriber's allocated IP exactly
 * - Loose: Source IP must be in any known subscriber range
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Maximum subscribers */
#define MAX_SUBSCRIBERS 1000000

/* Anti-spoof modes */
#define ANTISPOOF_DISABLED 0
#define ANTISPOOF_STRICT   1  /* Source must match allocated IP */
#define ANTISPOOF_LOOSE    2  /* Source must be in known range */
#define ANTISPOOF_LOG_ONLY 3  /* Log but don't drop */

/* Subscriber binding: MAC -> allowed source IP */
struct subscriber_binding {
	__u32 ipv4_addr;        /* Allowed IPv4 source address */
	__u8  ipv6_addr[16];    /* Allowed IPv6 source address */
	__u8  ipv4_valid;       /* IPv4 binding is valid */
	__u8  ipv6_valid;       /* IPv6 binding is valid */
	__u8  mode;             /* Anti-spoof mode for this subscriber */
	__u8  _pad;
};

/* Violation event for logging */
struct spoof_event {
	__u64 timestamp;
	__u8  src_mac[6];
	__u8  protocol;         /* 4 = IPv4, 6 = IPv6 */
	__u8  _pad;
	__u32 spoofed_ip;       /* Attempted spoofed IPv4 */
	__u32 allowed_ip;       /* Actually allowed IPv4 */
	__u8  spoofed_ipv6[16]; /* Attempted spoofed IPv6 */
	__u8  allowed_ipv6[16]; /* Actually allowed IPv6 */
};

/* Statistics */
struct antispoof_stats {
	__u64 packets_allowed;
	__u64 packets_dropped;
	__u64 packets_logged;
	__u64 ipv4_violations;
	__u64 ipv6_violations;
	__u64 unknown_mac;
};

/* MAC to binding map
 * Key: MAC address as __u64 (lower 48 bits)
 * Value: subscriber_binding struct
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SUBSCRIBERS);
	__type(key, __u64);
	__type(value, struct subscriber_binding);
} subscriber_bindings SEC(".maps");

/* Global configuration */
struct antispoof_config {
	__u8 default_mode;      /* Default mode for unknown MACs */
	__u8 log_violations;    /* Log violations to perf buffer */
	__u8 _pad[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct antispoof_config);
} antispoof_config SEC(".maps");

/* Statistics (per-CPU) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct antispoof_stats);
} antispoof_stats SEC(".maps");

/* Perf event buffer for violation logging */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} spoof_events SEC(".maps");

/* Allowed source IP ranges (LPM trie for loose mode) */
struct lpm_key_v4 {
	__u32 prefixlen;
	__u32 ip;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__type(key, struct lpm_key_v4);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allowed_ranges_v4 SEC(".maps");

/* Helper: Convert MAC bytes to u64 key */
static __always_inline __u64 mac_to_u64(unsigned char *mac) {
	return ((__u64)mac[0] << 40) |
	       ((__u64)mac[1] << 32) |
	       ((__u64)mac[2] << 24) |
	       ((__u64)mac[3] << 16) |
	       ((__u64)mac[4] << 8) |
	       ((__u64)mac[5]);
}

/* Helper: Update statistics */
static __always_inline void update_stats(int allowed, int ipv6) {
	__u32 key = 0;
	struct antispoof_stats *stats = bpf_map_lookup_elem(&antispoof_stats, &key);
	if (!stats)
		return;

	if (allowed) {
		__sync_fetch_and_add(&stats->packets_allowed, 1);
	} else {
		__sync_fetch_and_add(&stats->packets_dropped, 1);
		if (ipv6)
			__sync_fetch_and_add(&stats->ipv6_violations, 1);
		else
			__sync_fetch_and_add(&stats->ipv4_violations, 1);
	}
}

/* Helper: Log violation event */
static __always_inline void log_violation(void *ctx, unsigned char *mac,
					  __u32 spoofed_ip, __u32 allowed_ip,
					  int is_ipv6) {
	struct spoof_event event = {};
	event.timestamp = bpf_ktime_get_ns();
	event.protocol = is_ipv6 ? 6 : 4;

	/* Copy MAC */
	#pragma unroll
	for (int i = 0; i < 6; i++)
		event.src_mac[i] = mac[i];

	if (!is_ipv6) {
		event.spoofed_ip = spoofed_ip;
		event.allowed_ip = allowed_ip;
	}

	bpf_perf_event_output(ctx, &spoof_events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	/* Update logged counter */
	__u32 key = 0;
	struct antispoof_stats *stats = bpf_map_lookup_elem(&antispoof_stats, &key);
	if (stats)
		__sync_fetch_and_add(&stats->packets_logged, 1);
}

/* Helper: Check if IP is in allowed ranges (loose mode) */
static __always_inline int ip_in_allowed_range(__u32 ip) {
	struct lpm_key_v4 key = {
		.prefixlen = 32,
		.ip = ip,
	};

	return bpf_map_lookup_elem(&allowed_ranges_v4, &key) != NULL;
}

/* TC Ingress: Validate source addresses from subscribers */
SEC("tc/ingress")
int antispoof_ingress(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	/* Parse Ethernet header */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	/* Get source MAC */
	__u64 mac_key = mac_to_u64(eth->h_source);

	/* Get configuration */
	__u32 cfg_key = 0;
	struct antispoof_config *config = bpf_map_lookup_elem(&antispoof_config, &cfg_key);
	__u8 default_mode = config ? config->default_mode : ANTISPOOF_DISABLED;
	__u8 log_violations = config ? config->log_violations : 0;

	/* Look up subscriber binding */
	struct subscriber_binding *binding = bpf_map_lookup_elem(&subscriber_bindings, &mac_key);

	__u8 mode = binding ? binding->mode : default_mode;

	/* If disabled, allow all */
	if (mode == ANTISPOOF_DISABLED) {
		update_stats(1, 0);
		return TC_ACT_OK;
	}

	/* Handle IPv4 */
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + sizeof(*eth);
		if ((void *)(ip + 1) > data_end)
			return TC_ACT_OK;

		__u32 src_ip = ip->saddr;
		int allowed = 0;

		if (binding && binding->ipv4_valid) {
			/* Strict mode: exact match required */
			if (mode == ANTISPOOF_STRICT || mode == ANTISPOOF_LOG_ONLY) {
				allowed = (src_ip == binding->ipv4_addr);
			}
		} else if (mode == ANTISPOOF_LOOSE) {
			/* Loose mode: check if in any allowed range */
			allowed = ip_in_allowed_range(src_ip);
		}

		if (!allowed) {
			if (log_violations)
				log_violation(skb, eth->h_source, src_ip,
					      binding ? binding->ipv4_addr : 0, 0);

			if (mode == ANTISPOOF_LOG_ONLY) {
				update_stats(1, 0);
				return TC_ACT_OK;
			}

			update_stats(0, 0);
			return TC_ACT_SHOT;
		}

		update_stats(1, 0);
		return TC_ACT_OK;
	}

	/* Handle IPv6 */
	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + sizeof(*eth);
		if ((void *)(ip6 + 1) > data_end)
			return TC_ACT_OK;

		int allowed = 0;

		if (binding && binding->ipv6_valid) {
			/* Check IPv6 source address */
			allowed = 1;
			#pragma unroll
			for (int i = 0; i < 16; i++) {
				if (ip6->saddr.s6_addr[i] != binding->ipv6_addr[i]) {
					allowed = 0;
					break;
				}
			}
		} else if (mode == ANTISPOOF_LOOSE) {
			/* For loose mode with IPv6, we'd need an IPv6 LPM trie */
			/* For now, allow if no binding exists in loose mode */
			allowed = 1;
		}

		if (!allowed && mode != ANTISPOOF_LOG_ONLY) {
			if (log_violations)
				log_violation(skb, eth->h_source, 0, 0, 1);
			update_stats(0, 1);
			return TC_ACT_SHOT;
		}

		update_stats(1, 1);
		return TC_ACT_OK;
	}

	/* Non-IP traffic - allow */
	update_stats(1, 0);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
