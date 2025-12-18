/* QoS Rate Limiting - eBPF TC Program
 *
 * Token bucket rate limiter for per-subscriber bandwidth control
 * Attached via TC (Traffic Control) for egress traffic shaping
 *
 * Algorithm: Token Bucket Filter (TBF)
 * - Tokens accumulate at configured rate (bits per second)
 * - Each packet consumes tokens equal to its size
 * - If insufficient tokens, packet is dropped or queued
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Maximum subscribers */
#define MAX_SUBSCRIBERS 1000000

/* Token bucket state per subscriber */
struct token_bucket {
	__u64 tokens;           /* Current tokens (in bytes) */
	__u64 last_update;      /* Last update timestamp (ns) */
	__u64 rate_bps;         /* Rate in bits per second */
	__u32 burst_bytes;      /* Maximum burst size in bytes */
	__u8  priority;         /* Traffic priority (0-7) */
	__u8  _pad[3];
};

/* QoS policy map: subscriber IP -> token bucket
 * Key: IPv4 address (network byte order)
 * Value: token_bucket struct
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SUBSCRIBERS);
	__type(key, __u32);   /* IPv4 address */
	__type(value, struct token_bucket);
} qos_egress SEC(".maps");

/* Ingress rate limiting (upload) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SUBSCRIBERS);
	__type(key, __u32);   /* IPv4 address */
	__type(value, struct token_bucket);
} qos_ingress SEC(".maps");

/* QoS statistics */
struct qos_stats {
	__u64 packets_passed;
	__u64 packets_dropped;
	__u64 bytes_passed;
	__u64 bytes_dropped;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct qos_stats);
} qos_stats_map SEC(".maps");

/* Update token bucket and check if packet can pass
 * Returns: 1 if packet allowed, 0 if should be dropped
 */
static __always_inline int token_bucket_check(struct token_bucket *tb, __u32 pkt_len) {
	__u64 now = bpf_ktime_get_ns();
	__u64 elapsed_ns;
	__u64 new_tokens;
	__u64 tokens_needed;

	/* Rate of 0 means unlimited */
	if (tb->rate_bps == 0)
		return 1;

	/* Calculate elapsed time since last update */
	elapsed_ns = now - tb->last_update;

	/* Calculate new tokens to add (rate_bps / 8 = bytes per second) */
	/* tokens = elapsed_ns * (rate_bps / 8) / 1e9 */
	/* Simplified: tokens = elapsed_ns * rate_bps / 8e9 */
	new_tokens = (elapsed_ns * (tb->rate_bps / 8)) / 1000000000ULL;

	/* Add tokens, capped at burst size */
	tb->tokens += new_tokens;
	if (tb->tokens > tb->burst_bytes)
		tb->tokens = tb->burst_bytes;

	/* Update timestamp */
	tb->last_update = now;

	/* Check if we have enough tokens for this packet */
	tokens_needed = pkt_len;
	if (tb->tokens >= tokens_needed) {
		tb->tokens -= tokens_needed;
		return 1; /* Allow */
	}

	return 0; /* Drop */
}

/* Update statistics */
static __always_inline void update_qos_stats(int passed, __u32 pkt_len) {
	__u32 key = 0;
	struct qos_stats *stats = bpf_map_lookup_elem(&qos_stats_map, &key);
	if (!stats)
		return;

	if (passed) {
		__sync_fetch_and_add(&stats->packets_passed, 1);
		__sync_fetch_and_add(&stats->bytes_passed, pkt_len);
	} else {
		__sync_fetch_and_add(&stats->packets_dropped, 1);
		__sync_fetch_and_add(&stats->bytes_dropped, pkt_len);
	}
}

/* TC egress program - rate limit download traffic to subscribers
 * Direction: BNG -> Subscriber
 * Key: destination IP (subscriber's IP)
 */
SEC("tc/egress")
int qos_egress_prog(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	/* Parse Ethernet header */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	/* Only process IPv4 */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	/* Parse IP header */
	struct iphdr *ip = data + sizeof(*eth);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	/* Get destination IP (subscriber) */
	__u32 dst_ip = ip->daddr;

	/* Lookup subscriber's QoS policy */
	struct token_bucket *tb = bpf_map_lookup_elem(&qos_egress, &dst_ip);
	if (!tb) {
		/* No policy = no rate limiting */
		return TC_ACT_OK;
	}

	/* Get packet length */
	__u32 pkt_len = skb->len;

	/* Check token bucket */
	int allowed = token_bucket_check(tb, pkt_len);

	/* Update stats */
	update_qos_stats(allowed, pkt_len);

	if (allowed) {
		/* Set priority based on policy */
		skb->priority = tb->priority;
		return TC_ACT_OK;
	}

	/* Drop packet - rate limit exceeded */
	return TC_ACT_SHOT;
}

/* TC ingress program - rate limit upload traffic from subscribers
 * Direction: Subscriber -> BNG
 * Key: source IP (subscriber's IP)
 */
SEC("tc/ingress")
int qos_ingress_prog(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	/* Parse Ethernet header */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	/* Only process IPv4 */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	/* Parse IP header */
	struct iphdr *ip = data + sizeof(*eth);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	/* Get source IP (subscriber) */
	__u32 src_ip = ip->saddr;

	/* Lookup subscriber's QoS policy */
	struct token_bucket *tb = bpf_map_lookup_elem(&qos_ingress, &src_ip);
	if (!tb) {
		/* No policy = no rate limiting */
		return TC_ACT_OK;
	}

	/* Get packet length */
	__u32 pkt_len = skb->len;

	/* Check token bucket */
	int allowed = token_bucket_check(tb, pkt_len);

	/* Update stats */
	update_qos_stats(allowed, pkt_len);

	if (allowed) {
		return TC_ACT_OK;
	}

	/* Drop packet - rate limit exceeded */
	return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
