//go:build ignore

#include "common.h"
#include "bpf_endian.h"

#define ETH_HLEN 14
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define DIR_INGRESS 0
#define DIR_EGRESS 1

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
};

struct flow_key {
	__u32 ifindex;
	__u8 family;
	__u8 direction;
	__u8 proto;
	__u8 pad;
	__u16 src_port;
	__u16 dst_port;
	__u8 src[16];
	__u8 dst[16];
};

struct flow_value {
	__u64 bytes;
	__u64 packets;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 262144);
	__type(key, struct flow_key);
	__type(value, struct flow_value);
} flows SEC(".maps");

static __always_inline void account_flow(struct flow_key *key, __u64 bytes) {
	struct flow_value zero = {};
	struct flow_value *value;

	value = bpf_map_lookup_elem(&flows, key);
	if (!value) {
		bpf_map_update_elem(&flows, key, &zero, BPF_NOEXIST);
		value = bpf_map_lookup_elem(&flows, key);
		if (!value) {
			return;
		}
	}

	__sync_fetch_and_add(&value->bytes, bytes);
	__sync_fetch_and_add(&value->packets, 1);
}

static __always_inline int parse_ports(struct __sk_buff *skb, __u32 offset, __u8 proto, struct flow_key *key) {
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
		return 0;
	}
	if (bpf_skb_load_bytes(skb, offset, &key->src_port, sizeof(key->src_port)) < 0) {
		return -1;
	}
	if (bpf_skb_load_bytes(skb, offset + 2, &key->dst_port, sizeof(key->dst_port)) < 0) {
		return -1;
	}
	return 0;
}

static __always_inline int account_ipv4(struct __sk_buff *skb, __u8 direction) {
	struct flow_key key = {};
	__u8 version_ihl;
	__u16 total_len;
	__u32 src;
	__u32 dst;
	__u32 ihl;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &version_ihl, sizeof(version_ihl)) < 0) {
		return TC_ACT_OK;
	}

	ihl = (version_ihl & 0x0f) * 4;
	if (ihl < 20 || ihl > 60) {
		return TC_ACT_OK;
	}

	if (bpf_skb_load_bytes(skb, ETH_HLEN + 2, &total_len, sizeof(total_len)) < 0) {
		return TC_ACT_OK;
	}
	if (bpf_skb_load_bytes(skb, ETH_HLEN + 9, &key.proto, sizeof(key.proto)) < 0) {
		return TC_ACT_OK;
	}
	if (bpf_skb_load_bytes(skb, ETH_HLEN + 12, &src, sizeof(src)) < 0) {
		return TC_ACT_OK;
	}
	if (bpf_skb_load_bytes(skb, ETH_HLEN + 16, &dst, sizeof(dst)) < 0) {
		return TC_ACT_OK;
	}

	key.ifindex = skb->ifindex;
	key.family = 4;
	key.direction = direction;
	__builtin_memcpy(key.src, &src, sizeof(src));
	__builtin_memcpy(key.dst, &dst, sizeof(dst));

	if (parse_ports(skb, ETH_HLEN + ihl, key.proto, &key) < 0) {
		return TC_ACT_OK;
	}

	account_flow(&key, bpf_ntohs(total_len));
	return TC_ACT_OK;
}

static __always_inline int account_ipv6(struct __sk_buff *skb, __u8 direction) {
	struct flow_key key = {};
	__u16 payload_len;

	if (bpf_skb_load_bytes(skb, ETH_HLEN + 4, &payload_len, sizeof(payload_len)) < 0) {
		return TC_ACT_OK;
	}
	if (bpf_skb_load_bytes(skb, ETH_HLEN + 6, &key.proto, sizeof(key.proto)) < 0) {
		return TC_ACT_OK;
	}
	if (bpf_skb_load_bytes(skb, ETH_HLEN + 8, key.src, 16) < 0) {
		return TC_ACT_OK;
	}
	if (bpf_skb_load_bytes(skb, ETH_HLEN + 24, key.dst, 16) < 0) {
		return TC_ACT_OK;
	}

	key.ifindex = skb->ifindex;
	key.family = 6;
	key.direction = direction;

	if (parse_ports(skb, ETH_HLEN + 40, key.proto, &key) < 0) {
		return TC_ACT_OK;
	}

	account_flow(&key, 40 + bpf_ntohs(payload_len));
	return TC_ACT_OK;
}

static __always_inline int account_packet(struct __sk_buff *skb, __u8 direction) {
	__u16 eth_proto;

	if (bpf_skb_load_bytes(skb, 12, &eth_proto, sizeof(eth_proto)) < 0) {
		return TC_ACT_OK;
	}

	if (eth_proto == bpf_htons(ETH_P_IP)) {
		return account_ipv4(skb, direction);
	}
	if (eth_proto == bpf_htons(ETH_P_IPV6)) {
		return account_ipv6(skb, direction);
	}
	return TC_ACT_OK;
}

SEC("tc")
int ingress_account(struct __sk_buff *skb) {
	return account_packet(skb, DIR_INGRESS);
}

SEC("tc")
int egress_account(struct __sk_buff *skb) {
	return account_packet(skb, DIR_EGRESS);
}

char __license[] SEC("license") = "Dual MIT/GPL";
