/*

LINK - http://github.com/sipcapture/rtcagent

Copyright (C) 2023 QXIP B.V.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "common2.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_tracing.h"

#define AF_INET 2
#define AF_INET6 10

char __license[] SEC("license") = "Dual MIT/GPL";

struct in6_addr {
	__u8 s6_addr[16];
} __attribute__((preserve_access_index));

struct sk_buff {} __attribute__((preserve_access_index));

struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
	struct in6_addr skc_v6_rcv_saddr;
	struct in6_addr skc_v6_daddr;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct tcp_sock {
	u32 srtt_us;
} __attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, u32);
} rtt_cache SEC(".maps");

struct event {
	u16 sport;
	u16 dport;
	u8 family;
	u8 _pad[3];
	u32 srtt;
	u32 saddr;
	u32 daddr;
	u8 saddr6[16];
	u8 daddr6[16];
};
struct event *unused_event __attribute__((unused));

static __always_inline u32 srtt_to_ms(u32 srtt_us)
{
	if (!srtt_us)
		return 0;
	return (srtt_us >> 3) / 1000;
}

static __always_inline void cache_srtt(struct sock *sk, u32 srtt_ms)
{
	u64 key = (u64)sk;
	bpf_map_update_elem(&rtt_cache, &key, &srtt_ms, BPF_ANY);
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv_established, struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
	if (!ts)
		return 0;

	cache_srtt(sk, srtt_to_ms(ts->srtt_us));
	return 0;
}

static __always_inline int emit_tcp_rtt(struct sock *sk)
{
	struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
	if (!ts)
		return 0;

	struct event *tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!tcp_info)
		return 0;

	u16 family = sk->__sk_common.skc_family;
	u32 srtt_ms = srtt_to_ms(ts->srtt_us);
	if (!srtt_ms) {
		u64 key = (u64)sk;
		u32 *cached = bpf_map_lookup_elem(&rtt_cache, &key);
		if (cached)
			srtt_ms = *cached;
	}

	tcp_info->family = (__u8)family;
	tcp_info->sport = sk->__sk_common.skc_num;
	tcp_info->dport = bpf_ntohs(sk->__sk_common.skc_dport);
	tcp_info->srtt = srtt_ms;

	if (family == AF_INET6) {
		__builtin_memcpy(tcp_info->saddr6, &sk->__sk_common.skc_v6_rcv_saddr, 16);
		__builtin_memcpy(tcp_info->daddr6, &sk->__sk_common.skc_v6_daddr, 16);
		tcp_info->saddr = 0;
		tcp_info->daddr = 0;
	} else {
		tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
		tcp_info->daddr = sk->__sk_common.skc_daddr;
		__builtin_memset(tcp_info->saddr6, 0, 16);
		__builtin_memset(tcp_info->daddr6, 0, 16);
	}

	bpf_ringbuf_submit(tcp_info, 0);
	return 0;
}

SEC("fentry/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk)
{
	if (sk->__sk_common.skc_family != AF_INET && sk->__sk_common.skc_family != AF_INET6)
		return 0;

	return emit_tcp_rtt(sk);
}
