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

#include "kamailio.h"

#define MAX_MEDIA_SIZE 1500

#if defined(__TARGET_ARCH_x86)
#define SYSCALL_RECVFROM 45
#define SYSCALL_SENDTO 44
#elif defined(__TARGET_ARCH_arm64)
#define SYSCALL_RECVFROM 207
#define SYSCALL_SENDTO 206
#else
#define SYSCALL_RECVFROM 45
#define SYSCALL_SENDTO 44
#endif

enum media_data_event_type {
	kMediaRead,
	kMediaWrite
};

struct syscall_data_t {
	u64 timestamp;
	const char *buf;
	u64 len;
	const void *addr;
	const int *addrlen;
	u8 direction;
};

struct media_data_event_t {
	enum media_data_event_type type;
	u64 timestamp_ns;
	u32 pid;
	u32 tid;
	struct ip_addr src_ip;
	struct ip_addr dst_ip;
	u16 src_port;
	u16 dst_port;
	s32 data_len;
	char data[MAX_MEDIA_SIZE];
	char comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct syscall_data_t);
	__uint(max_entries, 4096);
} syscall_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct media_data_event_t);
	__uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

static __always_inline int is_rtpengine_process(void)
{
	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(&comm, sizeof(comm));

	if (comm[0] != 'r' || comm[1] != 't' || comm[2] != 'p' || comm[3] != 'e' ||
	    comm[4] != 'n' || comm[5] != 'g' || comm[6] != 'i' || comm[7] != 'n' ||
	    comm[8] != 'e')
		return 0;

	return 1;
}

static __always_inline int should_trace_process(u32 pid, u32 uid)
{
#ifndef KERNEL_LESS_5_2
	if (target_pid != 0 && target_pid != pid)
		return 0;
	if (target_uid != 0 && target_uid != uid)
		return 0;
#endif
	return is_rtpengine_process();
}

static __always_inline unsigned short rtp_su_getport(const union sockaddr_union *su)
{
	switch (su->s.sa_family) {
	case AF_INET:
		return bpf_ntohs(su->sin.sin_port);
	case AF_INET6:
		return bpf_ntohs(su->sin6.sin6_port);
	default:
		return 0;
	}
}

static __inline struct media_data_event_t *create_media_event(u64 current_pid_tgid, u64 timestamp)
{
	u32 kZero = 0;
	struct media_data_event_t *event = bpf_map_lookup_elem(&data_buffer_heap, &kZero);
	if (!event)
		return NULL;

	const u32 kMask32b = 0xffffffff;
	event->pid = current_pid_tgid >> 32;
	event->tid = current_pid_tgid & kMask32b;
	event->timestamp_ns = timestamp;
	return event;
}

static __always_inline int emit_media_event(struct pt_regs *ctx, u64 current_pid_tgid,
					    enum media_data_event_type type,
					    struct syscall_data_t *data, long ret)
{
	if (ret <= 0 || ret > MAX_MEDIA_SIZE)
		return 0;

	struct media_data_event_t *event = create_media_event(current_pid_tgid, data->timestamp);
	if (!event)
		return 0;

	event->type = type;
	event->data_len = (s32)ret;
	bpf_probe_read_user(event->data, event->data_len, data->buf);
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	union sockaddr_union peer = {};
	if (data->addr && data->addrlen) {
		int addrlen = 0;
		bpf_probe_read_user(&addrlen, sizeof(addrlen), data->addrlen);
		if (addrlen > 0)
			bpf_probe_read_user(&peer, addrlen & 127, data->addr);
	}

	__builtin_memset(&event->src_ip, 0, sizeof(event->src_ip));
	__builtin_memset(&event->dst_ip, 0, sizeof(event->dst_ip));
	event->src_port = 0;
	event->dst_port = 0;

	if (type == kMediaRead) {
		su2ip_addr(&event->src_ip, &peer);
		event->src_port = rtp_su_getport(&peer);
	} else {
		su2ip_addr(&event->dst_ip, &peer);
		event->dst_port = rtp_su_getport(&peer);
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
			      sizeof(struct media_data_event_t));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter")
int tracepoint_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	u64 current_pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = current_pid_tgid >> 32;
	u32 uid = bpf_get_current_uid_gid();

	if (!should_trace_process(pid, uid))
		return 0;

	if (ctx->id != SYSCALL_RECVFROM && ctx->id != SYSCALL_SENDTO)
		return 0;

	struct syscall_data_t data = {};
	data.timestamp = bpf_ktime_get_ns();
	data.buf = (const char *)ctx->args[1];
	data.len = ctx->args[2];
	data.addr = (const void *)ctx->args[4];
	data.addrlen = (const int *)ctx->args[5];
	data.direction = (ctx->id == SYSCALL_RECVFROM) ? kMediaRead : kMediaWrite;

	bpf_map_update_elem(&syscall_hash, &current_pid_tgid, &data, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit")
int tracepoint_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	u64 current_pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = current_pid_tgid >> 32;
	u32 uid = bpf_get_current_uid_gid();

	if (!should_trace_process(pid, uid))
		return 0;

	struct syscall_data_t *data = bpf_map_lookup_elem(&syscall_hash, &current_pid_tgid);
	if (!data)
		return 0;

	enum media_data_event_type type = data->direction;
	int ret = emit_media_event((struct pt_regs *)ctx, current_pid_tgid, type, data, ctx->ret);
	bpf_map_delete_elem(&syscall_hash, &current_pid_tgid);
	return ret;
}
