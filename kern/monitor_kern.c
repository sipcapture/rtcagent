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

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_tracing.h"

// #include "common2.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif
#define AF_INET 2

char __license[] SEC("license") = "Dual MIT/GPL";

/**
 * For CO-RE relocatable eBPF programs, __attribute__((preserve_access_index))
 * preserves the offset of the specified fields in the original kernel struct.
 * So here we don't need to include "vmlinux.h". Instead we only need to define
 * the kernel struct and their fields the eBPF program actually requires.
 *
 * Also note that BTF-enabled programs like fentry, fexit, fmod_ret, tp_btf,
 * lsm, etc. declared using the BPF_PROG macro can read kernel memory without
 * needing to call bpf_probe_read*().
 */

struct data_t
{
	u64 pid;
	u64 timestamp;
	u32 syscall_id;
};

enum func_data_event_type
{
    kSIPRead,
    kSIPWrite
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct data_t);
	__uint(max_entries, 1024);
} syscalls SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct func_data_event_t);
    __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");


struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events2 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct event's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */
struct event
{
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
	u32 srtt;
};
struct event *unused_event __attribute__((unused));

struct func_data_event_t
{
    enum func_data_event_type type;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u64 syscall_id;
    char comm[TASK_COMM_LEN];
};

static __inline struct func_data_event_t *create_sip_data_event(u64 current_pid_tgid, u64 timestamp)
{
    u32 kZero = 0;
    struct func_data_event_t *event =
        bpf_map_lookup_elem(&data_buffer_heap, &kZero);
    if (event == NULL)
    {
        return NULL;
    }

    const u32 kMask32b = 0xffffffff;
    event->pid = current_pid_tgid >> 32;
    event->tid = current_pid_tgid & kMask32b;
    event->timestamp_ns = timestamp;

    return event;
}

SEC("fentry/tcp_close")
int BPF_PROG(tcp_close2, struct sock *sk)
{

	// char fmt2[] = "TIMESTAMP: %d\n";
	// bpf_trace_printk(fmt2, sizeof(fmt2), 1);

	if (sk->__sk_common.skc_family != AF_INET)
	{
		return 0;
	}

	// The input struct sock is actually a tcp_sock, so we can type-cast
	struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
	if (!ts)
	{
		return 0;
	}

	struct event *tcp_info;
	tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!tcp_info)
	{
		return 0;
	}

	tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
	tcp_info->daddr = sk->__sk_common.skc_daddr;
	tcp_info->dport = bpf_ntohs(sk->__sk_common.skc_dport);
	tcp_info->sport = sk->__sk_common.skc_num;

	tcp_info->srtt = ts->srtt_us >> 3;
	tcp_info->srtt /= 1000;

	bpf_ringbuf_submit(tcp_info, 0);

	bpf_printk("  tcp_close2: ========== rt_sigtimedwait");

	return 0;
}

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	char comm[TASK_COMM_LEN];
	// char fname[TASK_COMM_LEN];
	u64 timestamp = bpf_ktime_get_ns();

	bpf_get_current_comm(&comm, sizeof(comm));
	int foundKamailio = 0;

	if (comm[0] == 'k' && comm[1] == 'a' && comm[2] == 'm' && comm[3] == 'a' && comm[4] == 'i' && comm[5] == 'l' &&
		comm[6] == 'i' && comm[7] == 'o' && comm[8] == '\0')
	{
		foundKamailio = 1;
	}

	if (foundKamailio == 0)
	{
		return 1;
	}

	u64 current_pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = current_pid_tgid >> 32;
	u64 current_uid_gid = bpf_get_current_uid_gid();
	u32 uid = current_uid_gid;

	unsigned long syscall_id = ctx->args[1];

	bpf_printk("Catched function call: %s; PID = : %d\n", comm, pid);
	// long syscall_id = ctx->filename_ptr;
	if (syscall_id == 62)
	{
		bpf_printk("  syscall_id: %u, function: %s\n", syscall_id, "sys_kill");
	}
	else if (syscall_id == 34)
	{
		bpf_printk("  syscall_id: %u, function: %s\n", syscall_id, "pause");
	}
	else if (syscall_id == 128)
	{
		bpf_printk("  syscall_id: %u, function: %s\n", syscall_id, "rt_sigtimedwait");
	}
	else if (syscall_id == 232)
	{
		bpf_printk("  syscall_id: %u, function: %s\n", syscall_id, "epoll_wait");
	}

	struct data_t data = {};
	data.pid = pid; // only process id
	data.timestamp = timestamp;
	data.syscall_id = syscall_id;

	bpf_map_update_elem(&syscalls, &current_pid_tgid, &data, BPF_ANY);

	// bpf_printk("  ss: %s\n", fname);
	// bpf_printk("  id: %u\n", id);

	// uint64_t arg3 = 0;
	// bpf_probe_read(&arg3, sizeof(uint64_t), PT_REGS_PARM3(regs));
	// bpf_printk("  Arg3: %u \n", arg3);

	struct func_data_event_t *event = create_sip_data_event(current_pid_tgid, timestamp);
    if (event == NULL)
    {
        return 0;
    }

    event->type = kSIPRead;
	event->syscall_id = syscall_id;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct func_data_event_t));

    bpf_map_delete_elem(&syscalls, &current_pid_tgid);

	return 0;
}
