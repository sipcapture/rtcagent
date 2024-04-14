/*

LINK - http://github.com/sipcapture/rtcagent

Copyright (C) 2024 QXIP B.V.

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
#include "bpf/bpf_core_read.h"

// #include "common2.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef TASK_FUNC_LEN
#define TASK_FUNC_LEN 32
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

// packed to avoid padding because the layout of the struct is significant
//#pragma pack(push, 1)

struct data_t
{
	u64 starttime_ns;
	u32 counter;
	u32 syscall_id;
}  __attribute__((packed));

enum func_data_event_type
{
	kSIPRead,
	kSIPWrite
};

struct
{
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct data_t);
} enter_id SEC(".maps");

//__uint(max_entries, 1024);

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct func_data_event_t);
	__uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct netevent_t);
	__uint(max_entries, 1);
} netdata_buffer_heap SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	//__uint(key_size, sizeof(u32));
	//__uint(value_size, sizeof(u32));
} netevents SEC(".maps");

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
}  __attribute__((packed));

struct event *unused_event __attribute__((unused));

struct func_data_event_t
{
	u8 event_type;
	u64 timestamp_ns;
	u32 pid;
	u32 tid;
	u32 syscall_id;
	u32 latency_ns;
	char comm[TASK_COMM_LEN];
	u32 nr_cpus_allowed;
	u32 recent_used_cpu;
	u32 exit_code;
	u64 cookie;
}  __attribute__((packed));


struct netevent_t
{
	u8 event_type;
	u64 timestamp_ns;
	u32 saddr_v4;
	u32 daddr_v4;
	u8 saddr_v6[16];
	u8 daddr_v6[16];
	u16 lport;
	u16 dport;
	u32 tid;
	u32 af;
	u32 pid;
	u64 delta_us;
	u64 ts_us;
	char comm[TASK_COMM_LEN];
} __attribute__((packed));

//#pragma pack(pop)

static __inline struct func_data_event_t *create_func_data_event(u64 current_pid_tgid, u64 timestamp)
{
	u32 kZero = 0;
	struct func_data_event_t *event =
		bpf_map_lookup_elem(&data_buffer_heap, &kZero);
	if (event == NULL)
	{
		return NULL;
	}

	const u32 kMask32b = 0xffffffff;
	event->event_type = 1;
	event->pid = current_pid_tgid >> 32;
	event->tid = current_pid_tgid & kMask32b;
	event->timestamp_ns = timestamp;

	return event;
}

static __inline struct netevent_t *create_net_event(u64 current_pid_tgid, u64 timestamp)
{
	u32 kZero = 0;
	struct netevent_t *event = bpf_map_lookup_elem(&netdata_buffer_heap, &kZero);
	if (event == NULL)
	{
		return NULL;
	}

	const u32 kMask32b = 0xffffffff;
	event->event_type = 2;
	event->pid = current_pid_tgid >> 32;
	event->tid = current_pid_tgid & kMask32b;
	event->timestamp_ns = timestamp;

	return event;
}

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	char comm[TASK_COMM_LEN];
	u64 timestamp = bpf_ktime_get_ns();
	struct data_t *ptr;
	struct task_struct *task;

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

	task = bpf_get_current_task_btf();
	if (task->pid != pid)
		return 0;

	bpf_printk("raw_tracepoint_sys_enter task_struct: Time: %d, CPUTime: %d\n", task->start_time, task->prev_cputime.stime);

	ptr = bpf_task_storage_get(&enter_id, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return 0;

	ptr->starttime_ns = timestamp;
	ptr->syscall_id = syscall_id;

	bpf_printk("raw_tracepoint_sys_enter function call: %s; PID = : %d, Time: %d\n", comm, pid, timestamp);
	bpf_printk("raw_tracepoint_sys_enter ptr: Sys: %d, Time: %d\n", ptr->syscall_id, ptr->starttime_ns);

	return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tracepoint_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
	char comm[TASK_COMM_LEN];
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

	bpf_printk("raw_tracepoint_sys_exit: %s; PID = : %u, Ts: %u\n", comm, pid, timestamp);

	struct func_data_event_t *event = create_func_data_event(current_pid_tgid, timestamp);
	if (event == NULL)
	{
		return 0;
	}

	struct task_struct *task;
	task = bpf_get_current_task_btf();
	if (task->pid != pid)
		return 0;

	struct data_t *ptr;
	ptr = bpf_task_storage_get(&enter_id, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return 0;

	event->syscall_id = ptr->syscall_id;
	event->timestamp_ns = timestamp;
	event->latency_ns = timestamp - ptr->starttime_ns;
	event->nr_cpus_allowed = task->nr_cpus_allowed;
	event->recent_used_cpu = task->recent_used_cpu;
	event->exit_code = task->exit_code;

	bpf_printk("raw_tracepoint_sys_exit Latency: %d, Exit code:%d, CPU:%d\n", event->latency_ns, task->exit_code, task->recent_used_cpu);

	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct func_data_event_t));

	return 0;
}

SEC("uprobe/user_function")
int user_function(struct pt_regs *ctx)
{
	char comm[TASK_COMM_LEN];
	u64 timestamp = bpf_ktime_get_ns();
	struct data_t *ptr;
	struct task_struct *task;

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
	unsigned long syscall_id = 100;

	task = bpf_get_current_task_btf();
	if (task->pid != pid)
		return 0;

	bpf_printk("user_function task_struct: Time: %d, CPUTime: %d\n", task->start_time, task->prev_cputime.stime);

	ptr = bpf_task_storage_get(&enter_id, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return 0;

	ptr->starttime_ns = timestamp;
	ptr->syscall_id = syscall_id;

	bpf_printk("user_function function call: %s; PID = : %d, Time: %d\n", comm, pid, timestamp);
	bpf_printk("user_function ptr: Sys: %d, Time: %d\n", ptr->syscall_id, ptr->starttime_ns);

	return 0;
}

SEC("uretprobe/user_function")
int user_ret_function(struct pt_regs *ctx)
{

	char comm[TASK_COMM_LEN];
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

	// u64 ip = PT_REGS_IP(ctx);
	// const char fmt_str[] = "return function fp %lld ip %lld\n";
	// bpf_trace_printk(fmt_str, sizeof(fmt_str), (void *)PT_REGS_FP(ctx), ip);

	u64 current_pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = current_pid_tgid >> 32;
	u64 current_uid_gid = bpf_get_current_uid_gid();
	u32 uid = current_uid_gid;

	bpf_printk("user_ret_function: %s; PID = : %u, Ts: %u\n", comm, pid, timestamp);

	struct func_data_event_t *event = create_func_data_event(current_pid_tgid, timestamp);
	if (event == NULL)
	{
		return 0;
	}

	struct task_struct *task;
	task = bpf_get_current_task_btf();
	if (task->pid != pid)
		return 0;

	struct data_t *ptr;
	ptr = bpf_task_storage_get(&enter_id, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return 0;

	__u64 cookie = bpf_get_attach_cookie(ctx);

	event->syscall_id = ptr->syscall_id;
	event->timestamp_ns = timestamp;
	event->latency_ns = timestamp - ptr->starttime_ns;
	event->nr_cpus_allowed = task->nr_cpus_allowed;
	event->recent_used_cpu = task->recent_used_cpu;
	event->exit_code = task->exit_code;
	event->cookie = cookie;

	bpf_printk("user_ret_function Latency: %d, Exit code:%d, CPU:%d\n", event->latency_ns, task->exit_code, task->recent_used_cpu);
	bpf_printk("Cookie: %lld\n", event->cookie);

	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct func_data_event_t));

	return 0;
}

static int trace_connect(struct sock *sk)
{
	/*

	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct piddata piddata = {};

	if (targ_tgid && targ_tgid != tgid)
		return 0;

	bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm));
	piddata.ts = bpf_ktime_get_ns();
	piddata.tgid = tgid;
	bpf_map_update_elem(&start, &sk, &piddata, 0);
	*/

	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{

	char comm[TASK_COMM_LEN];
	u64 timestamp = bpf_ktime_get_ns();
	struct data_t *ptr;
	struct task_struct *task;

	u64 current_pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = current_pid_tgid >> 32;
	u64 current_uid_gid = bpf_get_current_uid_gid();
	u32 uid = current_uid_gid;
	unsigned long syscall_id = 100;

	task = bpf_get_current_task_btf();

	bpf_printk("tcp_v4_connect - task: %d vs %d \n", task->pid, pid);

	if (task->pid != pid)
		return 0;

	bpf_get_current_comm(&comm, sizeof(comm));
	int foundKamailio = 0;

	if (comm[0] == 'k' && comm[1] == 'a' && comm[2] == 'm' && comm[3] == 'a' && comm[4] == 'i' && comm[5] == 'l' &&
		comm[6] == 'i' && comm[7] == 'o' && comm[8] == '\0')
	{
		foundKamailio = 1;
	}

	bpf_printk("tcp_v4_connect - conn : kama: %d - %s\n", foundKamailio, comm);

	if (foundKamailio == 0)
	{
		return 1;
	}

	bpf_printk("user_function task_struct: Time: %d, CPUTime: %d\n", task->start_time, task->prev_cputime.stime);

	ptr = bpf_task_storage_get(&enter_id, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return 0;

	ptr->starttime_ns = timestamp;
	ptr->syscall_id = syscall_id;

	bpf_printk("tcp_v4_connect call: %s; PID = : %d, Time: %d\n", comm, pid, timestamp);
	bpf_printk("tcp_v4_connect: Sys: %d, Time: %d\n", ptr->syscall_id, ptr->starttime_ns);

	// return trace_connect(sk);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_ret, int ret)
{

	char comm[TASK_COMM_LEN];
	u64 timestamp = bpf_ktime_get_ns();
	u64 current_pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = current_pid_tgid >> 32;
	u64 current_uid_gid = bpf_get_current_uid_gid();
	u32 uid = current_uid_gid;

	struct task_struct *task;
	task = bpf_get_current_task_btf();
	if (task->pid != pid)
		return 0;

	bpf_get_current_comm(&comm, sizeof(comm));
	int foundKamailio = 0;

	if (comm[0] == 'k' && comm[1] == 'a' && comm[2] == 'm' && comm[3] == 'a' && comm[4] == 'i' && comm[5] == 'l' &&
		comm[6] == 'i' && comm[7] == 'o' && comm[8] == '\0')
	{
		foundKamailio = 1;
	}

	bpf_printk("tcp_v4_connect - ret : kama: %d\n", foundKamailio);

	if (foundKamailio == 0)
	{
		return 1;
	}

	struct func_data_event_t *event = create_func_data_event(current_pid_tgid, timestamp);
	if (event == NULL)
	{
		return 0;
	}

	struct data_t *ptr;
	ptr = bpf_task_storage_get(&enter_id, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return 0;

	__u64 cookie = bpf_get_attach_cookie(ctx);

	event->syscall_id = ptr->syscall_id;
	event->timestamp_ns = timestamp;
	event->latency_ns = timestamp - ptr->starttime_ns;
	event->nr_cpus_allowed = task->nr_cpus_allowed;
	event->recent_used_cpu = task->recent_used_cpu;
	event->exit_code = task->exit_code;
	event->cookie = cookie;

	bpf_printk("user_ret_function Latency: %d, Exit code:%d, CPU:%d\n", event->latency_ns, task->exit_code, task->recent_used_cpu);
	bpf_printk("Cookie: %lld\n", event->cookie);

	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct func_data_event_t));

	return 0;
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(tcp_rcv_state_process, struct sock *sk)
{
	char comm[TASK_COMM_LEN];
	u64 timestamp = bpf_ktime_get_ns();
	u64 current_pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = current_pid_tgid >> 32;
	u64 current_uid_gid = bpf_get_current_uid_gid();
	u32 uid = current_uid_gid;

	struct task_struct *task;
	task = bpf_get_current_task_btf();
	if (task->pid != pid)
		return 0;

	bpf_get_current_comm(&comm, sizeof(comm));
	int foundKamailio = 0;

	if (comm[0] == 'k' && comm[1] == 'a' && comm[2] == 'm' && comm[3] == 'a' && comm[4] == 'i' && comm[5] == 'l' &&
		comm[6] == 'i' && comm[7] == 'o' && comm[8] == '\0')
	{
		foundKamailio = 1;
	}

	// if (foundKamailio == 0)
	//{
	//	return 1;
	// }

	struct data_t *ptr;
	ptr = bpf_task_storage_get(&enter_id, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return 0;

	__u64 cookie = bpf_get_attach_cookie(ctx);

	int state = BPF_CORE_READ(sk, __sk_common.skc_state);

	if (state != TCP_SYN_SENT)
	{
		bpf_printk("tcp_rcv_state_process - state: %d\n", state);
		return 0;
	}

	struct netevent_t *event = create_net_event(current_pid_tgid, timestamp);
	if (event == NULL)
	{
		return 0;
	}

	bpf_printk("tcp_rcv_state_process [1] - state: %d\n", state);

	event->ts_us = timestamp / 1000;
	event->lport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
	event->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	event->af = BPF_CORE_READ(sk, __sk_common.skc_family);

	bpf_printk("tcp_rcv_state_process PID: %d, TID :%d, TS: %d\n", event->pid, event->tid, event->ts_us);
	bpf_printk("tcp_rcv_state_process === PID: %d\n", pid);

	if (event->af == AF_INET)
	{
		event->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		event->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		bpf_printk("tcp_rcv_state_process Port: %d, Dport:%d, Af:%d\n", event->lport, event->dport, event->af);
		bpf_printk("tcp_rcv_state_process SA: %d, DA: :%d, TS: %d\n", event->saddr_v4, event->daddr_v4, event->ts_us);
	}
	/*
	else
	{
		BPF_CORE_READ_INTO(&event->saddr_v6, sk,
						   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&event->daddr_v6, sk,
						   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	*/

	// bpf_printk("tcp_rcv_state_process Latency: %d, Exit code:%d, CPU:%d\n", event->latency_ns, task->exit_code, task->recent_used_cpu);
	// bpf_printk("Cookie: %lld, State: %d\n", event->cookie, state);
	// bpf_get_current_comm(&event->comm, sizeof(event->comm));
	// bpf_perf_event_output(ctx, &netevents, BPF_F_CURRENT_CPU, &event, sizeof(event));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct netevent_t));

	// return trace_connect(sk);
	return 0;
}