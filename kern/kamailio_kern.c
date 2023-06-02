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

typedef struct receive_info
{
    struct ip_addr src_ip;
    struct ip_addr dst_ip;
    unsigned short src_port; /* host byte order */
    unsigned short dst_port; /* host byte order */
} receive_info_t;

enum sip_data_event_type
{
    kSIPRead,
    kSIPWrite
};

struct data_t
{
    u64 pid;
    u64 timestamp;
    const char *buf;
    u64 len;
    const void *rcvinfo;
    char comm[TASK_COMM_LEN];
    s8 retval; // dispatch_command return value
};

/*
u16 src_port;
    u16 dst_port;
    u8 src_ipv6;
    u8 dst_ipv6;
*/

struct sip_data_event_t
{
    enum sip_data_event_type type;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    receive_info_t rcinfo;
    char data[MAX_DATA_SIZE_SIP];
    s32 data_len;
    char comm[TASK_COMM_LEN];
};

//__attribute__((packed))

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct data_t);
    __uint(max_entries, 1024);
} sip_hash_recv SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct data_t);
    __uint(max_entries, 1024);
} sip_hash_send SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct sip_data_event_t);
    __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct socket_info);
    __uint(max_entries, 1);
} socket_info_heap SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

/***********************************************************
 * BPF syscall processing functions
 ***********************************************************/

/* gets the port number (host byte order) */
static inline unsigned short su_getport(const union sockaddr_union *su)
{
    switch (su->s.sa_family)
    {
    case AF_INET:
        return bpf_ntohs(su->sin.sin_port);
    case AF_INET6:
        return bpf_ntohs(su->sin6.sin6_port);
    default:
        return 0;
    }
}

static __inline struct sip_data_event_t *create_sip_data_event(u64 current_pid_tgid, u64 timestamp)
{
    u32 kZero = 0;
    struct sip_data_event_t *event =
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

static int process_sip_data(struct pt_regs *ctx, u64 id, enum sip_data_event_type type, struct data_t *data)
{
    char fmt2[] = "TIMESTAMP: %lld\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), data->timestamp);

    if (data->len < 0)
    {
        return 0;
    }

    struct sip_data_event_t *event = create_sip_data_event(id, data->timestamp);
    if (event == NULL)
    {
        return 0;
    }

    event->type = type;
    event->data_len = (data->len < MAX_DATA_SIZE_SIP ? (data->len & (MAX_DATA_SIZE_SIP - 1))
                                                     : MAX_DATA_SIZE_SIP);

    bpf_probe_read_user(event->data, event->data_len, data->buf);

    if (type == kSIPRead)
    {
        bpf_probe_read(&event->rcinfo, sizeof(event->rcinfo), data->rcvinfo);
    }
    else
    {
        dest_info_t dest;
        bpf_probe_read(&dest, sizeof(dest_info_t), data->rcvinfo);

        u16 dst_port = su_getport(&dest.to);
        char fmt1[] = "PORT DST: %d\n";
        bpf_trace_printk(fmt1, sizeof(fmt1), dst_port);

        event->rcinfo.dst_port = dst_port;
        su2ip_addr(&event->rcinfo.dst_ip, &dest.to);

        data->rcvinfo = dest.send_sock;

        u32 kZero = 0;
        struct socket_info *send_sock = bpf_map_lookup_elem(&socket_info_heap, &kZero);

        if (!send_sock)
            return 0;

        bpf_probe_read(send_sock, sizeof(struct socket_info), data->rcvinfo);
        event->rcinfo.src_port = send_sock->port_no;

        __builtin_memcpy(&event->rcinfo.src_ip, &send_sock->address, sizeof(event->rcinfo.src_ip));

        char fmt8[] = "PORT SRC: %d\n";
        bpf_trace_printk(fmt8, sizeof(fmt8), send_sock->port_no);
    }

    char fmt8[] = "len10 %s\n";
    bpf_trace_printk(fmt8, sizeof(fmt8), event->data);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct sip_data_event_t));
    return 0;
}

SEC("uprobe/receive_msg")
int kamailio_receive_msg(struct pt_regs *ctx)
{

    // debug_bpf_printk("kamailio ======================================= d\n");

    u64 timestamp = bpf_ktime_get_ns();
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid)
    {
        return 0;
    }
    if (target_uid != 0 && target_uid != uid)
    {
        return 0;
    }
#endif

    u64 len = (u64)PT_REGS_PARM2(ctx);
    if (len < 0)
    {
        return 0;
    }

    char fmt2[] = "kamailio_query: %d\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), pid);

    struct data_t data = {};
    data.pid = pid; // only process id
    data.len = len; // origin query sql length
    data.timestamp = timestamp;
    data.retval = -1;

    const char *buf = (const char *)PT_REGS_PARM1(ctx);
    data.buf = buf;

    const void *rcvinfo = (void *)PT_REGS_PARM3(ctx);
    data.rcvinfo = rcvinfo;

    bpf_map_update_elem(&sip_hash_recv, &current_pid_tgid, &data, BPF_ANY);

    return 0;
}

SEC("uretprobe/receive_msg")
int kamailio_ret_receive_msg(struct pt_regs *ctx)
{
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid)
    {
        return 0;
    }
    if (target_uid != 0 && target_uid != uid)
    {
        return 0;
    }
#endif

    debug_bpf_printk("receive ret :%d\n", pid);
    int len = (int)PT_REGS_RC(ctx);
    char fmt2[] = "len4a: %d\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), len);

    struct data_t *data = bpf_map_lookup_elem(&sip_hash_recv, &current_pid_tgid);
    if (!data)
    {
        return 0; // missed start
    }

    if (data->buf != NULL)
    {
        char fmt5[] = "len5 %d\n";
        bpf_trace_printk(fmt5, sizeof(fmt5), data->len);
        process_sip_data(ctx, current_pid_tgid, kSIPRead, data);
    }

    bpf_map_delete_elem(&sip_hash_recv, &current_pid_tgid);
    return 0;
}

SEC("uprobe/msg_send_udp")
int msg_send_udp(struct pt_regs *ctx)
{
    // int run_onsend(sip_msg_t *orig_msg, dest_info_t *dst, char *buf, int len)
    //  debug_bpf_printk("kamailio ======================================= d\n");
    //  static inline int msg_send_buffer(struct dest_info *dst, char *buf, int len, int flags)
    // int udp_send(struct dest_info* dst, char *buf, unsigned len);

    u64 timestamp = bpf_ktime_get_ns();
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid)
    {
        return 0;
    }
    if (target_uid != 0 && target_uid != uid)
    {
        return 0;
    }
#endif

    u64 len = (u64)PT_REGS_PARM3(ctx);

    char fmt2[] = "msg_send: %lld\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), timestamp);

    if (len < 0)
    {
        return 0;
    }

    // int udp_send(struct dest_info* dst, char *buf, unsigned len);

    struct data_t data = {};
    data.pid = pid; // only process id
    data.len = len; // origin query sql length
    data.timestamp = timestamp;
    data.retval = -1;

    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    data.buf = buf;

    const void *rcvinfo = (void *)PT_REGS_PARM1(ctx);
    data.rcvinfo = rcvinfo;

    bpf_map_update_elem(&sip_hash_send, &current_pid_tgid, &data, BPF_ANY);

    // struct socket_info send_sock = {};
    // bpf_map_update_elem(&tmp_socket_info, &current_pid_tgid, &send_sock, BPF_ANY);

    return 0;
}

SEC("uretprobe/msg_send_udp")
int msg_ret_send_udp(struct pt_regs *ctx)
{

    u64 timestamp = bpf_ktime_get_ns();
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid)
    {
        return 0;
    }
    if (target_uid != 0 && target_uid != uid)
    {
        return 0;
    }
#endif

    int len = (int)PT_REGS_RC(ctx);
    char fmt2[] = "msg_send return: %d\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), len);

    struct data_t *data = bpf_map_lookup_elem(&sip_hash_send, &current_pid_tgid);
    if (!data)
    {
        return 0; // missed start
    }

    if (data->buf != NULL)
    {
        data->timestamp = timestamp;
        // int len2 = bpf_map_lookup_elem(&active_sip_read_len_map, &current_pid_tgid);
        char fmt5[] = "len ret: %d\n";
        bpf_trace_printk(fmt5, sizeof(fmt5), data->len);
        process_sip_data(ctx, current_pid_tgid, kSIPWrite, data);
    }

    // bpf_map_delete_elem(&tmp_socket_info, &current_pid_tgid);
    bpf_map_delete_elem(&sip_hash_send, &current_pid_tgid);

    return 0;
}

SEC("uprobe/msg_send_tcp")
int msg_send_tcp(struct pt_regs *ctx)
{
    // int run_onsend(sip_msg_t *orig_msg, dest_info_t *dst, char *buf, int len)
    //  debug_bpf_printk("kamailio ======================================= d\n");
    //  static inline int msg_send_buffer(struct dest_info *dst, char *buf, int len, int flags)
    // int tcp_send(struct dest_info *dst, union sockaddr_union *from, const char *buf, unsigned len)

    u64 timestamp = bpf_ktime_get_ns();
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid)
    {
        return 0;
    }
    if (target_uid != 0 && target_uid != uid)
    {
        return 0;
    }
#endif

    u64 len = (u64)PT_REGS_PARM4(ctx);

    char fmt2[] = "msg_tcp_send: %lld\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), timestamp);

    if (len < 0)
    {
        return 0;
    }

    struct data_t data = {};
    data.pid = pid; // only process id
    data.len = len; // origin query sql length
    data.timestamp = timestamp;
    data.retval = -1;

    const char *buf = (const char *)PT_REGS_PARM3(ctx);
    data.buf = buf;

    const void *rcvinfo = (void *)PT_REGS_PARM1(ctx);
    data.rcvinfo = rcvinfo;

    bpf_map_update_elem(&sip_hash_send, &current_pid_tgid, &data, BPF_ANY);

    // struct socket_info send_sock = {};
    // bpf_map_update_elem(&tmp_socket_info, &current_pid_tgid, &send_sock, BPF_ANY);

    return 0;
}

SEC("uretprobe/msg_send_tcp")
int msg_ret_send_tcp(struct pt_regs *ctx)
{

    u64 timestamp = bpf_ktime_get_ns();

    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

    int len = (int)PT_REGS_RC(ctx);
    char fmt2[] = "msg_tcp_send return: %d\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), len);

    struct data_t *data = bpf_map_lookup_elem(&sip_hash_send, &current_pid_tgid);
    if (!data)
    {
        return 0; // missed start
    }

    if (data->buf != NULL)
    {
        data->timestamp = timestamp;
        // int len2 = bpf_map_lookup_elem(&active_sip_read_len_map, &current_pid_tgid);
        char fmt5[] = "len ret: %d\n";
        bpf_trace_printk(fmt5, sizeof(fmt5), data->len);
        process_sip_data(ctx, current_pid_tgid, kSIPWrite, data);
    }

    // bpf_map_delete_elem(&tmp_socket_info, &current_pid_tgid);
    bpf_map_delete_elem(&sip_hash_send, &current_pid_tgid);

    return 0;
}
