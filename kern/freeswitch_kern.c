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

#include "freeswitch.h"
// sudo cat  /sys/kernel/debug/tracing/trace_pipe

typedef struct receive_info
{
    struct ip_addr src_ip;
    struct ip_addr dst_ip;
    unsigned short src_port; /* host byte order */
    unsigned short dst_port; /* host byte order */
} receive_info_t;

typedef struct dstinfo
{
    unsigned short port;
    unsigned char addr[16];
} dst_info_t;

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
    const void *tp;
    char comm[TASK_COMM_LEN];
    s8 retval; // dispatch_command return value
};

struct sip_data_event_t
{
    enum sip_data_event_type type;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    // receive_info_t rcinfo;
    char dstInfo[20];
    char srcInfo[20];
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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, msg_t);
    __uint(max_entries, 1);
} msg_freeswitch_heap SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, dst_info_t);
    __uint(max_entries, 1);
} buf_freeswitch_heap SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, msg_iovec_t);
    __uint(max_entries, 1);
} msg_iovect_heap SEC(".maps");

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

    ////int tport_send_msg(tport_t *self, msg_t *msg, tp_name_t const *tpn, struct sigcomp_compartment *cc)
    /// static ssize_t tport_vsend(tport_t * self,  msg_t * msg, tp_name_t const *tpn,  msg_iovec_t iov[], size_t iovused,struct sigcomp_compartment *cc)
    event->type = type;
    // event->data_len = (data->len < MAX_DATA_SIZE_SIP ? (data->len & (MAX_DATA_SIZE_SIP - 1)): MAX_DATA_SIZE_SIP);
    // bpf_probe_read_user(event->data, event->data_len, data->buf);

    u32 kZero = 0;

    if (type == kSIPRead)
    {

        dst_info_t *buf = bpf_map_lookup_elem(&buf_freeswitch_heap, &kZero);
        if (!buf)
            return 0;

        bpf_probe_read(&event->dstInfo, sizeof(&event->dstInfo), data->rcvinfo + 210);

        msg_iovec_t *iovec = bpf_map_lookup_elem(&msg_iovect_heap, &kZero);
        if (!iovec)
            return 0;
        int i = 0, payload_len = 0;

        bpf_probe_read(iovec, sizeof(msg_iovec_t), data->buf);
        event->data_len = (iovec->siv_len < MAX_DATA_SIZE_SIP ? (iovec->siv_len & (MAX_DATA_SIZE_SIP - 1)) : MAX_DATA_SIZE_SIP);
        bpf_probe_read_user(event->data, event->data_len, iovec->siv_base);
    }
    else
    {

        // bpf_probe_read_user(&event->data, event->data_len, data->rcvinfo+210);
        dst_info_t *buf = bpf_map_lookup_elem(&buf_freeswitch_heap, &kZero);
        if (!buf)
            return 0;

        bpf_probe_read(&event->dstInfo, sizeof(&event->dstInfo), data->rcvinfo + 210);


        msg_iovec_t *iovec = bpf_map_lookup_elem(&msg_iovect_heap, &kZero);
        if (!iovec)
            return 0;
        int i = 0, payload_len = 0;

        /*for (i = 0; i < 1; i++)
        {
        */

        bpf_probe_read(iovec, sizeof(msg_iovec_t), data->buf);
        event->data_len = (iovec->siv_len < MAX_DATA_SIZE_SIP ? (iovec->siv_len & (MAX_DATA_SIZE_SIP - 1)) : MAX_DATA_SIZE_SIP);
        bpf_probe_read_user(event->data, event->data_len, iovec->siv_base);

  
        // event->data_len = message->
        //char fmt2[] = "DATA MSG LEN: %d\n";
        //bpf_trace_printk(fmt2, sizeof(fmt2), sizeof(msg_t));

        // event->rcinfo.src_port = send_sock->port_no;
        event->type = type;
        // Socket INFO

        char fmt8[] = "PORT SRC: %d\n";
        bpf_trace_printk(fmt8, sizeof(fmt8), 1);
    }

    char fmt8[] = "len10 %s\n";
    bpf_trace_printk(fmt8, sizeof(fmt8), event->data);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct sip_data_event_t));
    return 0;
}

SEC("uprobe/receive_msg")
int freeswitch_receive_msg(struct pt_regs *ctx)
{

    // su_vrecv
    //  debug_bpf_printk("freeswitch ======================================= d\n");
    //   n = su_vrecv(self->tp_socket, iovec, veclen, 0, from, &fromlen);

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
    if (len < 0)
    {
        return 0;
    }

    char fmt2[] = "freeswitch_query: %d\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), pid);

    struct data_t data = {};
    data.pid = pid; // only process id
    data.len = len; // origin query sql length
    data.timestamp = timestamp;
    data.retval = -1;

    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    data.buf = buf;

    const void *rcvinfo = (void *)PT_REGS_PARM5(ctx);
    data.rcvinfo = rcvinfo;

    bpf_map_update_elem(&sip_hash_recv, &current_pid_tgid, &data, BPF_ANY);

    return 0;
}

SEC("uretprobe/receive_msg")
int freeswitch_ret_receive_msg(struct pt_regs *ctx)
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

    debug_bpf_printk("uretprobe/receive_msg pid :%d\n", pid);
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

SEC("uprobe/msg_send")
int msg_send(struct pt_regs *ctx)
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

    u64 len = (u64)PT_REGS_PARM5(ctx);

    char fmt2[] = "msg_send: %d\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), len);

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

    // int tport_send_msg(tport_t *self, msg_t *msg, tp_name_t const *tpn, struct sigcomp_compartment *cc)

    const char *buf = (const char *)PT_REGS_PARM4(ctx);
    data.buf = buf;

    const void *rcvinfo = (void *)PT_REGS_PARM2(ctx);
    data.rcvinfo = rcvinfo;

    bpf_map_update_elem(&sip_hash_send, &current_pid_tgid, &data, BPF_ANY);

    return 0;
}

// int tport_send_msg(tport_t *self, msg_t *msg, tp_name_t const *tpn, struct sigcomp_compartment *cc)

SEC("uretprobe/msg_send")
int msg_ret_send(struct pt_regs *ctx)
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
