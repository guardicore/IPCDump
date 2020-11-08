package main

import (
    "fmt"
    "os"
    "os/signal"
    "flag"
    "bytes"
    "io/ioutil"
    "path"
    "path/filepath"
    "syscall"
    "strings"
    "strconv"
    "time"
    "golang.org/x/sys/unix"
    "encoding/binary"

    bpf "github.com/iovisor/gobpf/bcc"
    "github.com/mitchellh/go-ps"
)

// TODO: refactor out
type uintArrayFlags []uint64

func (i *uintArrayFlags) String() string {
	return ""
}

func (i *uintArrayFlags) Set(value string) error {
    u, err := strconv.ParseUint(value, 0, 32)
    if err != nil {
        return err
    }
	*i = append(*i, u)
	return nil
}

type stringArrayFlags []string

func (i *stringArrayFlags) String() string {
	return ""
}

func (i *stringArrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}
// till here



const ipcSource = `
#define KBUILD_MODNAME "IPCDUMP"

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/tty.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/af_unix.h>
#include <net/sock.h>
#include <linux/un.h>

__DEFINES__

// TODO: this from outside!
#ifdef BPF_DEBUG
#define TRACE(fmt, ...) do { bpf_trace_printk(fmt, __VA_ARGS__); } while (0)
#else
#define TRACE(fmt, ...)
#endif

struct __attribute__((packed)) signal_data_t {
    u64 sig;
    // this is too big
    u64 src_pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u64 dst_pid;
};

struct __attribute__((packed)) unix_sock_stream_data_t {
    u64 src_pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u64 dst_pid;
    u64 count;
    char path[108];
};

struct __attribute__((packed)) unix_sock_dgram_data_t {
    u64 src_pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u64 dst_pid;
    u64 count;
    char path[108];
};

struct __attribute__((packed)) pty_write_data_t {
    u64 src_pid;
    u64 dst_pid;
    u64 dst_sid;
    u64 count;
    char tty_name[64];
};

struct __attribute__((packed)) loopback_sock_tcp_t {
    u64 src_pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u64 dst_pid;
    u64 count;
    u16 src_port;
    u16 dst_port;
    u64 dst_inode;
};

struct __attribute__((packed)) loopback_sock_udp_t {
    u64 src_pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u64 dst_pid;
    u16 count;
    u16 src_port;
    u16 dst_port;
    u64 dst_inode;
};

BPF_PERF_OUTPUT(events);

enum ipc_event_type {
    IPC_EVENT_NONE = 0,
    IPC_EVENT_SIGNAL,
    IPC_EVENT_UNIX_SOCK_STREAM,
    IPC_EVENT_UNIX_SOCK_DGRAM,
    IPC_EVENT_PTY_WRITE,
    IPC_EVENT_LOOPBACK_SOCK_TCP,
    IPC_EVENT_LOOPBACK_SOCK_UDP,
};

struct ipc_event_t {
    u8 type;
    union {
        struct signal_data_t signal;
        struct unix_sock_stream_data_t unix_sock_stream;
        struct unix_sock_dgram_data_t unix_sock_dgram;
        struct pty_write_data_t pty_write;
        struct loopback_sock_tcp_t loopback_sock_tcp;
        struct loopback_sock_udp_t loopback_sock_udp;
    };
};

struct __attribute__((packed)) signal_generate_args_t {
    u16 common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    u32 common_pid;

    u32 sig;
    u32 errno;
    u32 code;
    char comm[16];
    u32 pid;
    u32 group;
    u32 result;
};

BPF_PERCPU_ARRAY(new_event, struct ipc_event_t, 1);
// TODO: add TYPE to get_new_event()/get_current_event()
// TODO: add save_incomplete_current_event() to explicitly chain probes
static inline struct ipc_event_t *get_new_event(void) __attribute__((always_inline));
static inline struct ipc_event_t *get_current_event(void) __attribute__((always_inline));
static inline void submit_current_event(void *ctx, size_t size) __attribute__((always_inline));
static inline struct ipc_event_t *get_current_event(void) {
    u32 key = 0;
    struct ipc_event_t *e = new_event.lookup(&key);
    if (!e) {
        return NULL;
    }
    return e;
}
// TODO: check that last event was submitted (type == 0)
static inline struct ipc_event_t *get_new_event(void) {
    struct ipc_event_t *e = get_current_event();
    if (!e) {
        return NULL;
    }
    memset(e, 0, sizeof(*e));
    return e;
}
static inline void submit_current_event(void *ctx, size_t size) {
    struct ipc_event_t *e = get_current_event();
    if (!e) {
        bpf_trace_printk("error: current event lookup failed\n");
        return;
    }
    if (e->type == IPC_EVENT_NONE) {
        bpf_trace_printk("error: no event is in progress\n");
        return;
    }
    // TODO: would be nice if we could automatically pull size based on e->type...
    events.perf_submit(ctx, e, sizeof(e->type) + size);
    memset(e, 0, sizeof(*e));
}

BPF_PERCPU_ARRAY(in_dgram_recvmsg, int, 1);
static inline int *get_in_dgram_recvmsg(void) __attribute__((always_inline));
static inline int *get_in_dgram_recvmsg(void) {
    u32 key = 0;
    int *in_recvmsg = in_dgram_recvmsg.lookup(&key);
    if (!in_recvmsg) {
        return NULL;
    }
    return in_recvmsg;
}


int trace_signal_generate(struct signal_generate_args_t *args) {
    if (args->result == 0 && args->code == 0) {
        struct ipc_event_t *e = get_new_event();
        if (e) {
            e->type = IPC_EVENT_SIGNAL;
            e->signal.sig = args->sig;
            e->signal.dst_pid = args->pid;
            e->signal.src_pid = (bpf_get_current_pid_tgid() >> 32);
            submit_current_event(args, sizeof(e->signal));
        };
    }
    return 0;
}

static inline int try_get_unix_name_path(char *path, u32 path_len, const struct sockaddr_un *name, int name_len) __attribute__((always_inline));

static inline int try_get_unix_name_path(char *path, u32 path_len, const struct sockaddr_un *name, int name_len) {
    if (name_len <= 2 || path_len < 1) {
        return -1;
    }

    if (name->sun_path[0] == '\0') {
        if (name_len <= 3) {
            bpf_trace_printk("warning: name_len %d for unix path was out of bounds\n", name_len);
            return -1;
        }

        path[0] = '@';

        // we use addr->len-3 because 2 bytes are for sun_family and 1 more is the initial null
        // (note that the name may contain more null bytes; we choose to stop at the first)
        int64_t read_len = min((int64_t)path_len - 1, (int64_t)name_len - 3);
        if (read_len < 0 || read_len >= sizeof(name->sun_path) - 1) {
            bpf_trace_printk("warning: read_len %lld for unix path was out of bounds\n", read_len);
            return -1;
        }
        bpf_probe_read_str(path + 1,
                           read_len,
                           name->sun_path + 1);
        bpf_trace_printk("RETURNING @0 for path %s\n", path);
        return 0;
    }
    bpf_probe_read_str(path, min((u32)path_len, (u32)name_len), name->sun_path);
    bpf_trace_printk("RETURNING regular 0 for path %s\n", path);
    return 0;
}

static int try_get_unix_address_path(char *path, u32 path_len, const struct unix_address *addr) {
    struct sockaddr_un name_copy = {0};
    u32 addr_len = (u32)addr->len;

    if (addr_len <= 2) {
        bpf_trace_printk("warning: addr_len %u for unix path was out of bounds\n", addr_len);
        return -1;
    }

    // verifier being ornary about addr_len bounds...
    if (addr_len > sizeof(name_copy)) {
        if (bpf_probe_read(&name_copy, sizeof(name_copy), addr->name)) return -1;
    } else {
        if (bpf_probe_read(&name_copy, addr_len, addr->name)) return -1;
    }

    return try_get_unix_name_path(path, path_len, &name_copy, addr_len);
}

static inline int try_get_unix_msghdr_path(char *path, u32 path_len, const struct msghdr *msg) __attribute__((always_inline));

static int try_get_unix_msghdr_path(char *path, u32 path_len, const struct msghdr *msg) {
    struct sockaddr_un name_copy = {0};
    u32 addr_len = (u32)msg->msg_namelen;

    if (addr_len <= 2) {

        return -1;
    }

    // verifier being ornary about addr_len bounds...
    if (addr_len > sizeof(name_copy)) {
        if (bpf_probe_read(&name_copy, sizeof(name_copy), msg->msg_name)) return -1;
    } else {
        if (bpf_probe_read(&name_copy, addr_len, msg->msg_name)) return -1;
    }

    return try_get_unix_name_path(path, path_len, &name_copy, addr_len);
}

static int try_get_unix_socket_path(char *path, int path_len, const struct socket *sock) {
    const struct unix_address *addr = ((struct unix_sock *)sock->sk)->addr;
    if (try_get_unix_address_path(path, path_len, addr)) {
        const struct unix_address *peer_addr = ((struct unix_sock *)((struct unix_sock *)sock->sk)->peer)->addr;
        if (try_get_unix_address_path(path, path_len, peer_addr)) {
            return -1;
        }
    }
    return 0;
}

// TODO: probe only on sendmsg() success
int probe_unix_stream_sendmsg(struct pt_regs *ctx,
                              struct socket *sock,
                              struct msghdr *msg,
                              size_t len) {
    struct ipc_event_t *e = get_new_event();
    if (e) {
        e->type = IPC_EVENT_UNIX_SOCK_STREAM;
        e->unix_sock_stream.src_pid = bpf_get_current_pid_tgid() >> 32;
        e->unix_sock_stream.dst_pid = sock->sk->sk_peer_pid->numbers[0].nr;
        if (try_get_unix_socket_path(e->unix_sock_stream.path, sizeof(e->unix_sock_stream.path), sock)) {
            char anonymous[] = "<anonymous>";
            bpf_probe_read_str(e->unix_sock_stream.path, sizeof(e->unix_sock_stream.path), anonymous);
        }
    }

    return 0;
}

int retprobe_unix_stream_sendmsg(struct pt_regs *ctx,
                                 struct socket *sock,
                                 struct msghdr *msg,
                                 size_t len) {
    int sent_count = PT_REGS_RC(ctx);
    if (sent_count < 0) {
        return 0;
    }

    struct ipc_event_t *e = get_current_event();
    if (!e || e->type != IPC_EVENT_UNIX_SOCK_STREAM) {
        bpf_trace_printk("warning: no unix_stream_sendmsg() probe was in progress\n");
        return 0;
    }

    e->unix_sock_stream.count = sent_count;
    submit_current_event(ctx, sizeof(e->unix_sock_stream));

    return 0;
}

int probe_unix_dgram_recvmsg(struct pt_regs *ctx,
                             struct socket *sock,
                             struct msghdr *msg,
                             size_t len) {
    int *in_recvmsg = get_in_dgram_recvmsg();
    if (!in_recvmsg || *in_recvmsg) {
        bpf_trace_printk("error: unexpected unix_dgram_recvmsg() context\n");
        return 0;
    }
    *in_recvmsg = 1;

    struct ipc_event_t *e = get_new_event();
    if (e) {
        e->type = IPC_EVENT_UNIX_SOCK_DGRAM;
        e->unix_sock_dgram.dst_pid = bpf_get_current_pid_tgid() >> 32;
        struct msghdr msg_copy = {0};
        // TODO: if
        bpf_probe_read(&msg_copy, sizeof(msg_copy), msg);

        if (!try_get_unix_msghdr_path(e->unix_sock_dgram.path, sizeof(e->unix_sock_dgram.path), &msg_copy)) {
        } else if (try_get_unix_socket_path(e->unix_sock_stream.path, sizeof(e->unix_sock_stream.path), sock)) {
            char anonymous[] = "<anonymous>";
            bpf_probe_read_str(e->unix_sock_dgram.path, sizeof(e->unix_sock_dgram.path), anonymous);
        }
    }

    return 0;

}

int retprobe_unix_dgram_recvmsg(struct pt_regs *ctx,
                                struct socket *sock,
                                struct msghdr *msg,
                                size_t len) {
    int *in_recvmsg = get_in_dgram_recvmsg();
    if (!in_recvmsg || !*in_recvmsg) {
        bpf_trace_printk("error: unexpected unix_dgram_recvmsg() context\n");
        return 0;
    }
    *in_recvmsg = 0;

    int recv_count = PT_REGS_RC(ctx);
    if (recv_count >= 0) {
        struct ipc_event_t *e = get_current_event();
        if (e) {
            e->unix_sock_dgram.count = recv_count;
            submit_current_event(ctx, sizeof(e->unix_sock_dgram));
        }
    }

    return 0;
}

int retprobe__skb_try_recv_datagram(struct pt_regs *ctx, struct sock *sk,
                                    struct sk_buff_head *queue,
                                    unsigned int flags, int *off, int *err,
                                    struct sk_buff **last) {


    if (!PT_REGS_RC(ctx)) {
        return 0;
    }

    int *in_recvmsg = get_in_dgram_recvmsg();
    if (!in_recvmsg) {
        bpf_trace_printk("error: unexpected sk_filter_trim_cap() context\n");
        return 0;
    }

    if (!*in_recvmsg) {
        return 0;
    }

    struct ipc_event_t *e = get_current_event();
    if (e) {
        struct sk_buff *skb = (struct sk_buff*)PT_REGS_RC(ctx);
        struct unix_skb_parms *cb = (struct unix_skb_parms*)(&(skb->cb));
        e->unix_sock_dgram.src_pid = cb->pid->numbers[0].nr;
    }
    return 0;
}



int probe_pty_write(struct pt_regs *ctx, struct tty_struct *tty, const unsigned char *buf, int c) {
    u64 dst_pid = tty->pgrp->numbers[0].nr;
    if (dst_pid == 0) {
        return 0;
    }

    struct ipc_event_t *e = get_new_event();
    if (e) {
        e->type = IPC_EVENT_PTY_WRITE;
        e->pty_write.src_pid = bpf_get_current_pid_tgid() >> 32;
        e->pty_write.dst_pid = tty->pgrp->numbers[0].nr;
        e->pty_write.dst_sid = tty->session->numbers[0].nr;
        bpf_probe_read_str(e->pty_write.tty_name, sizeof(e->pty_write.tty_name), tty->name);
    }
    return 0;
}

int retprobe_pty_write(struct pt_regs *ctx, struct tty_struct *tty, const unsigned char *buf, int c) {
    int written = PT_REGS_RC(ctx);
    if (written >= 0) 
    {
        // TODO: make this not trace "no event is in process"
        struct ipc_event_t *e = get_current_event();
        if (e) {
            e->pty_write.count = written;
            submit_current_event(ctx, sizeof(e->pty_write));
        }
    }
    return 0;
}

BPF_HASH(sock_pid_map, struct socket*, u64);
// TODO: consider using netif_rx tracepoint instead for a more stable api
int probe_tcp_rcv_established(struct pt_regs *ctx,
                              struct sock *sk,
                              struct sk_buff *skb) {

    u64 src_pid = bpf_get_current_pid_tgid() >> 32;
    if (src_pid == 0) {
        return 0;
    }

    if (skb->skb_iif != LOOPBACK_IFINDEX) {
        return 0;
    }

    unsigned char *head_ptr = NULL;
    u16 transport_header = 0;

    // TODO: this mess is because bcc is being ornary. refactor
    bpf_probe_read(&head_ptr, sizeof(head_ptr), &skb->head);
    bpf_probe_read(&transport_header, sizeof(transport_header), &skb->transport_header);

    struct tcphdr tcp_copy = {0};
    bpf_probe_read(&tcp_copy, sizeof(tcp_copy), head_ptr + transport_header);

    u16 src_port = ntohs(tcp_copy.source);
    u16 dst_port = ntohs(tcp_copy.dest);

    int64_t count = skb->len - tcp_copy.doff * 4;
    if (count <= 0) {
        return 0;
    }

    struct ipc_event_t *e = get_new_event();
    if (!e) {
        return 0;
    }

    u64 dst_pid = 0;
    struct socket *sk_socket = NULL;
    if (!bpf_probe_read(&sk_socket, sizeof(sk_socket), &sk->sk_socket)) {
        u64 *dst_pid_ptr = sock_pid_map.lookup(&sk_socket);
        if (dst_pid_ptr) {
            dst_pid = *dst_pid_ptr;
        }
    }

    e->type = IPC_EVENT_LOOPBACK_SOCK_TCP;
    e->loopback_sock_tcp.src_pid = src_pid;
    e->loopback_sock_tcp.dst_pid = dst_pid;
    e->loopback_sock_tcp.src_port = src_port;
    e->loopback_sock_tcp.dst_port = dst_port;
    e->loopback_sock_tcp.count = count;
    e->loopback_sock_tcp.dst_inode = sk->sk_socket->file->f_inode->i_ino;

    submit_current_event(ctx, sizeof(e->loopback_sock_tcp));

    return 0;
}

// TODO: consider using netif_rx tracepoint instead for a more stable api
int probe_udp_queue_rcv_skb(struct pt_regs *ctx,
                            struct sock *sk,
                            struct sk_buff *skb) {

    u64 src_pid = bpf_get_current_pid_tgid() >> 32;
    if (src_pid == 0) {
        return 0;
    }

    if (skb->skb_iif != LOOPBACK_IFINDEX) {
        return 0;
    }

    unsigned char *head_ptr = NULL;
    u16 transport_header = 0;

    // TODO: this mess is because bcc is being ornary. refactor
    bpf_probe_read(&head_ptr, sizeof(head_ptr), &skb->head);
    bpf_probe_read(&transport_header, sizeof(transport_header), &skb->transport_header);

    struct udphdr udp_copy = {0};
    bpf_probe_read(&udp_copy, sizeof(udp_copy), head_ptr + transport_header);

    u16 src_port = ntohs(udp_copy.source);
    u16 dst_port = ntohs(udp_copy.dest);

    u16 count = ntohs(udp_copy.len);
    if (count <= 0) {
        return 0;
    }

    struct ipc_event_t *e = get_new_event();
    if (!e) {
        return 0;
    }

    u64 dst_pid = 0;
    struct socket *sk_socket = NULL;
    if (!bpf_probe_read(&sk_socket, sizeof(sk_socket), &sk->sk_socket)) {
        u64 *dst_pid_ptr = sock_pid_map.lookup(&sk_socket);
        if (dst_pid_ptr) {
            dst_pid = *dst_pid_ptr;
        }
    }

    e->type = IPC_EVENT_LOOPBACK_SOCK_UDP;
    e->loopback_sock_udp.src_pid = src_pid;
    e->loopback_sock_udp.dst_pid = dst_pid;
    e->loopback_sock_udp.src_port = src_port;
    e->loopback_sock_udp.dst_port = dst_port;
    e->loopback_sock_udp.count = count;
    e->loopback_sock_udp.dst_inode = sk->sk_socket->file->f_inode->i_ino;

    submit_current_event(ctx, sizeof(e->loopback_sock_udp));

    return 0;
}

int retprobe_sockfd_lookupX(struct pt_regs *ctx) {

    unsigned long REST = PT_REGS_RC(ctx);
    struct socket *sock = (struct socket*)PT_REGS_RC(ctx);
    if (sock) {
        u64 pid = bpf_get_current_pid_tgid() >> 32;
        sock_pid_map.update(&sock, &pid);
    }
    return 0;
}

int probe___sock_release(struct pt_regs *ctx,
                       struct socket *sk) {
    sock_pid_map.delete(&sk);
    return 0;
}`

const (
    IPC_EVENT_NONE = iota
    IPC_EVENT_SIGNAL = iota
    IPC_EVENT_UNIX_SOCK_STREAM = iota
    IPC_EVENT_UNIX_SOCK_DGRAM = iota
    IPC_EVENT_PTY_WRITE = iota
    IPC_EVENT_LOOPBACK_SOCK_TCP = iota
    IPC_EVENT_LOOPBACK_SOCK_UDP = iota
)

type signalIpcEvent struct {
    Sig uint64
	SrcPid uint64
    DstPid uint64
}

type unixSockStreamEvent struct {
	SrcPid uint64
    DstPid uint64
    Count uint64
    Path [108]byte
}

type unixSockDgramEvent struct {
	SrcPid uint64
    DstPid uint64
    Count uint64
    Path [108]byte
}

type ptyWriteEvent struct {
	SrcPid uint64
    DstPid uint64
    DstSid uint64
    Count uint64
    TtyName [64]byte
}

type loopbackSockTcpEvent struct {
	SrcPid uint64
	DstPid uint64
    Count uint64
    SrcPort uint16
    DstPort uint16
    DstInode uint64
}

type loopbackSockUdpEvent struct {
	SrcPid uint64
	DstPid uint64
    Count uint16
    SrcPort uint16
    DstPort uint16
    DstInode uint64
}


func HandleSignalEvent(event *signalIpcEvent) {
    signalNum := syscall.Signal(event.Sig)
    fmt.Printf("SIGNAL: %v --> %v signal %d (%s)\n",
        event.SrcPid,
        event.DstPid,
        signalNum, unix.SignalName(signalNum))
}

func HandleUnixSockStreamEvent(event *unixSockStreamEvent) {
    fmt.Printf("UNIX SOCK STREAM: %v --> %v over %s (%d bytes)\n",
        event.SrcPid,
        event.DstPid,
        event.Path,
        event.Count)
}

func HandleUnixSockDgramEvent(event *unixSockDgramEvent) {
    fmt.Printf("UNIX SOCK DGRAM: %v --> %v over %s (%d bytes)\n",
        event.SrcPid,
        event.DstPid,
        event.Path,
        event.Count)
}

func HandlePtyWriteEvent(event *ptyWriteEvent) {
    skipEvent := false
    dstProcess, err := ps.FindProcess((int)(event.DstPid))
    if err == nil && dstProcess != nil {
        if dstProcess.Executable() == "tmux: client" {
            skipEvent = true
        }
    }
    if (event.SrcPid == event.DstPid) {
        skipEvent = true
    }
    if !skipEvent {
        fmt.Printf("PTY WRITE: %v --> %v over %s with sid %d (%d bytes)\n",
        event.SrcPid,
        event.DstPid,
        event.TtyName,
        event.DstSid,
        event.Count)
    }
}

func HandleLoopbackSockTcpEvent(event *loopbackSockTcpEvent, inodeInfoMap map[uint64]inodeProcessInfo) {
    dstPidStr := "<unknown>"
    if event.DstPid != 0 {
        dstPidStr = strconv.FormatUint(event.DstPid, 10)
    } else {
        info, ok := inodeInfoMap[event.DstInode]
        if ok {
            dstPidStr = strconv.FormatUint(info.Pid, 10)
        }
    }
    // TODO: map dst inode to dst pid
    fmt.Printf("LOOPBACK SOCK TCP: %v --> %s (inode %v) from port %v to port %v (%d bytes)\n",
        event.SrcPid,
        dstPidStr,
        event.DstInode,
        event.SrcPort,
        event.DstPort,
        event.Count)
}

func HandleLoopbackSockUdpEvent(event *loopbackSockUdpEvent, inodeInfoMap map[uint64]inodeProcessInfo) {
    // TODO: map dst inode to dst pid
    dstPidStr := "<unknown>"
    if event.DstPid != 0 {
        dstPidStr = strconv.FormatUint(event.DstPid, 10)
    } else {
        info, ok := inodeInfoMap[event.DstInode]
        if ok {
            dstPidStr = strconv.FormatUint(info.Pid, 10)
        }
    }
    fmt.Printf("LOOPBACK SOCK UDP: %v --> %s (inode %v) from port %v to %v (%d bytes)\n",
        event.SrcPid,
        dstPidStr,
        event.DstInode,
        event.SrcPort,
        event.DstPort,
        event.Count)
}

func HandlePerfEvent(data []byte, inodeInfoMap map[uint64]inodeProcessInfo) {
    ipcType := data[0]
    var err error

    ipcEvent := data[1:]

    switch ipcType {
        // TODO: refactor
    case IPC_EVENT_SIGNAL:
        var event signalIpcEvent
        if err = binary.Read(bytes.NewBuffer(ipcEvent), bpf.GetHostByteOrder(), &event); err != nil {
            fmt.Printf("failed to parse signal event: %s\n", err)
            return
        }
        HandleSignalEvent(&event)
    case IPC_EVENT_UNIX_SOCK_STREAM:
        var event unixSockStreamEvent
        if err = binary.Read(bytes.NewBuffer(ipcEvent), bpf.GetHostByteOrder(), &event); err != nil {
            fmt.Printf("failed to parse unix sock stream event: %s\n", err)
            return
        }
        HandleUnixSockStreamEvent(&event)
    case IPC_EVENT_UNIX_SOCK_DGRAM:
        var event unixSockDgramEvent
        if err = binary.Read(bytes.NewBuffer(ipcEvent), bpf.GetHostByteOrder(), &event); err != nil {
            fmt.Printf("failed to parse unix sock dgram event: %s\n", err)
            return
        }
        HandleUnixSockDgramEvent(&event)
    case IPC_EVENT_PTY_WRITE:
        var event ptyWriteEvent
        if err = binary.Read(bytes.NewBuffer(ipcEvent), bpf.GetHostByteOrder(), &event); err != nil {
            fmt.Printf("failed to parse pty write event: %s\n", err)
            return
        }
        HandlePtyWriteEvent(&event)
    case IPC_EVENT_LOOPBACK_SOCK_TCP:
        var event loopbackSockTcpEvent
        if err = binary.Read(bytes.NewBuffer(ipcEvent), bpf.GetHostByteOrder(), &event); err != nil {
            fmt.Printf("failed to parse loopback sock tcp event: %s\n", err)
            return
        }
        HandleLoopbackSockTcpEvent(&event, inodeInfoMap)
    case IPC_EVENT_LOOPBACK_SOCK_UDP:
        var event loopbackSockUdpEvent
        if err = binary.Read(bytes.NewBuffer(ipcEvent), bpf.GetHostByteOrder(), &event); err != nil {
            fmt.Printf("failed to parse loopback sock udp event: %s\n", err)
            return
        }
        HandleLoopbackSockUdpEvent(&event, inodeInfoMap)
    default:
        fmt.Printf("unknown ipc event type %v\n", ipcType)
    }

}

type inodeProcessInfo struct {
    Fd uint64
    Pid uint64
    ProcessStartTime uint64
}

func GetStartTimeFromPidStateFile(pidStatPath string) (uint64, error) {
    procStat, err := ioutil.ReadFile(pidStatPath)
    procStatStr := string(procStat)
    // avoid all sorts of ugly stuff that can happen when comm has unusual characters/spaces
    i := strings.LastIndex(procStatStr, ")")
    if i <= 0 {
        fmt.Printf("warning: no comm found in %s: %s\n", pidStatPath, procStatStr)
        return 0, err
    }

    splitStat := strings.SplitN(procStatStr[i+1:], " ", 22)
    if len(splitStat) != 22 {
        fmt.Printf("warning: strange result parsing %s: %s\n", pidStatPath, procStatStr)
        return 0, err
    }
    startTimeStr := splitStat[20]
    startTime, err := strconv.ParseUint(startTimeStr, 10, 0)
    if err != nil {
        fmt.Printf("warning: failed to parse process start time %s: %s\n", startTimeStr, err)
        return 0, err
    }

    return startTime, nil
}

func ScanProcessSocketInodes() (map[uint64]inodeProcessInfo, error) {
    matches, err := filepath.Glob("/proc/*/fd/*")
    if err != nil {
        fmt.Printf("warning: failed to scan process fd inodes: %s\n", err)
        return nil, err
    }

    inodeProcInfoMap := make(map[uint64]inodeProcessInfo)
    for _, fdPath := range matches {
        var stat syscall.Stat_t
        if err := syscall.Stat(fdPath, &stat); err != nil {
            if !os.IsNotExist(err) {
                fmt.Printf("warning: failed to stat file %s: %s\n", fdPath, err)
            }
            continue
        }

        if stat.Mode & syscall.S_IFSOCK != syscall.S_IFSOCK {
            continue
        }

        d, fdStr := path.Split(fdPath)
        procDir := filepath.Dir(filepath.Dir(d))
        _, pidStr := path.Split(procDir)

        if pidStr == "self" || pidStr == "thread-self" {
            continue
        }

        pid, err := strconv.ParseUint(pidStr, 10, 0)
        if err != nil {
            fmt.Printf("warning: failed to parse pid %s: %s\n", pidStr, err)
            continue
        }
        fd, err := strconv.ParseUint(fdStr, 10, 0)
        if err != nil {
            fmt.Printf("warning: failed to parse fd str %s for pid %d: %s\n", fdStr, pid, err)
            continue
        }

        startTime, err := GetStartTimeFromPidStateFile(filepath.Join(procDir, "stat"))
        if err != nil {
            if !os.IsNotExist(err) {
                fmt.Printf("warning: failed to read stat file for pid %d: %s\n", pid, err)
            }
            continue
        }

        existing, ok := inodeProcInfoMap[stat.Ino]
        if !ok || existing.ProcessStartTime > startTime {
            inodeProcInfoMap[stat.Ino] = inodeProcessInfo{Fd: fd, Pid: pid, ProcessStartTime: startTime}
        }
    }
    if len(inodeProcInfoMap) == 0 {
        fmt.Printf("warning: no socket inodes were found in /proc. this is unlikely to be correct.\n")
    }
    return inodeProcInfoMap, nil
}

func IsFilteringBySrcPid() bool {
    return len(filterBySrcPids) > 0
}
func IsFilteringByDstPid() bool {
    return len(filterByDstPids) > 0
}
func IsSrcPidAllowed(pid uint64) bool {
    if IsFilteringBySrcPid() {
        return true
    }
    _, ok = filterBySrcPids[pid]
    return ok
}
func IsDstPidAllowed(pid uint64) bool {
    if IsFilteringByDstPid() {
        return true
    }
    _, ok = filterByDstPids[pid]
    return ok
}

func EmitIpcEvent(type uint16, srcPid uint64, dstPid uint64, metadata map[string]string, contents []byte) bool {
    if !IsSrcPidAllowed(srcPid) || !IsDstPidAllowed(dstPid) {
        return false
    }
    // we rely on the type filtering to hold true at the event-generation level, so we don't check it here
}

func main() {
    var dumpBytes int
    var filterBySrcPids uintArrayFlags
    var filterByDstPids uintArrayFlags
    var filterByPids uintArrayFlags
    var filterByTypes stringArrayFlags
    var outputFormat string

    flag.IntVar(&dumpBytes, "X", 0, "dump IPC bytes where relevant (rather than just event details)")
    flag.Var(&filterBySrcPids, "s", "filter by source pid (can be specified more than once)")
    flag.Var(&filterByDstPids, "d", "filter by dest pid (can be specified more than once)")
    flag.Var(&filterByPids, "p", "filter by pid (either source or dest, can be specified more than once)")
    flag.Var(&filterByTypes, "t", "filter by type (can be specified more than once)")
    flag.StringVar(&outputFormat, "f", "<text|json> output format (default is text)")

    flag.Parse()

    var collectSignals = false
    var collectUnixStreams = false
    var collectUnixDgrams = false
    var collectPtys = false
    var collectLoopbackTcp = false
    var collectLoopbackUdp = false

    var filteredSrcPids = make(map[uint64]struct{})
    var filteredDstPids = make(map[uint64]struct{})
    for _, pid in filterByPids {
        filteredSrcPids[pid] = struct{}
        filteredDstPids[pid] = struct{}
    }
    for _, pid in filterBySrcPids {
        filteredSrcPids[pid] = struct{}
    }
    for _, pid in filterBySrcPids {
        filteredDstPids[pid] = struct{}
    }

    var collectAllTypes = len(filterByTypes) == 0
    if !collectAllTypes {
        if len(filterByTypes) == 1 && (filterByTypes[0] == "a" || filterByTypes[0] == "all") {
            collectAllTypes = true
        }
    }

    if collectAllTypes {
        collectSignals = true
        collectUnixStreams = true
        collectUnixDgrams = true
        collectPtys = true
        collectLoopbackTcp = true
        collectLoopbackUdp = true
    }
    for _, filterType := range filterByTypes {
        switch filterType {
        case "k":
        case "signal":
            collectSignals = true

        case "us":
        case "unix-stream":
            collectUnixStreams = true
        case "ud":
        case "unix-dgram":
            collectUnixDgrams = true
        case "u":
        case "unix":
            collectUnixStreams = true
            collectUnixDgrams = true

        case "p":
        case "pty":
            collectPtys = true

        case "lt":
        case "loopback-tcp":
            collectLoopbackTcp = true
        case "lu":
        case "loopback-udp":
            collectLoopbackUdp = true
        case "lo":
        case "loopback":
            collectLoopbackTcp = true
            collectLoopbackUdp = true
        }
    }


    finalBpfProgram := strings.ReplaceAll(ipcSource, "__DEFINES__", "#define BPF_DEBUG")
    m := bpf.NewModule(finalBpfProgram, []string{})
    defer m.Close()


    if collectUnixStreams {
        kprobe, err := m.LoadKprobe("probe_unix_stream_sendmsg")
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to probe_unix_stream_sendmsg() kprobe: %s\n", err)
            os.Exit(1)
        }
        if err := m.AttachKprobe("unix_stream_sendmsg", kprobe, -1); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to attach unix_stream_sendmsg() kprobe: %s\n", err)
            os.Exit(1)
        }

        if kprobe, err = m.LoadKprobe("retprobe_unix_stream_sendmsg"); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to retprobe_unix_stream_sendmsg() kprobe: %s\n", err)
            os.Exit(1)
        }
        if err = m.AttachKretprobe("unix_stream_sendmsg", kprobe, -1); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to attach unix_stream_sendmsg() kretprobe: %s\n", err)
            os.Exit(1)
        }
    }


    if collectUnixDgrams {
        // TODO: move this
        // TODO: detach on failure
        kprobe, err := m.LoadKprobe("retprobe__skb_try_recv_datagram")
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to load retprobe__skb_try_recv_datagram() kprobe: %s\n", err)
            os.Exit(1)
        }
        if err = m.AttachKretprobe("__skb_try_recv_datagram", kprobe, -1); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to attach __skb_try_recv_datagram() kretprobe: %s\n", err)
            os.Exit(1)
        }

        if kprobe, err = m.LoadKprobe("retprobe_unix_dgram_recvmsg"); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to load retprobe_unix_dgram_recvmsg() kprobe: %s\n", err)
            os.Exit(1)
        }
        if err = m.AttachKretprobe("unix_dgram_recvmsg", kprobe, -1); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to attach unix_dgram_recvmsg kretprobe: %s\n", err)
            os.Exit(1)
        }

        if kprobe, err = m.LoadKprobe("probe_unix_dgram_recvmsg"); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to load probe_unix_dgram_recvmsg() kprobe: %s\n", err)
            os.Exit(1)
        }
        if err = m.AttachKprobe("unix_dgram_recvmsg", kprobe, -1); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to attach unix_dgram_recvmsg() kprobe: %s\n", err)
            os.Exit(1)
        }

    }

    if collectPtys {
        kprobe, err := m.LoadKprobe("probe_pty_write")
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to probe_pty_write() kprobe: %s\n", err)
            os.Exit(1)
        }
        if err := m.AttachKprobe("pty_write", kprobe, -1); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to attach pty_write() kprobe: %s\n", err)
            os.Exit(1)
        }

        if kprobe, err = m.LoadKprobe("retprobe_pty_write"); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to retprobe_pty_write() kprobe: %s\n", err)
            os.Exit(1)
        }
        if err = m.AttachKretprobe("pty_write", kprobe, -1); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to attach pty_write() kretprobe: %s\n", err)
            os.Exit(1)
        }
    }

    if collectSignals {
        tracepoint, err := m.LoadTracepoint("trace_signal_generate")
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to load signal:signal_generate tracepoint: %s\n", err)
            os.Exit(1)
        }

        if err = m.AttachTracepoint("signal:signal_generate", tracepoint); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to attach syscall__execve: %s\n", err)
            os.Exit(1)
        }
    }

    needSocketInodes := collectLoopbackTcp || collectLoopbackUdp

    var inodeInfoMap map[uint64]inodeProcessInfo
    if needSocketInodes {
        var err error
        inodeInfoMap, err = ScanProcessSocketInodes()
        if err != nil {
            fmt.Printf("warning: failed initial scan for process socket inodes\n")
        }

        kprobe, err := m.LoadKprobe("probe___sock_release")
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to probe___sock_release() kprobe: %s\n", err)
            os.Exit(1)
        }
        if err := m.AttachKprobe("__sock_release", kprobe, -1); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to attach __sock_release() kprobe: %s\n", err)
            os.Exit(1)
        }

        kprobe, err = m.LoadKprobe("retprobe_sockfd_lookupX")
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to retprobe_sockfd_lookupX() kprobe: %s\n", err)
            os.Exit(1)
        }
        if err := m.AttachKretprobe("sockfd_lookup", kprobe, -1); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to attach sockfd_lookup() kprobe: %s\n", err)
            os.Exit(1)
        }
        if err := m.AttachKretprobe("sockfd_lookup_light", kprobe, -1); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to attach sockfd_lookup_light() kprobe: %s\n", err)
            os.Exit(1)
        }
    }

    if collectLoopbackTcp {
        kprobe, err := m.LoadKprobe("probe_tcp_rcv_established")
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to probe_tcp_rcv_established() kprobe: %s\n", err)
            os.Exit(1)
        }
        if err := m.AttachKprobe("tcp_rcv_established", kprobe, -1); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to attach tcp_rcv_established() kprobe: %s\n", err)
            os.Exit(1)
        }
    }

    if collectLoopbackUdp {
        kprobe, err := m.LoadKprobe("probe_udp_queue_rcv_skb")
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to probe_udp_queue_rcv_skb() kprobe: %s\n", err)
            os.Exit(1)
        }
        if err := m.AttachKprobe("udp_queue_rcv_skb", kprobe, -1); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to attach udp_queue_rcv_skb() kprobe: %s\n", err)
            os.Exit(1)
        }
    }

    table := bpf.NewTable(m.TableId("events"), m)

    perfChannel := make(chan []byte, 4096)

    perfMap, err := bpf.InitPerfMap(table, perfChannel, nil)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
        os.Exit(1)
    }

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, os.Kill)

    inodeScanTicker := time.NewTicker(1 * time.Second)
    if !needSocketInodes {
        inodeScanTicker.Stop()
    }

    go func() {
        for {
            select {
            case perfData := <-perfChannel:
                HandlePerfEvent(perfData, inodeInfoMap)
            case <- inodeScanTicker.C:
                inodeInfoMap, err = ScanProcessSocketInodes()
                if err != nil {
                    fmt.Printf("warning: failed to scan for process socket inodes\n")
                }
            }
        }
    }()

    perfMap.Start()
    <-sig
    perfMap.Stop()
}


