package collection

import (
    "fmt"
    "bytes"
    "syscall"
    "encoding/binary"
    "strconv"
    "github.com/iovisor/gobpf/bcc"
    "github.com/guardicode/ipcdump/internal/bpf"
)

const loopbackIncludes = `
#include <net/sock.h>
#include <linux/skbuff.h>
#include <uapi/linux/ptrace.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
`

const loopbackSource = `
struct __attribute__((packed)) loopback_sock_ipc_t {
    u8 proto;
    u64 src_pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u64 dst_pid;
    u64 count;
    u16 src_port;
    u16 dst_port;
    u64 dst_inode;
};

BPF_PERF_OUTPUT(loopback_events);

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

    struct loopback_sock_ipc_t e = {
        // TODO: tcp6
        .proto = IPPROTO_TCP,
        .src_port = src_port,
        .dst_port = dst_port,
        .src_pid = src_pid,
        .count = count,
    };

    // stack alignment :(
    u64 dst_pid = 0;
    get_pid_for_sock(&dst_pid, sk);
    e.dst_pid = dst_pid;

    e.dst_inode = sk->sk_socket->file->f_inode->i_ino;

    loopback_events.perf_submit(ctx, &e, sizeof(e));

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

    int64_t count = ntohs(udp_copy.len);
    if (count <= 0) {
        return 0;
    }

    struct loopback_sock_ipc_t e = {
        // TODO: udp6
        .proto = IPPROTO_UDP,
        .src_port = src_port,
        .dst_port = dst_port,
        .src_pid = src_pid,
        .count = count,
    };

    // stack alignment :(
    u64 dst_pid = 0;
    get_pid_for_sock(&dst_pid, sk);
    e.dst_pid = dst_pid;
    e.dst_inode = sk->sk_socket->file->f_inode->i_ino;

    loopback_events.perf_submit(ctx, &e, sizeof(e));

    return 0;
}

`

type loopbackSockIpcEvent struct {
    Proto uint8
	SrcPid uint64
	DstPid uint64
    Count uint64
    SrcPort uint16
    DstPort uint16
    DstInode uint64
}

var (
    collectLoopbackTcp = false
    collectLoopbackUdp = false
)

// TODO: tcp/udp!
func InitLoopbackIpcCollection(bpfBuilder *bpf.BpfBuilder, tcp bool, udp bool) error {
    if (tcp || udp) == false {
        return nil
    }
    if err := bpfBuilder.AddIncludes(loopbackIncludes); err != nil {
        return err
    }
    bpfBuilder.AddSources(loopbackSource)
    // TODO: fix these semantics!
    collectLoopbackTcp = tcp
    collectLoopbackUdp = udp
    return nil
}

type inodeProcessInfo struct {
    Fd uint64
    Pid uint64
    ProcessStartTime uint64
}

func handleLoopbackSockIpcEvent(event *loopbackSockIpcEvent, sockId *SocketIdentifier) error {
    dstPidStr := "<unknown>"
    if event.DstPid != 0 {
        dstPidStr = strconv.FormatUint(event.DstPid, 10)
    } else {
        pid, ok := sockId.GuessMissingSockPidFromUsermode(event.DstInode)
        if ok {
            dstPidStr = strconv.FormatUint(pid, 10)
        }
    }
    var typeStr string
    switch event.Proto {
    case syscall.IPPROTO_TCP:
        typeStr = "TCP"
    case syscall.IPPROTO_UDP:
        typeStr = "DGRAM"
    default:
        // TODO: handle error
        return fmt.Errorf("unix ipc event had unexpected proto %d", event.Proto)
    }
    // TODO: map dst inode to dst pid
    fmt.Printf("LOOPBACK SOCK %v: %v --> %s (inode %v) from port %v to port %v (%d bytes)\n",
        typeStr,
        event.SrcPid,
        dstPidStr,
        event.DstInode,
        event.SrcPort,
        event.DstPort,
        event.Count)

    return nil
}

func CollectLoopbackIpc(module *bcc.Module, exit <-chan struct{}, sockId *SocketIdentifier) error {
    if (collectLoopbackTcp || collectLoopbackUdp) == false {
        return nil
    }

    perfChannel := make(chan []byte, 4096)
    table := bcc.NewTable(module.TableId("loopback_events"), module)
    perfMap, err := bcc.InitPerfMap(table, perfChannel, nil)
    if err != nil {
        return err
    }

    perfMap.Start()
    defer perfMap.Stop()

    if collectLoopbackTcp {
        kprobe, err := module.LoadKprobe("probe_tcp_rcv_established")
        if err != nil {
            return err
        }
        if err := module.AttachKprobe("tcp_rcv_established", kprobe, -1); err != nil {
            return err
        }
    }

    if collectLoopbackUdp {
        kprobe, err := module.LoadKprobe("probe_udp_queue_rcv_skb")
        if err != nil {
            return err
        }
        if err := module.AttachKprobe("udp_queue_rcv_skb", kprobe, -1); err != nil {
            return err
        }
    }

    for {
        select {
        case perfData := <-perfChannel:
            var event loopbackSockIpcEvent
            if err := binary.Read(bytes.NewBuffer(perfData), bcc.GetHostByteOrder(), &event); err != nil {
                return fmt.Errorf("failed to parse signal event: %w", err)
            }
            // TODO: udp!
            handleLoopbackSockIpcEvent(&event, sockId)

        case <- exit:
            return nil
        }
    }
}

