package collection

import (
    "fmt"
    "unsafe"
    "bytes"
    "syscall"
    "encoding/binary"
    "github.com/iovisor/gobpf/bcc"
    "github.com/guardicode/ipcdump/internal/bpf"
    "github.com/guardicode/ipcdump/internal/events"
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
struct loopback_sock_ipc_metadata_t {
    u64 src_pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    char src_comm[16];
    u64 dst_pid;
    char dst_comm[16];
    u64 count;
    u64 dst_inode;
    u64 timestamp;
    u16 src_port;
    u16 dst_port;
    u8 proto;
    u8 pad0;
    u16 pad1;
    // this is offset 80
};

struct loopback_sock_ipc_t {
    struct loopback_sock_ipc_metadata_t d;
    REMAINING_BYTES_BUFFER(struct loopback_sock_ipc_metadata_t);
};

BPF_PERF_OUTPUT(loopback_events);

BPF_PERCPU_ARRAY(working_loopback_event_arr, struct loopback_sock_ipc_t, 1);

// TODO: refactor tcp+udp
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

    int ekey = 0;
    struct loopback_sock_ipc_t *e = working_loopback_event_arr.lookup(&ekey);
    if (!e) {
        return 0;
    }

    // TODO: tcp6
    e->d.proto = IPPROTO_TCP;
    e->d.src_port = src_port;
    e->d.dst_port = dst_port;
    e->d.src_pid = src_pid;
    e->d.count = count;
    e->d.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(e->d.src_comm, sizeof(e->d.src_comm));

    // stack alignment :(
    u64 dst_pid = 0;
    get_pid_for_sock(&dst_pid, sk);
    e->d.dst_pid = dst_pid;
    get_comm_for_pid(e->d.dst_pid, e->d.dst_comm, sizeof(e->d.dst_comm));
    e->d.dst_inode = sk->sk_socket->file->f_inode->i_ino;

    #ifdef COLLECT_IPC_BYTES
    e->bytes_len = BYTES_BUF_LEN(e, e->d.count);
    bpf_probe_read(e->bytes, e->bytes_len, head_ptr + transport_header + tcp_copy.doff * 4);
    #endif

    loopback_events.perf_submit(ctx, e, EVENT_SIZE(e));

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

    int ekey = 0;
    struct loopback_sock_ipc_t *e = working_loopback_event_arr.lookup(&ekey);
    if (!e) {
        return 0;
    }

    // TODO: udp6
    e->d.proto = IPPROTO_UDP;
    e->d.src_port = src_port;
    e->d.dst_port = dst_port;
    e->d.src_pid = src_pid;
    e->d.count = count;
    e->d.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(e->d.src_comm, sizeof(e->d.src_comm));

    // stack alignment :(
    u64 dst_pid = 0;
    get_pid_for_sock(&dst_pid, sk);
    e->d.dst_pid = dst_pid;
    get_comm_for_pid(e->d.dst_pid, e->d.dst_comm, sizeof(e->d.dst_comm));
    e->d.dst_inode = sk->sk_socket->file->f_inode->i_ino;

    #ifdef COLLECT_IPC_BYTES
    e->bytes_len = BYTES_BUF_LEN(e, e->d.count);
    bpf_probe_read(e->bytes, e->bytes_len, head_ptr + transport_header + sizeof(udp_copy));
    #endif

    loopback_events.perf_submit(ctx, e, EVENT_SIZE(e));

    return 0;
}

`

type loopbackSockIpcEvent struct {
    SrcPid uint64
    SrcComm [16]byte
    DstPid uint64
    DstComm [16]byte
    Count uint64
    DstInode uint64
    Timestamp uint64
    SrcPort uint16
    DstPort uint16
    Proto uint8
    _ uint8
    _ uint16
    BytesLen uint16
}

var (
    collectLoopbackTcp = false
    collectLoopbackUdp = false
)

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

func handleLoopbackSockIpcEvent(event *loopbackSockIpcEvent, eventBytes []byte, commId *CommIdentifier,
    sockId *SocketIdentifier) error {

    dstPid := (int64)(event.DstPid)
    if dstPid <= 0 {
        dstPidU, ok := sockId.GuessMissingSockPidFromUsermode(event.DstInode)
        if !ok {
            dstPid = -1
        } else {
            dstPid = (int64)(dstPidU)
        }
    }

    var eventType events.EmittedEventType
    switch event.Proto {
    case syscall.IPPROTO_TCP:
        eventType = events.IPC_EVENT_LOOPBACK_SOCK_TCP
    case syscall.IPPROTO_UDP:
        eventType = events.IPC_EVENT_LOOPBACK_SOCK_UDP
    default:
        return fmt.Errorf("unix ipc event had unexpected proto %d", event.Proto)
    }
    e := events.IpcEvent{
        Src: makeIpcEndpoint(commId, event.SrcPid, event.SrcComm),
        Dst: makeIpcEndpointI(commId, dstPid, event.DstComm),
        Type: eventType,
        Timestamp: TsFromKtime(event.Timestamp),
        Metadata: events.IpcMetadata{
            events.IpcMetadataPair{Name: "src_port", Value: event.SrcPort},
            events.IpcMetadataPair{Name: "dst_port", Value: event.DstPort},
            events.IpcMetadataPair{Name: "dst_inode", Value: event.DstInode},
            events.IpcMetadataPair{Name: "count", Value: event.Count},
        },
        Bytes: eventBytes,
    }
    return events.EmitIpcEvent(e)
}

func CollectLoopbackIpc(module *bcc.Module, exit <-chan struct{}, commId *CommIdentifier,
    sockId *SocketIdentifier) error {

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
            eventMetadata := perfData[:unsafe.Sizeof(event)]
            if err := binary.Read(bytes.NewBuffer(eventMetadata), bcc.GetHostByteOrder(), &event); err != nil {
                return fmt.Errorf("failed to parse signal event: %w", err)
            }
            eventBytes := perfData[len(eventMetadata):][:event.BytesLen]
            if err := handleLoopbackSockIpcEvent(&event, eventBytes, commId, sockId); err != nil {
                return fmt.Errorf("failed to handle loopback sock event: %w", err)
            }

        case <- exit:
            return nil
        }
    }
}

