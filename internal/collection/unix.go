package collection

import (
    "fmt"
    "bytes"
    "encoding/binary"
    "github.com/iovisor/gobpf/bcc"
    "github.com/guardicode/ipcdump/internal/bpf"
)

const unixIncludes = `
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/af_unix.h>
#include <linux/un.h>
`

const unixSource = `
enum unix_ipc_type_t {
    UNIX_IPC_TYPE_NONE = 0,
    UNIX_IPC_TYPE_STREAM,
    UNIX_IPC_TYPE_DGRAM,
};

struct __attribute__((packed)) unix_sock_ipc_data_t {
    u8 type;
    u64 src_pid;
    u64 dst_pid;
    u64 count;
    char path[108];
};

BPF_PERF_OUTPUT(unix_events);

BPF_HASH(unix_event_arr, u64, struct unix_sock_ipc_data_t);


static inline struct unix_sock_ipc_data_t *current_unix_event(void) __attribute__((always_inline));
static inline struct unix_sock_ipc_data_t *current_unix_event(void) {
    u64 key = bpf_get_current_pid_tgid();
    struct unix_sock_ipc_data_t *e = unix_event_arr.lookup(&key);
    if (!e) {
        bpf_trace_printk("failed to get current unix event\n");
        return NULL;
    }
    return e;
}

static inline struct unix_sock_ipc_data_t *current_unix_event_type(u8 expected_type) __attribute__((always_inline));
static inline struct unix_sock_ipc_data_t *current_unix_event_type(u8 expected_type) {
    struct unix_sock_ipc_data_t *e = current_unix_event();
    if (!e) {
        return NULL;
    }

    if (e->type != expected_type) {
        bpf_trace_printk("expected unix event with type %d, but found type %d\n", 
            expected_type, e->type);
        return NULL;
    }
    return e;
}

static inline struct unix_sock_ipc_data_t *new_unix_event(u8 new_type) __attribute__((always_inline));
static inline struct unix_sock_ipc_data_t *new_unix_event(u8 new_type) {
    u64 key = bpf_get_current_pid_tgid();
    struct unix_sock_ipc_data_t new = { .type = new_type };

    unix_event_arr.update(&key, &new);
    return current_unix_event_type(new_type);
}

static inline void delete_current_unix_event(void) __attribute__((always_inline));
static inline void delete_current_unix_event(void) {
    u64 key = bpf_get_current_pid_tgid();
    unix_event_arr.delete(&key);
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
        return 0;
    }
    bpf_probe_read_str(path, min((u32)path_len, (u32)name_len), name->sun_path);
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
    struct unix_sock_ipc_data_t *e = new_unix_event(UNIX_IPC_TYPE_STREAM);
    if (e) {
        e->src_pid = bpf_get_current_pid_tgid() >> 32;
        e->dst_pid = sock->sk->sk_peer_pid->numbers[0].nr;
        if (try_get_unix_socket_path(e->path, sizeof(e->path), sock)) {
            char anonymous[] = "<anonymous>";
            bpf_probe_read_str(e->path, sizeof(e->path), anonymous);
        }
    }

    return 0;
}

int retprobe_unix_stream_sendmsg(struct pt_regs *ctx) {

    int sent_count = PT_REGS_RC(ctx);
    if (sent_count < 0) {
        return 0;
    }

    struct unix_sock_ipc_data_t *e = current_unix_event_type(UNIX_IPC_TYPE_STREAM);
    if (!e) {
        bpf_trace_printk("failed to get current unix ipc event for retprobe_unix_stream_sendmsg()\n");
        return 0;
    }

    e->count = sent_count;
    unix_events.perf_submit(ctx, e, sizeof(*e));
    delete_current_unix_event();

    return 0;
}

int probe_unix_dgram_recvmsg(struct pt_regs *ctx,
                             struct socket *sock,
                             struct msghdr *msg,
                             size_t len) {
    struct unix_sock_ipc_data_t *e = new_unix_event(UNIX_IPC_TYPE_DGRAM);
    if (!e) {
        bpf_trace_printk("failed to get new unix ipc event for probe_unix_dgram_recvmsg()\n");
        return 0;
    }

    e->type = UNIX_IPC_TYPE_DGRAM;
    e->dst_pid = bpf_get_current_pid_tgid() >> 32;
    struct msghdr msg_copy = {0};
    // TODO: check result
    bpf_probe_read(&msg_copy, sizeof(msg_copy), msg);

    if (!try_get_unix_msghdr_path(e->path, sizeof(e->path), &msg_copy)) {
    } else if (try_get_unix_socket_path(e->path, sizeof(e->path), sock)) {
        char anonymous[] = "<anonymous>";
        bpf_probe_read_str(e->path, sizeof(e->path), anonymous);
    }

    return 0;

}

int retprobe_unix_dgram_recvmsg(struct pt_regs *ctx) {

    int recv_count = PT_REGS_RC(ctx);
    if (recv_count < 0) {
        return 0;
    }

    struct unix_sock_ipc_data_t *e = current_unix_event_type(UNIX_IPC_TYPE_DGRAM);
    if (!e) {
        bpf_trace_printk("failed to get current unix ipc event for retprobe_unix_dgram_recvmsg()\n");
        return 0;
    }

    e->count = recv_count;
    unix_events.perf_submit(ctx, e, sizeof(*e));
    delete_current_unix_event();

    return 0;
}

int retprobe___skb_try_recv_datagram(struct pt_regs *ctx) {

    if (!PT_REGS_RC(ctx)) {
        return 0;
    }

    struct unix_sock_ipc_data_t *e = current_unix_event();
    if (!e) {
        bpf_trace_printk("failed to get current unix ipc event for retprobe___skb_try_recv_datagram\n");
        return 0;
    }

    if (e->type != UNIX_IPC_TYPE_DGRAM) {
        return 0;
    }

    struct sk_buff *skb = (struct sk_buff*)PT_REGS_RC(ctx);
    struct unix_skb_parms *cb = (struct unix_skb_parms*)(&(skb->cb));
    e->src_pid = cb->pid->numbers[0].nr;

    if (e->src_pid == 0) {
        get_pid_for_sock(&e->src_pid, skb->sk);
    }

    return 0;
}
`

var (
    collectUnixStreams = false
    collectUnixDgrams = false
)

const (
    UNIX_IPC_TYPE_NONE = 0
    UNIX_IPC_TYPE_STREAM = iota
    UNIX_IPC_TYPE_DGRAM = iota
)

type unixSockIpcEvent struct {
    Type uint8
	SrcPid uint64
    DstPid uint64
    Count uint64
    Path [108]byte
}

func handleUnixSockIpcEvent(event *unixSockIpcEvent, sockId *SocketIdentifier) error {
    var typeStr string
    switch event.Type {
    case UNIX_IPC_TYPE_STREAM:
        typeStr = "STREAM"
    case UNIX_IPC_TYPE_DGRAM:
        typeStr = "DGRAM"
    default:
        // TODO: handle error
        return fmt.Errorf("unix ipc event had unexpected type %d", event.Type)
    }

    fmt.Printf("UNIX SOCK %v: %v --> %v over %s (%v bytes)\n",
        typeStr,
        event.SrcPid,
        event.DstPid,
        event.Path,
        event.Count)

    return nil
}

func InitUnixSocketIpcCollection(bpfBuilder *bpf.BpfBuilder, streams bool, dgrams bool) error {
    if (streams || dgrams) == false {
        return nil
    }

    if err := bpfBuilder.AddIncludes(unixIncludes); err != nil {
        return err
    }
    bpfBuilder.AddSources(unixSource)
    collectUnixStreams = streams
    collectUnixDgrams = dgrams
    return nil
}

// in theory we could pass sockId for just the datagram case
func CollectUnixSocketIpc(module *bcc.Module, exit <-chan struct{}, sockId *SocketIdentifier) error {
    if (collectUnixStreams || collectUnixDgrams) == false {
        return nil
    }

    perfChannel := make(chan []byte, 32)
    table := bcc.NewTable(module.TableId("unix_events"), module)
    perfMap, err := bcc.InitPerfMap(table, perfChannel, nil)
    if err != nil {
        return err
    }

    perfMap.Start()
    defer perfMap.Stop()

    if collectUnixStreams {
        kprobe, err := module.LoadKprobe("probe_unix_stream_sendmsg")
        if err != nil {
            return err
        }
        if err := module.AttachKprobe("unix_stream_sendmsg", kprobe, -1); err != nil {
            return err
        }

        if kprobe, err = module.LoadKprobe("retprobe_unix_stream_sendmsg"); err != nil {
            return err
        }
        if err = module.AttachKretprobe("unix_stream_sendmsg", kprobe, -1); err != nil {
            return err
        }
    }


    if collectUnixDgrams {
        kprobe, err := module.LoadKprobe("retprobe___skb_try_recv_datagram")
        if err != nil {
            return err
        }
        if err = module.AttachKretprobe("__skb_try_recv_datagram", kprobe, -1); err != nil {
            return err
        }

        kprobe, err = module.LoadKprobe("retprobe_unix_dgram_recvmsg"); if err != nil {
            return err
        }
        if err = module.AttachKretprobe("unix_dgram_recvmsg", kprobe, -1); err != nil {
            return err
        }

        if kprobe, err = module.LoadKprobe("probe_unix_dgram_recvmsg"); err != nil {
            return err
        }
        if err = module.AttachKprobe("unix_dgram_recvmsg", kprobe, -1); err != nil {
            return err
        }
    }

    for {
        select {
        case perfData := <-perfChannel:
            var event unixSockIpcEvent
            if err := binary.Read(bytes.NewBuffer(perfData), bcc.GetHostByteOrder(), &event); err != nil {
                return fmt.Errorf("failed to parse unix socket ipc event: %w", err)
            }
            if err := handleUnixSockIpcEvent(&event, sockId); err != nil {
                return fmt.Errorf("failed to handle unix socket ipc event: %w", err)
            }

        case <- exit:
            return nil
        }
    }
}

