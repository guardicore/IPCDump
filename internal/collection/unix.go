package collection

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/guardicode/ipcdump/internal/bpf"
	"github.com/guardicode/ipcdump/internal/events"
	"github.com/iovisor/gobpf/bcc"
)

// These hooks aren't particularly complicated, but there's a lot of boilerplate to them.
// (Particularly to extracting the unix socket path from the sockets.)
// Datagram sockets don't store a connection state, so we can't always figure out who
// the sender is directly; we fill that in based on the source inode where necessary.
// The other issue that complicates these hooks is that unix_stream_sendmsg() and
// unix_dgram_recvmsg() use struct iov_iter rather than simple pointer-length buffers.
// Copying bytes out of these structs without bounded loop support is very frustrating
// (we have the same issue with pipe i/o). Fortunately, both unix_stream_sendmsg() and
// unix_dgram_recvmsg() internally handle one buffer from the iovec at a time using a
// helper function: skb_copy_datagram_from_iter() in streams and __skb_try_recv_datagram()
// in datagrams. So we store the metadata we need on entry to unix_stream_sendmsg() and to
// unix_dgram_recvmsg(), and then report a new event *for each* single buffer transfered in
// these helper functions.

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

struct __attribute__((packed)) unix_sock_ipc_metadata_t {
    u64 src_pid;
    char src_comm[16];
    u64 dst_pid;
    char dst_comm[16];
    u64 count;
    u64 src_inode;
    u64 timestamp;
    char path[108];
    u32 pad0;
    u8 type;
    u8 pad1;
    u16 pad2;
    u32 pad3;
    u32 pad4;
    u32 pad5;
};

struct __attribute__((packed)) unix_sock_ipc_data_t {
    struct unix_sock_ipc_metadata_t d;
    REMAINING_BYTES_BUFFER(struct unix_sock_ipc_metadata_t);
};

BPF_PERF_OUTPUT(unix_events);

BPF_HASH(unix_event_arr, u64, struct unix_sock_ipc_metadata_t);
BPF_PERCPU_ARRAY(working_unix_event_arr, struct unix_sock_ipc_data_t, 1);


static inline struct unix_sock_ipc_metadata_t *current_unix_event(void) __attribute__((always_inline));
static inline struct unix_sock_ipc_metadata_t *current_unix_event(void) {
    u64 key = bpf_get_current_pid_tgid();
    struct unix_sock_ipc_metadata_t *e = unix_event_arr.lookup(&key);
    if (!e) {
        return NULL;
    }
    return e;
}

static inline struct unix_sock_ipc_metadata_t *current_unix_event_type(u8 expected_type) __attribute__((always_inline));
static inline struct unix_sock_ipc_metadata_t *current_unix_event_type(u8 expected_type) {
    struct unix_sock_ipc_metadata_t *e = current_unix_event();
    if (!e) {
        bpf_trace_printk("no current unix event was found (expected type %d)\n", expected_type);
        return NULL;
    }

    if (e->type != expected_type) {
        bpf_trace_printk("expected unix event with type %d, but found type %d\n", 
            expected_type, e->type);
        return NULL;
    }
    return e;
}

static inline struct unix_sock_ipc_metadata_t *new_unix_event(u8 new_type) __attribute__((always_inline));
static inline struct unix_sock_ipc_metadata_t *new_unix_event(u8 new_type) {
    u64 key = bpf_get_current_pid_tgid();
    struct unix_sock_ipc_metadata_t new = { .type = new_type, .pad0 = 1, .pad1 = 2, .pad2 = 3, .pad4 = 5, .pad5 = 6 };

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
        if (read_len < 0 || read_len >= sizeof(name->sun_path)) {
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

    if (!addr) {
        return -1;
    }

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

int probe_unix_stream_sendmsg(struct pt_regs *ctx,
                              struct socket *sock,
                              struct msghdr *msg,
                              size_t len) {
    struct unix_sock_ipc_metadata_t *e = new_unix_event(UNIX_IPC_TYPE_STREAM);
    if (!e) {
        bpf_trace_printk("failed to get new unix ipc event for probe_unix_stream_sendmsg()\n");
        return 0;
    }

    e->timestamp = bpf_ktime_get_ns();
    e->src_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->src_comm, sizeof(e->src_comm));
    e->dst_pid = sock->sk->sk_peer_pid->numbers[0].nr;
    get_comm_for_pid(e->dst_pid, e->dst_comm, sizeof(e->dst_comm));

    try_get_unix_socket_path(e->path, sizeof(e->path), sock);

    return 0;
}

BPF_HASH(copied_dgram_skb_arr, u64, struct sk_buff*);

int probe_skb_copy_datagram_from_iter(struct pt_regs *ctx,
                                      struct sk_buff *skb,
                                      int offset,
                                      struct iov_iter *from,
                                      int len) {
    if (!skb) {
        return 0;
    }

    struct unix_sock_ipc_metadata_t *event_metadata = current_unix_event();
    if (!event_metadata || event_metadata->type != UNIX_IPC_TYPE_STREAM) {
        return 0;
    }

    u64 key = bpf_get_current_pid_tgid();
    copied_dgram_skb_arr.update(&key, &skb);

    return 0;
}

static inline int fill_and_submit_unix_event(struct pt_regs *ctx, const struct unix_sock_ipc_metadata_t *event_metadata, const struct sk_buff *skb) __attribute__((always_inline));
static inline int fill_and_submit_unix_event(struct pt_regs *ctx, const struct unix_sock_ipc_metadata_t *event_metadata, const struct sk_buff *skb) {
    int ekey = 0;
    struct unix_sock_ipc_data_t *e = working_unix_event_arr.lookup(&ekey);
    if (!e) {
        bpf_trace_printk("failed to get working unix ipc event in fill_and_submit_unix_event()\n");
        return 0;
    }

    if (bpf_probe_read(&e->d, sizeof(e->d), event_metadata)) {
        bpf_trace_printk("failed to copy unix ipc event metadata in fill_and_submit_unix_event()\n");
        return 0;
    }

    #ifdef COLLECT_IPC_BYTES
    unsigned char *head_ptr = NULL;
    if (bpf_probe_read(&head_ptr, sizeof(head_ptr), &skb->head)) {
        bpf_trace_printk("failed to get unix socket head ptr in fill_and_submit_unix_event()\n");
        return 0;
    }

    e->bytes_len = BYTES_BUF_LEN(e, e->d.count);
    if (bpf_probe_read(e->bytes, e->bytes_len, head_ptr)) {
        bpf_trace_printk("failed to copy unix ipc event stream bytes in fill_and_submit_unix_event()\n");
    }
    #endif

    unix_events.perf_submit(ctx, e, EVENT_SIZE(e));

    return 0;
}

// this is called once per skb_copy_datagram_from_iter(), which *may be more* than once per sendmsg().
int retprobe_skb_copy_datagram_from_iter(struct pt_regs *ctx) {

    u64 pkey = bpf_get_current_pid_tgid();
    struct sk_buff **skb_ptr = copied_dgram_skb_arr.lookup(&pkey);
    if (!skb_ptr) {
        bpf_trace_printk("failed to lookup saved argument skb in retprobe_skb_copy_datagram_from_iter()\n");
        return 0;
    }
    struct sk_buff *skb = *skb_ptr;
    copied_dgram_skb_arr.delete(&pkey);


    struct unix_sock_ipc_metadata_t *event_metadata = current_unix_event();
    if (!event_metadata || event_metadata->type != UNIX_IPC_TYPE_STREAM) {
        return 0;
    }

    event_metadata->count = skb->len;

    if (fill_and_submit_unix_event(ctx, event_metadata, skb)) {
        bpf_trace_printk("failed to fill and submit unix ipc event in retprobe_skb_copy_datagram_from_iter()\n");
    }

    return 0;
}

int retprobe_unix_stream_sendmsg(struct pt_regs *ctx) {
    delete_current_unix_event();
    return 0;
}

int probe_unix_dgram_recvmsg(struct pt_regs *ctx,
    struct socket *sock,
    struct msghdr *msg,
    size_t len) {

    struct unix_sock_ipc_metadata_t *e = new_unix_event(UNIX_IPC_TYPE_DGRAM);
    if (!e) {
        bpf_trace_printk("failed to get new unix ipc event for probe_unix_dgram_recvmsg()\n");
        return 0;
    }

    e->timestamp = bpf_ktime_get_ns();
    e->type = UNIX_IPC_TYPE_DGRAM;
    e->dst_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->dst_comm, sizeof(e->dst_comm));

    struct msghdr msg_copy = {0};
    if (bpf_probe_read(&msg_copy, sizeof(msg_copy), msg)) {
        bpf_trace_printk("failed to copy msghdr in probe_unix_dgram_recvmsg()\n");
        return 0;
    }

    if (try_get_unix_msghdr_path(e->path, sizeof(e->path), &msg_copy)) {
        try_get_unix_socket_path(e->path, sizeof(e->path), sock);
    }

    return 0;

}


int retprobe_unix_dgram_recvmsg(struct pt_regs *ctx) {
    delete_current_unix_event();
    return 0;
}

int retprobe___skb_try_recv_datagram(struct pt_regs *ctx) {

    struct sk_buff *skb = (struct sk_buff*)PT_REGS_RC(ctx);
    if (!skb) {
        return 0;
    }

    struct unix_sock_ipc_metadata_t *event_metadata = current_unix_event();
    if (!event_metadata || event_metadata->type != UNIX_IPC_TYPE_DGRAM) {
        return 0;
    }

    struct unix_skb_parms *cb = (struct unix_skb_parms*)(&(skb->cb));
    event_metadata->src_pid = cb->pid->numbers[0].nr;
    event_metadata->src_inode = skb->sk->sk_socket->file->f_inode->i_ino;

    if (event_metadata->src_pid == 0) {
        get_pid_comm_for_sock(&event_metadata->src_pid, 
            event_metadata->src_comm, 
            sizeof(event_metadata->src_comm),
            skb->sk);
    }

    event_metadata->count = skb->len;

    if (fill_and_submit_unix_event(ctx, event_metadata, skb)) {
        bpf_trace_printk("failed to fill and submit unix ipc event in retprobe___skb_try_recv_datagram()\n");
    }

    return 0;
}
`

var (
	collectUnixStreams = false
	collectUnixDgrams  = false
)

const (
	UNIX_IPC_TYPE_NONE   = 0
	UNIX_IPC_TYPE_STREAM = iota
	UNIX_IPC_TYPE_DGRAM  = iota
)

type unixSockIpcEvent struct {
	SrcPid    uint64
	SrcComm   [16]byte
	DstPid    uint64
	DstComm   [16]byte
	Count     uint64
	SrcInode  uint64
	Timestamp uint64
	Path      [108]byte
	_         uint32
	Type      uint8
	_         uint8
	_         uint16
	_         uint32
	_         uint32
	_         uint32
	BytesLen  uint16
}

func handleUnixSockIpcEvent(event *unixSockIpcEvent, eventBytes []byte, commId *CommIdentifier,
	sockId *SocketIdentifier) error {

	var eventType events.EmittedEventType
	switch event.Type {
	case UNIX_IPC_TYPE_STREAM:
		eventType = events.IPC_EVENT_UNIX_SOCK_STREAM
	case UNIX_IPC_TYPE_DGRAM:
		eventType = events.IPC_EVENT_UNIX_SOCK_DGRAM
	default:
		return fmt.Errorf("unix ipc event had unexpected type %d", event.Type)
	}

	path := nullStr(event.Path[:])
	if len(path) == 0 {
		path = "<anonymous>"
	}

	metadata := events.IpcMetadata{
		events.IpcMetadataPair{Name: "path", Value: path},
		events.IpcMetadataPair{Name: "count", Value: event.Count},
	}

	srcPid := (int64)(event.SrcPid)
	if eventType == events.IPC_EVENT_UNIX_SOCK_DGRAM {
		metadata = append(metadata,
			events.IpcMetadataPair{Name: "src_inode", Value: event.SrcInode})
		if srcPid <= 0 {
			srcPidU, ok := sockId.GuessMissingSockPidFromUsermode(event.SrcInode)
			if !ok {
				srcPid = -1
			} else {
				srcPid = (int64)(srcPidU)
			}
		}
	}

	e := events.IpcEvent{
		Src:       makeIpcEndpointI(commId, srcPid, event.SrcComm),
		Dst:       makeIpcEndpoint(commId, event.DstPid, event.DstComm),
		Type:      eventType,
		Timestamp: TsFromKtime(event.Timestamp),
		Metadata:  metadata,
		Bytes:     eventBytes,
	}
	return events.EmitIpcEvent(e)
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

func installUnixSocketHooks(bpfMod *bpf.BpfModule) error {
	module := bpfMod.Get()
	defer bpfMod.Put()

	if collectUnixStreams {
		kprobe, err := module.LoadKprobe("retprobe_unix_stream_sendmsg")
		if err != nil {
			return err
		}
		if err = module.AttachKretprobe("unix_stream_sendmsg", kprobe, -1); err != nil {
			return err
		}

		kprobe, err = module.LoadKprobe("probe_unix_stream_sendmsg")
		if err != nil {
			return err
		}
		if err = module.AttachKprobe("unix_stream_sendmsg", kprobe, -1); err != nil {
			return err
		}

		kprobe, err = module.LoadKprobe("retprobe_skb_copy_datagram_from_iter")
		if err != nil {
			return err
		}
		if err = module.AttachKretprobe("skb_copy_datagram_from_iter", kprobe, -1); err != nil {
			return err
		}
		kprobe, err = module.LoadKprobe("probe_skb_copy_datagram_from_iter")
		if err != nil {
			return err
		}
		if err = module.AttachKprobe("skb_copy_datagram_from_iter", kprobe, -1); err != nil {
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

		kprobe, err = module.LoadKprobe("retprobe_unix_dgram_recvmsg")
		if err != nil {
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

	return nil
}

// in theory we could pass sockId for just the datagram case
func CollectUnixSocketIpc(bpfMod *bpf.BpfModule, exit <-chan struct{}, commId *CommIdentifier,
	sockId *SocketIdentifier) error {

	if (collectUnixStreams || collectUnixDgrams) == false {
		return nil
	}

	perfChannel := make(chan []byte, 1024)
	lostChannel := make(chan uint64, 32)
	perfMap, err := bpfMod.InitPerfMap(perfChannel, "unix_events", lostChannel)
	if err != nil {
		return err
	}

	perfMap.Start()
	defer perfMap.Stop()

	if err := installUnixSocketHooks(bpfMod); err != nil {
		return err
	}

	for {
		select {
		case perfData := <-perfChannel:
			var event unixSockIpcEvent
			eventMetadata := perfData[:unsafe.Sizeof(event)]
			if err := binary.Read(bytes.NewBuffer(eventMetadata), bcc.GetHostByteOrder(), &event); err != nil {
				return fmt.Errorf("failed to parse unix sock ipc event: %w", err)
			}
			eventBytes := perfData[len(eventMetadata):][:event.BytesLen]
			if err := handleUnixSockIpcEvent(&event, eventBytes, commId, sockId); err != nil {
				return fmt.Errorf("failed to handle unix socket ipc event: %w", err)
			}

		case lost := <-lostChannel:
			events.EmitLostIpcEvents(events.IPC_EVENT_UNIX_SOCK_STREAM_OR_DGRAM, lost)

		case <-exit:
			return nil
		}
	}
}
