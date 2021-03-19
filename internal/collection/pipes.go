package collection

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/guardicore/ipcdump/internal/bpf"
	"github.com/guardicore/ipcdump/internal/events"
	"github.com/iovisor/gobpf/bcc"
)

// probe_pipe_write() saves the last pid/comm that wrote to the pipe's inode.
// This mapping is cleaned up in probe__destroy_inode().
// probe_pipe_read() takes the last pid/comm couple stored in probe_pipe_write() in order to
// identify the source process.
// This isn't 100% accurate, but there isn't really a good way to keep track of which bytes
// were sent by which process, so it's a decent ballpark.
// Also worth noting: trying to copy bytes out of struct iovec without bounded loop support
// (only in newish kernels) is a pain, so we report just the first entry. This means we might be
// missing some bytes.

const pipeIncludes = `
#include <linux/uio.h>
#include <linux/fs.h>
`

const pipeSource = `
BPF_PERF_OUTPUT(pipe_events);

struct __attribute__((packed)) pipe_io_metadata_t {
    u64 src_pid;
    char src_comm[16];
    u64 dst_pid;
    char dst_comm[16];
    char pipe_name[256];
    u64 pipe_inode;
    u64 count;
    u64 timestamp;
};

struct __attribute__((packed)) pipe_read_info_t {
    struct pipe_io_metadata_t d;
    struct iov_iter arg_iov;
};

struct pipe_io_data_t {
    struct pipe_io_metadata_t d;
    REMAINING_BYTES_BUFFER(struct pipe_io_metadata_t);
};

struct pipe_writer_record_t {
    u64 pid;
    char comm[16];
    u64 prev_pid;
    char prev_comm[16];
};
BPF_HASH(last_pipe_writers_by_inode, u64, struct pipe_writer_record_t);

BPF_HASH(pipe_reads_by_pid_arr, u64, struct pipe_read_info_t);

BPF_PERCPU_ARRAY(working_pipe_io_arr, struct pipe_io_data_t, 1);

#ifdef COLLECT_IPC_BYTES

#define PIPE_BUF_BYTES_SIZE ((int)(sizeof(((struct pipe_io_data_t*)NULL)->bytes)))

static inline ssize_t collect_iov_bytes(unsigned char *buf, size_t buf_len, const struct iov_iter *iter, ssize_t count) __attribute__((always_inline));
static inline ssize_t collect_iov_bytes(unsigned char *buf, size_t buf_len, const struct iov_iter *iter, ssize_t count) {
    struct iov_iter iter_copy = {0};
    if (bpf_probe_read(&iter_copy, sizeof(iter_copy), iter)) {
        bpf_trace_printk("failed to copy iov_iter in collect_iov_bytes()\n");
        return -1;
    }

    if ((iter_copy.type & ITER_IOVEC) != ITER_IOVEC) {
        bpf_trace_printk("iter_copy type was %d instead of expected ITER_IOVEC (%d)\n",
            iter_copy.type, ITER_IOVEC);
        return -1;
    }

    if (iter_copy.count == 0) {
        return 0;
    }

    // for the time being, support just the first iter->iov.
    // without bounded loops this is kind of a pain.

    struct iovec iov_copy = {0};
    if (bpf_probe_read(&iov_copy, sizeof(iov_copy), &iter_copy.iov[0])) {
        bpf_trace_printk("failed to copy iovec in collect_iov_bytes()\n");
        return -1;
    }
    
    if (count < 0) {
        return -1;
    }
    size_t ucount = (size_t)count;
    int to_copy = (int)min(ucount, iov_copy.iov_len);
    if (to_copy < 0) {
        return -1;
    }
    if (to_copy > PIPE_BUF_BYTES_SIZE) {
        to_copy = PIPE_BUF_BYTES_SIZE;
    }

    if (bpf_probe_read(buf, to_copy, iov_copy.iov_base)) {
        bpf_trace_printk("failed to copy iov bytes in collect_iov_bytes()\n");
        return -1;
    }

    return to_copy;
}

#endif // COLLECT_IPC_BYTES


static inline int get_kiocb_inode(const struct kiocb *iocb, u64 *inode) __attribute__((always_inline));
static inline int get_kiocb_inode(const struct kiocb *iocb, u64 *inode) {
    if (!iocb) {
        return -1;
    }

    if (!iocb->ki_filp) {
        return -1;
    }

    if (!iocb->ki_filp->f_inode) {
        return -1;
    }

    *inode = iocb->ki_filp->f_inode->i_ino;

    return 0;
}

static inline int get_kiocb_name(const struct kiocb *iocb, char *name, size_t len) __attribute__((always_inline));
static inline int get_kiocb_name(const struct kiocb *iocb, char *name, size_t len) {
    if (!iocb) {
        return -1;
    }

    if (!iocb->ki_filp) {
        return -1;
    }

    if (!iocb->ki_filp->f_path.dentry) {
        return -1;
    }

    // this is best effort (only fifos have names)
    bpf_probe_read_str(name, len, iocb->ki_filp->f_path.dentry->d_name.name);
    return 0;
}

static inline void fill_current_pid_comm(u64 *pid, char *comm, size_t comm_len) __attribute__((always_inline));
static inline void fill_current_pid_comm(u64 *pid, char *comm, size_t comm_len) {
    *pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(comm, comm_len);
}

static inline void fill_and_submit_pipe_io_event(struct pt_regs *ctx, const struct pipe_read_info_t *read_info) __attribute__((always_inline));
static inline void fill_and_submit_pipe_io_event(struct pt_regs *ctx, const struct pipe_read_info_t *read_info) {
    int ekey = 0;
    struct pipe_io_data_t *e = working_pipe_io_arr.lookup(&ekey);
    if (e) {
        if (!bpf_probe_read(&e->d, sizeof(e->d), &read_info->d)) {

            #ifdef COLLECT_IPC_BYTES
            ssize_t collected = collect_iov_bytes(e->bytes, sizeof(e->bytes), &read_info->arg_iov, e->d.count);
            if (collected >= 0) {
                e->bytes_len = BYTES_BUF_LEN(e, collected);
            }
            #endif

            pipe_events.perf_submit(ctx, e, EVENT_SIZE(e));
        }
    }
}

ssize_t probe_pipe_read(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *to) {
    struct pipe_read_info_t read_info = {0};
    if (get_kiocb_inode(iocb, &read_info.d.pipe_inode)) {
        bpf_trace_printk("failed to get kiocb inode\n");
        return 0;
    }
    if (bpf_probe_read(&read_info.arg_iov, sizeof(read_info.arg_iov), to)) {
        bpf_trace_printk("failed to copy iov in probe_pipe_read()\n");
        return 0;
    }
    fill_current_pid_comm(&read_info.d.dst_pid, read_info.d.dst_comm, sizeof(read_info.d.dst_comm));
    get_kiocb_name(iocb, read_info.d.pipe_name, sizeof(read_info.d.pipe_name));

    u64 pkey = bpf_get_current_pid_tgid();
    pipe_reads_by_pid_arr.update(&pkey, &read_info);

    return 0;
}

ssize_t retprobe_pipe_read(struct pt_regs *ctx) {
    u64 pkey = bpf_get_current_pid_tgid();
    struct pipe_read_info_t *read_info = pipe_reads_by_pid_arr.lookup(&pkey);
    if (!read_info) {
        bpf_trace_printk("warning: failed to find current read for %d info in retprobe_pipe_read()\n", pkey);
        return 0;
    }

    u64 ino = 0;
    if (bpf_probe_read(&ino, sizeof(ino), &read_info->d.pipe_inode)) {
        bpf_trace_printk("warning: failed to copy current inode in retprobe_pipe_read()\n");
        pipe_reads_by_pid_arr.delete(&pkey);
        return 0;
    }

    ssize_t res = PT_REGS_RC(ctx);
    if (res <= 0) {
        pipe_reads_by_pid_arr.delete(&pkey);
        return 0;
    }

    struct pipe_writer_record_t *last_writer_to_this = last_pipe_writers_by_inode.lookup(&ino);
    if (last_writer_to_this == NULL) {
        bpf_trace_printk("warning: failed to find last writer to pipe %d in retprobe_pipe_read()\n",
            read_info->d.pipe_inode);
        pipe_reads_by_pid_arr.delete(&pkey);
        return 0;
    }

    read_info->d.src_pid = last_writer_to_this->pid;
    if (bpf_probe_read(read_info->d.src_comm, sizeof(read_info->d.src_comm), last_writer_to_this->comm)) {
        bpf_trace_printk("warning: failed to copy running write's source comm for pid %d\n", read_info->d.src_pid);
    }

    read_info->d.count = (u64)res;
    read_info->d.timestamp = bpf_ktime_get_ns();

    fill_and_submit_pipe_io_event(ctx, read_info);

    pipe_reads_by_pid_arr.delete(&pkey);
    return 0;
}

int probe___destroy_inode(struct inode *inode) {
    // yes, this is true of anonymous pipes as well
    if (S_ISFIFO(inode->i_mode)) {
        u64 ino = inode->i_ino;
        last_pipe_writers_by_inode.delete(&ino);
    }

    return 0;
}

ssize_t probe_pipe_write(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *from) {
    u64 pkey = bpf_get_current_pid_tgid();
    u64 pipe_inode = 0;
    if (get_kiocb_inode(iocb, &pipe_inode)) {
        bpf_trace_printk("warning failed to get kiocb inode in probe_pipe_write()\n");
        return 0;
    }

    struct pipe_writer_record_t this_write = {0};
    fill_current_pid_comm(&this_write.pid, this_write.comm, sizeof(this_write.comm));
    last_pipe_writers_by_inode.update(&pipe_inode, &this_write);

    return 0;
}
`

type pipeIoEvent struct {
	SrcPid    uint64
	SrcComm   [16]byte
	DstPid    uint64
	DstComm   [16]byte
	PipeName  [256]byte
	PipeInode uint64
	Count     uint64
	Timestamp uint64
	BytesLen  uint16
}

func InitPipeIpcCollection(bpfBuilder *bpf.BpfBuilder) error {
	if err := bpfBuilder.AddIncludes(pipeIncludes); err != nil {
		return err
	}
	bpfBuilder.AddSources(pipeSource)
	return nil
}

func handlePipeIoEvent(event *pipeIoEvent, eventBytes []byte, ipcDataEmitter *events.IpcDataEmitter) error {
	pipeName := nullStr(event.PipeName[:])
	if len(pipeName) == 0 {
		pipeName = "<anonymous>"
	}
	e := events.IpcEvent{
		Src:       events.IpcEndpoint{Pid: (int64)(event.SrcPid), Comm: commStr(event.SrcComm)},
		Dst:       events.IpcEndpoint{Pid: (int64)(event.DstPid), Comm: commStr(event.DstComm)},
		Type:      events.IPC_EVENT_PIPE,
		Timestamp: TsFromKtime(event.Timestamp),
		Metadata: events.IpcMetadata{
			events.IpcMetadataPair{Name: "pipe_name", Value: pipeName},
			events.IpcMetadataPair{Name: "pipe_inode", Value: event.PipeInode},
			events.IpcMetadataPair{Name: "count", Value: event.Count},
		},
		Bytes: eventBytes,
	}
	return ipcDataEmitter.EmitIpcEvent(e)
}

func installPipeIpcHooks(bpfMod *bpf.BpfModule) error {
	module := bpfMod.Get()
	defer bpfMod.Put()

	kprobe, err := module.LoadKprobe("probe___destroy_inode")
	if err != nil {
		return err
	}
	if err := module.AttachKprobe("__destroy_inode", kprobe, -1); err != nil {
		return err
	}

	if kprobe, err = module.LoadKprobe("probe_pipe_write"); err != nil {
		return err
	}
	if err = module.AttachKprobe("pipe_write", kprobe, -1); err != nil {
		return err
	}

	if kprobe, err = module.LoadKprobe("retprobe_pipe_read"); err != nil {
		return err
	}
	if err = module.AttachKretprobe("pipe_read", kprobe, -1); err != nil {
		return err
	}
	if kprobe, err = module.LoadKprobe("probe_pipe_read"); err != nil {
		return err
	}
	if err = module.AttachKprobe("pipe_read", kprobe, -1); err != nil {
		return err
	}

	return nil
}

func CollectPipeIpc(bpfMod *bpf.BpfModule, exit <-chan struct{}, ipcDataEmitter *events.IpcDataEmitter) error {
	perfChannel := make(chan []byte, 1024)
	lostChannel := make(chan uint64, 32)
	perfMap, err := bpfMod.InitPerfMap(perfChannel, "pipe_events", lostChannel)
	if err != nil {
		return err
	}

	perfMap.Start()
	defer perfMap.Stop()

	if err := installPipeIpcHooks(bpfMod); err != nil {
		return err
	}

	for {
		select {
		case perfData := <-perfChannel:
			var event pipeIoEvent
			eventMetadata := perfData[:unsafe.Sizeof(event)]
			if err := binary.Read(bytes.NewBuffer(eventMetadata), bcc.GetHostByteOrder(), &event); err != nil {
				return fmt.Errorf("failed to parse pipe io event: %w", err)
			}
			eventBytes := perfData[len(eventMetadata):][:event.BytesLen]
			if err := handlePipeIoEvent(&event, eventBytes, ipcDataEmitter); err != nil {
				return fmt.Errorf("failed to handle pipe io event: %w", err)
			}

		case lost := <-lostChannel:
			ipcDataEmitter.EmitLostIpcEvents(events.IPC_EVENT_PIPE, lost)

		case <-exit:
			return nil
		}
	}
}
