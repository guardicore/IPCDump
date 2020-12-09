package collection

import (
    "fmt"
    "unsafe"
    "bytes"
    "encoding/binary"
    "github.com/iovisor/gobpf/bcc"
    "github.com/guardicode/ipcdump/internal/bpf"
    "github.com/guardicode/ipcdump/internal/events"
)

const pipeIncludes = `
#include <linux/uio.h>
#include <linux/fs.h>
`

const pipeSource = `
BPF_PERF_OUTPUT(pipe_events);


// The flow here is a bit convoluted. Here's how it works.
// There are two situations for data transfer in a pipe: write-within-read and read-within-write.
// 1) Write-within-read: the pipe is empty. A call to pipe_read() blocks until there's something to read.
// 2) Read-within-write: the pipe is full. A call to pipe_write() blocks until the reader makes room.
//
// In case 1, we set up a new outer_pipe_io_t for the write event (with the writer's process info).
// Then, when we reach the read event inside the write event, we save all the information we need in a
// pipe_io_call_t; the event is submitted when the *read* event returns. 
// (The write event retprobe just does cleanup in this case.)
//
// Case 2 is exactly the opposite: a new outer_pipe_io_t is filled out for the initial read (reader's pid
// info this time). The write event (pipe_write() called before pipe_read() returns) fills out a
// pipe_io_call_t, and on the retprobe from pipe_write() the new event is submitted. Finally, pipe_read()'s
// retprobe does some cleanup for the initial outer_pipe_io_t.

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

struct __attribute__((packed)) pipe_io_call_t {
    struct pipe_io_metadata_t d;
    struct iov_iter arg_iov;
};

struct pipe_io_data_t {
    struct pipe_io_metadata_t d;
    REMAINING_BYTES_BUFFER(struct pipe_io_metadata_t);
};

struct outer_pipe_io_t {
    u64 pid;
    char comm[16];
};

BPF_PERCPU_ARRAY(working_pipe_io_arr, struct pipe_io_data_t, 1);

BPF_HASH(running_pipe_reads, u64, struct outer_pipe_io_t);
BPF_HASH(running_pipe_writes, u64, struct outer_pipe_io_t);

BPF_HASH(pipe_reads_by_pid_arr, u64, struct pipe_io_call_t);
BPF_HASH(pipe_writes_by_pid_arr, u64, struct pipe_io_call_t);

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

static inline void fill_and_submit_pipe_io_event(struct pt_regs *ctx, const struct pipe_io_call_t *call) __attribute__((always_inline));
static inline void fill_and_submit_pipe_io_event(struct pt_regs *ctx, const struct pipe_io_call_t *call) {
    int ekey = 0;
    struct pipe_io_data_t *e = working_pipe_io_arr.lookup(&ekey);
    if (e) {
        if (!bpf_probe_read(&e->d, sizeof(e->d), &call->d)) {

            #ifdef COLLECT_IPC_BYTES
            ssize_t collected = collect_iov_bytes(e->bytes, sizeof(e->bytes), &call->arg_iov, e->d.count);
            if (collected >= 0) {
                e->bytes_len = BYTES_BUF_LEN(e, collected);
            }
            #endif

            pipe_events.perf_submit(ctx, e, EVENT_SIZE(e));
        }
    }
}

ssize_t probe_pipe_read(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *to) {
    struct pipe_io_call_t call = {0};
    if (get_kiocb_inode(iocb, &call.d.pipe_inode)) {
        bpf_trace_printk("failed to get kiocb inode\n");
        return 0;
    }

    struct outer_pipe_io_t *running_write = running_pipe_writes.lookup(&call.d.pipe_inode);
    if (running_write) {
        if (bpf_probe_read(&call.arg_iov, sizeof(call.arg_iov), to)) {
            bpf_trace_printk("failed to copy iov in probe_pipe_read()\n");
            return 0;
        }
        call.d.src_pid = running_write->pid;
        if (bpf_probe_read(call.d.src_comm, sizeof(call.d.src_comm), running_write->comm)) {
            bpf_trace_printk("warning: failed to copy running write's source comm for pid %d\n", call.d.src_pid);
        }
        fill_current_pid_comm(&call.d.dst_pid, call.d.dst_comm, sizeof(call.d.dst_comm));
        get_kiocb_name(iocb, call.d.pipe_name, sizeof(call.d.pipe_name));

    } else {
        struct outer_pipe_io_t this_read = {0};
        fill_current_pid_comm(&this_read.pid, this_read.comm, sizeof(this_read.comm));

        running_pipe_reads.update(&call.d.pipe_inode, &this_read);
    }
    u64 pkey = bpf_get_current_pid_tgid();
    pipe_reads_by_pid_arr.update(&pkey, &call);

    return 0;
}

ssize_t retprobe_pipe_read(struct pt_regs *ctx) {
    u64 pkey = bpf_get_current_pid_tgid();
    struct pipe_io_call_t *read_call = pipe_reads_by_pid_arr.lookup(&pkey);
    if (!read_call) {
        return 0;
    }

    u64 ino = 0;
    if (bpf_probe_read(&ino, sizeof(ino), &read_call->d.pipe_inode)) {
        return 0;
    }
    running_pipe_reads.delete(&ino);

    if (!running_pipe_writes.lookup(&ino)) {
        pipe_reads_by_pid_arr.delete(&pkey);
        return 0;
    }

    ssize_t res = PT_REGS_RC(ctx);
    if (res <= 0) {
        pipe_reads_by_pid_arr.delete(&pkey);
        return 0;
    }

    read_call->d.count = (u64)res;
    read_call->d.timestamp = bpf_ktime_get_ns();

    fill_and_submit_pipe_io_event(ctx, read_call);

    pipe_reads_by_pid_arr.delete(&pkey);
    return 0;
}

ssize_t probe_pipe_write(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *from) {
    struct pipe_io_call_t call = {0};
    if (get_kiocb_inode(iocb, &call.d.pipe_inode)) {
        bpf_trace_printk("failed to get kiocb inode\n");
        return 0;
    }

    struct outer_pipe_io_t *running_read = running_pipe_reads.lookup(&call.d.pipe_inode);
    if (running_read) {
        if (bpf_probe_read(&call.arg_iov, sizeof(call.arg_iov), from)) {
            bpf_trace_printk("failed to copy iov in probe_pipe_write()\n");
            return 0;
        }
        call.d.dst_pid = running_read->pid;
        if (bpf_probe_read(call.d.dst_comm, sizeof(call.d.dst_comm), running_read->comm)) {
            bpf_trace_printk("warning: failed to copy running read's destination comm for pid %d\n", call.d.dst_pid);
        }
        fill_current_pid_comm(&call.d.src_pid, call.d.src_comm, sizeof(call.d.src_comm));
        get_kiocb_name(iocb, call.d.pipe_name, sizeof(call.d.pipe_name));

    } else {
        struct outer_pipe_io_t this_write = {0};
        fill_current_pid_comm(&this_write.pid, this_write.comm, sizeof(this_write.comm));

        running_pipe_writes.update(&call.d.pipe_inode, &this_write);
    }
    u64 pkey = bpf_get_current_pid_tgid();
    pipe_writes_by_pid_arr.update(&pkey, &call);

    return 0;
}

ssize_t retprobe_pipe_write(struct pt_regs *ctx) {
    u64 pkey = bpf_get_current_pid_tgid();
    struct pipe_io_call_t *write_call = pipe_writes_by_pid_arr.lookup(&pkey);
    if (!write_call) {
        return 0;
    }

    u64 ino = 0;
    if (bpf_probe_read(&ino, sizeof(ino), &write_call->d.pipe_inode)) {
        return 0;
    }
    running_pipe_writes.delete(&ino);

    if (!running_pipe_reads.lookup(&ino)) {
        pipe_writes_by_pid_arr.delete(&pkey);
        return 0;
    }

    ssize_t res = PT_REGS_RC(ctx);
    if (res <= 0) {
        pipe_writes_by_pid_arr.delete(&pkey);
        return 0;
    }

    write_call->d.count = (u64)res;
    write_call->d.timestamp = bpf_ktime_get_ns();

    fill_and_submit_pipe_io_event(ctx, write_call);

    pipe_reads_by_pid_arr.delete(&pkey);
    return 0;
}
`

type pipeIoEvent struct {
    SrcPid uint64
    SrcComm [16]byte
    DstPid uint64
    DstComm [16]byte
    PipeName [256]byte
    PipeInode uint64
    Count uint64
    Timestamp uint64
    BytesLen uint16
}

func InitPipeIpcCollection(bpfBuilder *bpf.BpfBuilder) error {
    if err := bpfBuilder.AddIncludes(pipeIncludes); err != nil {
        return err
    }
    bpfBuilder.AddSources(pipeSource)
    return nil
}

func handlePipeIoEvent(event *pipeIoEvent, eventBytes []byte) error {
    pipeName := nullStr(event.PipeName[:])
    if len(pipeName) == 0 {
        pipeName = "<anonymous>"
    }
    e := events.IpcEvent{
        Src: events.IpcEndpoint{Pid: (int64)(event.SrcPid), Comm: commStr(event.SrcComm)},
        Dst: events.IpcEndpoint{Pid: (int64)(event.DstPid), Comm: commStr(event.DstComm)},
        Type: events.IPC_EVENT_PIPE,
        Timestamp: TsFromKtime(event.Timestamp),
        Metadata: events.IpcMetadata{
            events.IpcMetadataPair{Name: "pipe_name", Value: pipeName},
            events.IpcMetadataPair{Name: "pipe_inode", Value: event.PipeInode},
            events.IpcMetadataPair{Name: "count", Value: event.Count},
        },
        Bytes: eventBytes,
    }
    return events.EmitIpcEvent(e)
}

func installPipeIpcHooks(bpfMod *bpf.BpfModule) error {
    module := bpfMod.Get()
    defer bpfMod.Put()

    kprobe, err := module.LoadKprobe("retprobe_pipe_write")
    if err != nil {
        return err
    }
    if err := module.AttachKretprobe("pipe_write", kprobe, -1); err != nil {
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

func CollectPipeIpc(bpfMod *bpf.BpfModule, exit <-chan struct{}) error {
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
            if err := handlePipeIoEvent(&event, eventBytes); err != nil {
                return fmt.Errorf("failed to handle pipe io event: %w", err)
            }

        case lost := <-lostChannel:
            events.EmitLostIpcEvents(events.IPC_EVENT_PIPE, lost)

        case <- exit:
            return nil
        }
    }
}
