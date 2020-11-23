package collection

import (
    "fmt"
    "unsafe"
    "bytes"
    "strings"
    "strconv"
    "encoding/binary"
    "github.com/iovisor/gobpf/bcc"
    "github.com/guardicode/ipcdump/internal/bpf"
    "github.com/mitchellh/go-ps"
    "github.com/guardicode/ipcdump/internal/events"
)

const ptyWriteIncludes = `
#include <uapi/linux/ptrace.h>
#include <linux/tty.h>
`

const ptyWriteSource = `
BPF_PERF_OUTPUT(pty_events);

struct pty_write_metadata_t {
    u64 src_pid;
    char src_comm[16];
    u64 dst_pid;
    char dst_comm[16];
    u64 dst_sid;
    char tty_name[64];
    u64 timestamp;
    u64 count;
};

struct pty_write_data_nobytes_t {
    struct pty_write_metadata_t d;
    const unsigned char *arg_buf;
};

struct pty_write_data_t {
    struct pty_write_metadata_t d;
    REMAINING_BYTES_BUFFER(struct pty_write_metadata_t);
};

// we use this to keep track of the same event info between the start probe and retprobe
BPF_HASH(pty_event_by_pid_arr, u64, struct pty_write_data_nobytes_t);
// and this one is just a way to work with large event structs without touching the stack
BPF_PERCPU_ARRAY(working_pty_event_arr, struct pty_write_data_t, 1);

int probe_pty_write(struct pt_regs *ctx, struct tty_struct *tty, const unsigned char *buf, int c) {
    u64 dst_pid = tty->pgrp->numbers[0].nr;

    struct pty_write_data_nobytes_t e = {0};
    e.d.timestamp = bpf_ktime_get_ns();
    e.d.src_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e.d.src_comm, sizeof(e.d.src_comm));
    e.d.dst_pid = tty->pgrp->numbers[0].nr;
    get_comm_for_pid(e.d.dst_pid, e.d.dst_comm, sizeof(e.d.dst_comm));
    e.d.dst_sid = tty->session->numbers[0].nr;
    bpf_probe_read_str(e.d.tty_name, sizeof(e.d.tty_name), tty->name);

    e.arg_buf = buf;

    u64 key = bpf_get_current_pid_tgid();
    pty_event_by_pid_arr.update(&key, &e);

    return 0;
}

int retprobe_pty_write(struct pt_regs *ctx) {
    int written = PT_REGS_RC(ctx);
    u64 pkey = bpf_get_current_pid_tgid();

    if (written <= 0) {
        pty_event_by_pid_arr.delete(&pkey);
        return 0;
    }

    struct pty_write_data_nobytes_t *event_nobytes = pty_event_by_pid_arr.lookup(&pkey);
    if (!event_nobytes) {
        bpf_trace_printk("failed to get current pty write event\n");
        return 0;
    }
    event_nobytes->d.count = written;

    int ekey = 0;
    struct pty_write_data_t *e = working_pty_event_arr.lookup(&ekey);
    if (e) {
        if (!bpf_probe_read(&e->d, sizeof(e->d), &event_nobytes->d)) {

            #ifdef COLLECT_IPC_BYTES
            e->bytes_len = BYTES_BUF_LEN(e, e->d.count);
            bpf_probe_read(e->bytes, e->bytes_len, event_nobytes->arg_buf);
            #endif

            pty_events.perf_submit(ctx, e, EVENT_SIZE(e));
        }
    }
    pty_event_by_pid_arr.delete(&pkey);

    return 0;
}
`

type ptyWriteEvent struct {
    SrcPid uint64
    SrcComm [16]byte
    DstPid uint64
    DstComm [16]byte
    DstSid uint64
    TtyName [64]byte
    Timestamp uint64
    Count uint64
    BytesLen uint16
}

func shouldSkipEvent(event *ptyWriteEvent) bool {
    dstProcess, err := ps.FindProcess((int)(event.DstPid))
    // TODO: revisit this
    if err == nil && dstProcess != nil {
        // TODO: add more spam to this list
        if dstProcess.Executable() == "tmux: client" {
            return true
        }
    }
    if (event.SrcPid == event.DstPid) {
        return true
    }

    return false
}

func handlePtyWriteEvent(event *ptyWriteEvent, eventBytes []byte, commId *CommIdentifier) error {
    if shouldSkipEvent(event) {
        return nil
    }

    ttyName := strings.TrimRight(string(event.TtyName[:]), "\x00")
    e := events.IpcEvent{
        Src: makeIpcEndpoint(commId, event.SrcPid, event.SrcComm),
        Dst: makeIpcEndpoint(commId, event.DstPid, event.DstComm),
        Type: events.IPC_EVENT_PTY_WRITE,
        Timestamp: TsFromKtime(event.Timestamp),
        Metadata: events.IpcMetadata{
            events.IpcMetadataPair{Name: "tty_name", Value: ttyName},
            events.IpcMetadataPair{Name: "dst_sid", Value: strconv.FormatUint((uint64)(event.DstSid), 10)},
            events.IpcMetadataPair{Name: "count", Value: strconv.FormatUint((uint64)(event.Count), 10)},
        },
        Bytes: eventBytes,
    }
    return events.EmitIpcEvent(e)
}


func InitPtyWriteCollection(bpfBuilder *bpf.BpfBuilder) error {
    if err := bpfBuilder.AddIncludes(ptyWriteIncludes); err != nil {
        return err
    }
    bpfBuilder.AddSources(ptyWriteSource)
    return nil
}

func CollectPtyWrites(module *bcc.Module, exit <-chan struct{}, commId *CommIdentifier) error {
    perfChannel := make(chan []byte, 1024)
    table := bcc.NewTable(module.TableId("pty_events"), module)
    perfMap, err := bcc.InitPerfMap(table, perfChannel, nil)
    if err != nil {
        return err
    }

    perfMap.Start()
    defer perfMap.Stop()

    kprobe, err := module.LoadKprobe("probe_pty_write")
    if err != nil {
        return err
    }
    if err := module.AttachKprobe("pty_write", kprobe, -1); err != nil {
        return err
    }

    if kprobe, err = module.LoadKprobe("retprobe_pty_write"); err != nil {
        return err
    }
    if err = module.AttachKretprobe("pty_write", kprobe, -1); err != nil {
        return err
    }

    for {
        select {
        case perfData := <-perfChannel:
            var event ptyWriteEvent
            eventMetadata := perfData[:unsafe.Sizeof(event)]
            if err := binary.Read(bytes.NewBuffer(eventMetadata), bcc.GetHostByteOrder(), &event); err != nil {
                return fmt.Errorf("failed to parse pty write event: %w", err)
            }
            eventBytes := perfData[len(eventMetadata):][:event.BytesLen]
            if err := handlePtyWriteEvent(&event, eventBytes, commId); err != nil {
                return fmt.Errorf("failed to handle pty write event: %w", err)
            }

        case <- exit:
            return nil
        }
    }
}
