package collection

import (
    "fmt"
    "bytes"
    "encoding/binary"
    "github.com/iovisor/gobpf/bcc"
    "github.com/guardicode/ipcdump/internal/bpf"
    "github.com/mitchellh/go-ps"
)

const ptyWriteIncludes = `
#include <uapi/linux/ptrace.h>
#include <linux/tty.h>
`

const ptyWriteSource = `
BPF_PERF_OUTPUT(pty_events);

struct __attribute__((packed)) pty_write_data_t {
    u64 src_pid;
    u64 dst_pid;
    u64 dst_sid;
    u64 count;
    char tty_name[64];
};

BPF_HASH(pty_event_arr, u64, struct pty_write_data_t);

int probe_pty_write(struct pt_regs *ctx, struct tty_struct *tty, const unsigned char *buf, int c) {
    u64 dst_pid = tty->pgrp->numbers[0].nr;
    if (dst_pid == 0) {
        return 0;
    }

    struct pty_write_data_t e = {0};
    e.src_pid = bpf_get_current_pid_tgid() >> 32;
    e.dst_pid = tty->pgrp->numbers[0].nr;
    e.dst_sid = tty->session->numbers[0].nr;
    bpf_probe_read_str(e.tty_name, sizeof(e.tty_name), tty->name);

    u64 key = bpf_get_current_pid_tgid();
    pty_event_arr.update(&key, &e);

    return 0;
}

int retprobe_pty_write(struct pt_regs *ctx, struct tty_struct *tty, const unsigned char *buf, int c) {
    int written = PT_REGS_RC(ctx);
    if (written <= 0) {
        return 0;
    }

    u64 key = bpf_get_current_pid_tgid();
    struct pty_write_data_t *e = pty_event_arr.lookup(&key);
    if (!e) {
        bpf_trace_printk("failed to get current pty write event\n");
        return 0;
    }

    e->count = written;
    pty_events.perf_submit(ctx, e, sizeof(*e));

    return 0;
}
`

type ptyWriteEvent struct {
	SrcPid uint64
    DstPid uint64
    DstSid uint64
    Count uint64
    TtyName [64]byte
}

func handlePtyWriteEvent(event *ptyWriteEvent) {
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


func InitPtyWriteCollection(bpfBuilder *bpf.BpfBuilder) error {
    if err := bpfBuilder.AddIncludes(ptyWriteIncludes); err != nil {
        return err
    }
    bpfBuilder.AddSources(ptyWriteSource)
    return nil
}

func CollectPtyWrites(module *bcc.Module, exit <-chan struct{}) error {
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
            if err := binary.Read(bytes.NewBuffer(perfData), bcc.GetHostByteOrder(), &event); err != nil {
                return fmt.Errorf("failed to parse pty write event: %w", err)
            }
            handlePtyWriteEvent(&event)

        case <- exit:
            return nil
        }
    }
}
