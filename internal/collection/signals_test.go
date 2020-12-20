package collection

import (
    "os"
    "os/exec"
    "syscall"
    "unsafe"
    "testing"
    "time"
    "golang.org/x/sys/unix"
    "github.com/guardicode/ipcdump/internal/events"
    "github.com/guardicode/ipcdump/internal/bpf"
)

// stolen from runtime/defs_linux_386.go
type siginfo struct {
	Signo int
	Errno int
	Pid  int
    OtherStuff [1024]byte
}

func checkSignal(t *testing.T, e *events.IpcEvent, p *os.Process, sigNum uint64, sigName string) {
        checkType(t, e, events.IPC_EVENT_SIGNAL)
        checkMetadataUint64(t, e, "num", sigNum)
        checkMetadataString(t, e, "name", sigName)
        checkOwnSrcIpc(t, e)
        if e.Dst.Pid != int64(p.Pid) {
            t.Fatalf("wrong destination pid for signal: expected %d but got %d", p.Pid, e.Dst.Pid)
        }
        if e.Dst.Comm != "sleep" {
            t.Fatalf("wrong destination comm for signal: expected sleep but got %s", e.Dst.Comm)
        }
}

func TestCollectSignals(t *testing.T) {
    bpfBuilder := bpf.NewBpfBuilder()
    SetupCommCollectionBpf(bpfBuilder)
    if err := InitSignalCollection(bpfBuilder); err != nil {
        t.Fatalf("InitSignalCollection() failed: %v", err)
    }

    mod, err := bpfBuilder.LoadModule()
    defer mod.Close()
    if err != nil {
        t.Fatalf("LoadModule() failed: %v", err)
    }

    commId, err := NewCommIdentifier(mod)
    if err != nil {
        t.Fatalf("NewCommIdentifier() failed: %v", err)
    }

    exit := make(chan struct{})
    collectDone := make(chan struct{})
    go func() {
        if err := CollectSignals(mod, exit, commId); err != nil {
            t.Errorf("CollectPipeIpc() failed: %v", err)
        }
        collectDone <- struct{}{}
    }()

    time.Sleep(1 * time.Second)

    t.Run("regularSignalsTest", func(t *testing.T) {
        p := exec.Command("sleep", "3")
        if err := p.Start(); err != nil {
            t.Fatalf("failed to start sleep for signal test: %v", err)
        }

        time.Sleep(500 * time.Millisecond)

        e := captureEmit(t, "regularSignalsTest()",
            func(*testing.T) { p.Process.Signal(os.Interrupt) },
            1 * time.Second)

        checkSignal(t, e, p.Process, uint64(os.Interrupt.(syscall.Signal)), "interrupt")

        p.Wait()
    })

    t.Run("realtimeSignalsTest", func(t *testing.T) {
        p := exec.Command("sleep", "3")
        if err := p.Start(); err != nil {
            t.Fatalf("failed to start sleep for signal test: %v", err)
        }

        time.Sleep(500 * time.Millisecond)

        e := captureEmit(t, "realtimeSignalsTest()",
            func(*testing.T) {
                si := siginfo{Signo: -1, Errno: -1}
                si.Pid = os.Getpid()
                _, _, errno := unix.Syscall(
                    unix.SYS_RT_SIGQUEUEINFO,
                    uintptr(p.Process.Pid),
                    34,
                    uintptr(unsafe.Pointer(&si)))
                if errno != 0 {
                    t.Fatalf("failed to send realtime signal: %v", errno)
                }
            },
            1 * time.Second)
        checkType(t, e, events.IPC_EVENT_SIGNAL)
        checkSignal(t, e, p.Process, 34, "signal 34")

        p.Wait()
    })

    exit <- struct{}{}
    timeoutTest(t, "CollectSignals()", func(*testing.T){ <-collectDone }, 1 * time.Second)
}
