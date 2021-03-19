package collection

import (
	"context"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/guardicore/ipcdump/internal/bpf"
	"github.com/guardicore/ipcdump/internal/events"
	"golang.org/x/sys/unix"
)

var PTY_TEST_MESSAGE_CONTENTS = []byte("some_day_i_will_grow_out_of_being_a_message_on_this_computer_into_a_real_living_thing._hope_it's_fun_as_it_sounds.")

func checkTtyPath(t *testing.T, e *events.IpcEvent, createdName string) {
	reported := getMetadataValue(t, e, "tty_name").(string)
	lastPart := path.Base(createdName)
	// typically, OpenTestPty() will return a path like "/dev/pts/13", but the event has i.e. "pts13"
	// this is lazy but it works for the time being.
	if !strings.HasSuffix(reported, lastPart) {
		t.Errorf("expected tty_name %s but got %s", reported, lastPart)
	}
}

func TestCollectPtyWrites(t *testing.T) {
	filterCurrentProcess()

	bpfBuilder := bpf.NewBpfBuilder()
	SetupIpcBytesOutput(bpfBuilder, true, 0)
	SetupCommCollectionBpf(bpfBuilder)
	if err := InitPtyWriteCollection(bpfBuilder); err != nil {
		t.Fatalf("InitPtyWriteCollection() failed: %v", err)
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
		if err := CollectPtyWrites(mod, exit, commId); err != nil {
			t.Errorf("CollectPtyWrites() failed: %v", err)
		}
		collectDone <- struct{}{}
	}()

	time.Sleep(1 * time.Second)

	// more theft from os/signal/os/signal
	f, procTtyName, err := OpenTestPty()
	if err != nil {
		t.Fatalf("failed to open test pty: %v", err)
	}
	defer f.Close()

	procTty, err := os.OpenFile(procTtyName, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer procTty.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	otherEnd := exec.CommandContext(ctx, "/bin/bash", "--norc", "--noprofile", "-i")
	// Clear HISTFILE so that we don't read or clobber the user's bash history.
	otherEnd.Env = append(os.Environ(), "HISTFILE=")
	otherEnd.Stdin = procTty
	otherEnd.Stdout = procTty
	otherEnd.Stderr = procTty
	otherEnd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		Ctty:    0,
	}

	if err := otherEnd.Start(); err != nil {
		t.Fatalf("failed to open other end of pty: %v", err)
	}

	otherEndSid, err := unix.Getsid(otherEnd.Process.Pid)
	if err != nil {
		t.Fatalf("failed to getsid for bash: %v", err)
	}

	if err := procTty.Close(); err != nil {
		t.Errorf("failed to close tty: %v", err)
	}

	time.Sleep(500 * time.Millisecond)
	startTime := time.Now()
	e := captureEmit(t, "TestCollectPtyWrites()",
		func(*testing.T) {
			f.Write(PTY_TEST_MESSAGE_CONTENTS)
		},
		1*time.Second)
	endTime := time.Now()

	checkType(t, e, events.IPC_EVENT_PTY_WRITE)
	checkOwnSrcIpc(t, e)
	if e.Dst.Comm != "bash" {
		t.Fatalf("wrong destination comm for signal: expected bash but got %s", e.Dst.Comm)
	}
	checkTimestamp(t, e, startTime, endTime)
	checkTtyPath(t, e, procTtyName)
	checkContents(t, e, PTY_TEST_MESSAGE_CONTENTS)
	checkMetadataUint64(t, e, "dst_sid", uint64(otherEndSid))

	otherEnd.Wait()

	exit <- struct{}{}
	timeoutTest(t, "CollectPtyWrites()", func(*testing.T) { <-collectDone }, 1*time.Second)
}
