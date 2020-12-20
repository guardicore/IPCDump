package collection

import (
    "testing"
    "os"
    "bytes"
    "strings"
    "io/ioutil"
    "time"
    "fmt"
    "golang.org/x/sys/unix"
    "github.com/guardicode/ipcdump/internal/events"
)

type TestFunc func(t *testing.T)
type MatchEventFunc func(e events.IpcEvent) bool

func getFdInode(i int) uint64 {
    var s unix.Stat_t
    if err := unix.Fstat(i, &s); err != nil {
        fmt.Fprintf(os.Stderr, "warning: failed to fstat file: %v", err)
        return 0
    }
    return s.Ino
}

func getFileInode(f *os.File) uint64 {
    return getFdInode(int(f.Fd()))
}

func filterCurrentProcess() {
    myPid := []uint64{(uint64)(os.Getpid())}
    events.FilterBySrcPids(myPid)
    events.FilterByDstPids(myPid)
}

func captureEmitMatch(t *testing.T, name string, f TestFunc, p MatchEventFunc, timeout time.Duration) *events.IpcEvent {
    prevEmit := events.EmitOutputFunc
    defer func(){ events.EmitOutputFunc = prevEmit }()

    wasCaught := false
    caughtEvent := make(chan events.IpcEvent, 1)
    events.EmitOutputFunc = func(e events.IpcEvent) error {
        if !wasCaught && p(e) {
            caughtEvent<- e
            wasCaught = true
        }
        return nil
    }

    timeoutChan := time.After(timeout)
    go func() {
        f(t)
    }()

    select {
    case <-timeoutChan:
        t.Fatal("no event was emitted for " + name)
        return nil
    case c := <-caughtEvent:
        return &c
    }
}

func captureEmit(t *testing.T, name string, f TestFunc, timeout time.Duration) *events.IpcEvent {
    return captureEmitMatch(t, name, f, func(e events.IpcEvent) bool { return true }, timeout)
}

func myComm() string {
    b, err := ioutil.ReadFile("/proc/self/comm")
    if err != nil {
        fmt.Fprintf(os.Stderr, "warning: failed to read /proc/self/comm: %v", err)
        return ""
    }

    return strings.TrimSuffix(nullStr(b), "\n")
}

func getMetadataValue(t *testing.T, e *events.IpcEvent, name string) interface{} {
    for _, p := range e.Metadata {
        if p.Name == name {
            return p.Value
        }
    }

    t.Fatalf("no metadata with name %s was found", name)
    return nil
}

func getMetadataOrDefault(e events.IpcEvent, name string, defaultVal interface{}) interface{} {
    for _, p := range e.Metadata {
        if p.Name == name {
            return p.Value
        }
    }

    return defaultVal
}

func checkOwnSrcIpc(t *testing.T, e *events.IpcEvent) {
    ownPid := int64(os.Getpid())
    if e.Src.Pid != ownPid {
        t.Errorf("unexpected src pid %d (expected %d)", e.Src.Pid, ownPid)
    }
    ownComm := myComm()
    if e.Src.Comm != ownComm {
        t.Errorf("unexpected src comm %s (expected %s)", e.Src.Comm, ownComm)
    }
}

func checkOwnDstIpc(t *testing.T, e *events.IpcEvent) {
    ownPid := int64(os.Getpid())
    if e.Dst.Pid != ownPid {
        t.Errorf("unexpected dst pid %d (expected %d)", e.Dst.Pid, ownPid)
    }
    ownComm := myComm()
    if e.Dst.Comm != ownComm {
        t.Errorf("unexpected dst comm %s (expected %s)", e.Dst.Comm, ownComm)
    }
}

func checkOwnIpc(t *testing.T, e *events.IpcEvent) {
    checkOwnSrcIpc(t, e)
    checkOwnDstIpc(t, e)
}

func checkType(t *testing.T, e *events.IpcEvent, expected events.EmittedEventType) {
    if e.Type != expected {
        t.Errorf("expected type %v but got %v", events.IPC_EVENT_PIPE, e.Type)
    }
}

func checkContents(t *testing.T, e *events.IpcEvent, expected []byte) {
    if bytes.Compare(e.Bytes, expected) != 0 {
        t.Errorf("wrong payload: expected\n%v\nbut got\n%v", expected, e.Bytes)
    }
    checkMetadataUint64(t, e, "count", uint64(len(expected)))
}

func checkTimestamp(t *testing.T, e *events.IpcEvent, start time.Time, end time.Time) {
    if e.Timestamp.Before(start) || e.Timestamp.After(end) {
        t.Errorf("event timestamp %v was not between start %v and end %v",
            e.Timestamp, start, end)
    }
}

func checkMetadataString(t *testing.T, e *events.IpcEvent, name string, expected string) {
    reported := getMetadataValue(t, e, name).(string)
    if reported != expected {
        t.Errorf("expected value %q for metadata %s, but got %q", expected, name, reported)
    }
}

func checkMetadataUint64(t *testing.T, e *events.IpcEvent, name string, expected uint64) {
    reported := getMetadataValue(t, e, name).(uint64)
    if reported != expected {
        t.Errorf("expected value %d for metadata %s, but got %d", expected, name, reported)
    }
}

func checkMetadataUint16(t *testing.T, e *events.IpcEvent, name string, expected uint16) {
    reported := getMetadataValue(t, e, name).(uint16)
    if reported != expected {
        t.Errorf("expected value %d for metadata %s, but got %d", expected, name, reported)
    }
}
