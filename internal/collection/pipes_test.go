package collection

import (
    "fmt"
    "strings"
    "path"
    "os"
    "bytes"
    "io/ioutil"
    "testing"
    "time"
    "github.com/guardicode/ipcdump/internal/events"
    "github.com/guardicode/ipcdump/internal/bpf"
    "golang.org/x/sys/unix"
)

var (
    WRITE_BEFORE_READ_STR = []byte("write_before_read")
    READ_BEFORE_WRITE_STR = []byte("read_before_write")
    FIFO_STR = []byte("comin_thru_a_fifo")
    FIFO_NAME = "fifo_test"
)

type TestFunc func(t *testing.T)
type MatchEventFunc func(e events.IpcEvent) bool

func timeoutTest(t *testing.T, name string, f TestFunc, timeout time.Duration) {
    timeoutChan := time.After(timeout)
    execDone := make(chan struct{})
    go func() {
        f(t)
        execDone<-struct{}{}
    }()
    select {
    case <-timeoutChan:
        t.Error(name + " took too long")
    case <-execDone:
        return
    }
}

func catchEmitMatch(t *testing.T, name string, f TestFunc, p MatchEventFunc, timeout time.Duration) *events.IpcEvent {
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

func writeBeforeReadTest(t *testing.T) {
    pRead, pWrite := openPipe()
    expected := expectedPipeValues{
        Inode: getFileInode(pRead),
        Name: "<anonymous>",
        Contents: WRITE_BEFORE_READ_STR,
    }

    expected.StartTime = time.Now()
    e := catchEmitMatch(t, "writeBeforeReadTest()", func(*testing.T) {

        pWrite.Write(WRITE_BEFORE_READ_STR)
        pWrite.Close()

        time.Sleep(1 * time.Second)


        buf := make([]byte, 32)
        pRead.Read(buf)
        pRead.Close()

    },
    func(e events.IpcEvent) bool {
        return getMetadataOrDefault(e, "pipe_inode", 0) == expected.Inode
    },
    3 * time.Second)
    expected.EndTime = time.Now()

    checkPipeEvent(t, e, expected)
}

func openFifo(t *testing.T, name string) (*os.File, *os.File) {
    fifoPath := path.Join(t.TempDir(), name)
    if err := unix.Mkfifo(fifoPath, 0777); err != nil {
        t.Fatalf("failed to create fifo: %v", err)
    }

    readOpenDone := make(chan struct{})
    var readEnd *os.File
    go func() {
        var err error
        readEnd, err = os.OpenFile(fifoPath, os.O_RDONLY, 0777)
        if err != nil {
            t.Fatalf("failed to open fifo read end: %v", err)
        }
        readOpenDone<- struct{}{}
    }()
    writeEnd, err := os.OpenFile(fifoPath, os.O_WRONLY, 0777)
    if err != nil {
        readEnd.Close()
        t.Fatalf("failed to open fifo write end: %v", err)
    }
    <-readOpenDone

    return readEnd, writeEnd
}

func fifoTest(t *testing.T) {
    pRead, pWrite := openFifo(t, FIFO_NAME)
    expected := expectedPipeValues{
        Inode: getFileInode(pRead),
        Name: FIFO_NAME,
        Contents: FIFO_STR,
    }

    expected.StartTime = time.Now()
    e := catchEmitMatch(t, "fifoTest()",
        func(*testing.T) {
            pWrite.Write(FIFO_STR)
            pWrite.Close()

            time.Sleep(1 * time.Second)


            buf := make([]byte, 32)
            pRead.Read(buf)
            pRead.Close()

        },
        func(e events.IpcEvent) bool {
            return getMetadataOrDefault(e, "pipe_inode", 0) == expected.Inode
        },
        3 * time.Second)
    expected.EndTime = time.Now()

    checkPipeEvent(t, e, expected)
}

func openPipe() (*os.File, *os.File) {
    var pipe []int = make([]int, 2)
    if err := unix.Pipe(pipe[:]); err != nil {
        return nil, nil
    }

    readEnd := os.NewFile((uintptr)(pipe[0]), "pipe_read")
    writeEnd := os.NewFile((uintptr)(pipe[1]), "pipe_write")

    return readEnd, writeEnd
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

func getFileInode(f *os.File) uint64 {
    var s unix.Stat_t
    if err := unix.Fstat(int(f.Fd()), &s); err != nil {
        fmt.Fprintf(os.Stderr, "warning: failed to fstat file: %v", err)
        return 0
    }
    return s.Ino
}

type expectedPipeValues struct {
    Inode uint64
    Name string
    StartTime time.Time
    EndTime time.Time
    Contents []byte
}

func checkPipeEvent(t *testing.T, e *events.IpcEvent, expected expectedPipeValues) {
    if e.Type != events.IPC_EVENT_PIPE {
        t.Errorf("expected type %v but got %v", events.IPC_EVENT_PIPE, e.Type)
    }

    ownPid := int64(os.Getpid())
    if e.Src.Pid != ownPid {
        t.Errorf("unexpected src pid %d (expected %d)", e.Src.Pid, ownPid)
    }
    if e.Dst.Pid != ownPid {
        t.Errorf("unexpected dst pid %d (expected %d)", e.Dst.Pid, ownPid)
    }
    ownComm := myComm()
    if e.Src.Comm != ownComm {
        t.Errorf("unexpected src comm %s (expected %s)", e.Src.Comm, ownComm)
    }
    if e.Dst.Comm != ownComm {
        t.Errorf("unexpected dst comm %s (expected %s)", e.Dst.Comm, ownComm)
    }

    if e.Timestamp.Before(expected.StartTime) || e.Timestamp.After(expected.EndTime) {
        t.Errorf("event timestamp %v was not between start %v and end %v",
            e.Timestamp, expected.StartTime, expected.EndTime)
    }

    if bytes.Compare(e.Bytes, expected.Contents) != 0 {
        t.Errorf("wrong payload: expected\n%v\nbut got\n%v", expected.Contents, e.Bytes)
    }

    reportedPipeName := getMetadataValue(t, e, "pipe_name").(string)
    if reportedPipeName != expected.Name {
        t.Errorf("expected <anonymous> pipe_name but got %s", expected.Name)
    }

    reportedInode := getMetadataValue(t, e, "pipe_inode").(uint64)
    if reportedInode != expected.Inode {
        t.Errorf("expected inode %d but got %d", expected.Inode, reportedInode)
    }

    reportedCount := getMetadataValue(t, e, "count").(uint64)
    expectedCount := uint64(len(expected.Contents))
    if reportedCount != expectedCount {
        t.Errorf("expected count of %d but got %d", expectedCount, reportedCount)
    }
}

func readBeforeWriteTest(t *testing.T) {
    pRead, pWrite := openPipe()
    expected := expectedPipeValues{
        Inode: getFileInode(pRead),
        Name: "<anonymous>",
        Contents: READ_BEFORE_WRITE_STR,
    }

    expected.StartTime = time.Now()
    e := catchEmitMatch(t, "readBeforeWriteTest()",
        func(*testing.T) {
            readComplete := make(chan struct{})
            go func() {
                buf := make([]byte, 32)
                pRead.Read(buf)
                pRead.Close()
                readComplete <-struct{}{}
            }()

            time.Sleep(1 * time.Second)

            pWrite.Write(READ_BEFORE_WRITE_STR)
            pWrite.Close()
            <-readComplete
        },
        func(e events.IpcEvent) bool {
            return getMetadataOrDefault(e, "pipe_inode", 0) == expected.Inode
        },
        3 * time.Second)
    expected.EndTime = time.Now()

    checkPipeEvent(t, e, expected)
}

func TestCollectPipeIpc(t *testing.T) {
    myPid := []uint64{(uint64)(os.Getpid())}
    events.FilterBySrcPids(myPid)
    events.FilterByDstPids(myPid)

    bpfBuilder := bpf.NewBpfBuilder()
    SetupIpcBytesOutput(bpfBuilder, true, 0)
    if err := InitPipeIpcCollection(bpfBuilder); err != nil {
        t.Fatalf("InitPipeIpcCollection() failed: %v", err)
    }

    mod, err := bpfBuilder.LoadModule()
    if err != nil {
        t.Fatalf("LoadModule() failed: %v", err)
    }

    exit := make(chan struct{})
    collectDone := make(chan struct{})
    go func() {
        if err := CollectPipeIpc(mod, exit); err != nil {
            t.Errorf("CollectPipeIpc() failed: %v", err)
        }
        collectDone <- struct{}{}
    }()

    time.Sleep(1 * time.Second)

    t.Run("readBeforeWriteTest", func(t *testing.T) {
        readBeforeWriteTest(t)
    })
    t.Run("writeBeforeReadTest", func(t *testing.T) {
        writeBeforeReadTest(t)
    })
    t.Run("fifoTest", func(t *testing.T) {
        fifoTest(t)
    })

    time.Sleep(1 * time.Second)
    exit <- struct{}{}

    timeoutTest(t, "CollectPipeIpc()", func(*testing.T){ <-collectDone }, 1 * time.Second) }
