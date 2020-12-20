package collection

import (
    "path"
    "os"
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

func writeBeforeReadTest(t *testing.T) {
    pRead, pWrite := openPipe()
    expected := expectedPipeValues{
        Inode: getFileInode(pRead),
        Name: "<anonymous>",
        Contents: WRITE_BEFORE_READ_STR,
    }

    expected.StartTime = time.Now()
    e := captureEmitMatch(t, "writeBeforeReadTest()", func(*testing.T) {

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
    e := captureEmitMatch(t, "fifoTest()",
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

type expectedPipeValues struct {
    Inode uint64
    Name string
    StartTime time.Time
    EndTime time.Time
    Contents []byte
}

func checkPipeEvent(t *testing.T, e *events.IpcEvent, expected expectedPipeValues) {
    checkType(t, e, events.IPC_EVENT_PIPE)
    checkOwnIpc(t, e)
    checkTimestamp(t, e, expected.StartTime, expected.EndTime)

    checkMetadataString(t, e, "pipe_name", expected.Name)
    checkMetadataUint64(t, e, "pipe_inode", expected.Inode)
    checkContents(t, e, expected.Contents)
}

func readBeforeWriteTest(t *testing.T) {
    pRead, pWrite := openPipe()
    expected := expectedPipeValues{
        Inode: getFileInode(pRead),
        Name: "<anonymous>",
        Contents: READ_BEFORE_WRITE_STR,
    }

    expected.StartTime = time.Now()
    e := captureEmitMatch(t, "readBeforeWriteTest()",
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
    filterCurrentProcess()

    bpfBuilder := bpf.NewBpfBuilder()
    SetupIpcBytesOutput(bpfBuilder, true, 0)
    if err := InitPipeIpcCollection(bpfBuilder); err != nil {
        t.Fatalf("InitPipeIpcCollection() failed: %v", err)
    }

    mod, err := bpfBuilder.LoadModule()
    defer mod.Close()
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

    exit <- struct{}{}
    timeoutTest(t, "CollectPipeIpc()", func(*testing.T){ <-collectDone }, 1 * time.Second) }
