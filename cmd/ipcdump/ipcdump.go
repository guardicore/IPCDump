package main

import (
    "github.com/guardicode/ipcdump/internal/collection"
    "github.com/guardicode/ipcdump/internal/bpf"
    "fmt"
    "os"
    "os/signal"
    "flag"
    "sync"
    "strings"
    "strconv"

    "github.com/iovisor/gobpf/bcc"
)

// TODO: refactor out
type uintArrayFlags []uint64

func (i *uintArrayFlags) String() string {
	return ""
}

func (i *uintArrayFlags) Set(value string) error {
    u, err := strconv.ParseUint(value, 0, 32)
    if err != nil {
        return err
    }
	*i = append(*i, u)
	return nil
}

type stringArrayFlags []string

func (i *stringArrayFlags) String() string {
	return ""
}

func (i *stringArrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}
// till here



const ipcSource = `
#define KBUILD_MODNAME "IPCDUMP"

__DEFINES__

// TODO: this from outside!
#ifdef BPF_DEBUG
#define TRACE(fmt, ...) do { bpf_trace_printk(fmt, __VA_ARGS__); } while (0)
#else
#define TRACE(fmt, ...)
#endif

`


const (
    IPC_EVENT_NONE = iota
    IPC_EVENT_SIGNAL = iota
    IPC_EVENT_UNIX_SOCK_STREAM = iota
    IPC_EVENT_UNIX_SOCK_DGRAM = iota
    IPC_EVENT_PTY_WRITE = iota
    IPC_EVENT_LOOPBACK_SOCK_TCP = iota
    IPC_EVENT_LOOPBACK_SOCK_UDP = iota
)

/*func IsFilteringBySrcPid() bool {
    return len(filterBySrcPids) > 0
}
func IsFilteringByDstPid() bool {
    return len(filterByDstPids) > 0
}
func IsSrcPidAllowed(pid uint64) bool {
    if IsFilteringBySrcPid() {
        return true
    }
    _, ok = filterBySrcPids[pid]
    return ok
}
func IsDstPidAllowed(pid uint64) bool {
    if IsFilteringByDstPid() {
        return true
    }
    _, ok = filterByDstPids[pid]
    return ok
}

func EmitIpcEvent(type uint16, srcPid uint64, dstPid uint64, metadata map[string]string, contents []byte) bool {
    if !IsSrcPidAllowed(srcPid) || !IsDstPidAllowed(dstPid) {
        return false
    }
    // we rely on the type filtering to hold true at the event-generation level, so we don't check it here
}*/

func main() {
    var dumpBytes int
    var filterBySrcPids uintArrayFlags
    var filterByDstPids uintArrayFlags
    var filterByPids uintArrayFlags
    var filterByTypes stringArrayFlags
    var outputFormat string

    flag.IntVar(&dumpBytes, "X", 0, "dump IPC bytes where relevant (rather than just event details)")
    flag.Var(&filterBySrcPids, "s", "filter by source pid (can be specified more than once)")
    flag.Var(&filterByDstPids, "d", "filter by dest pid (can be specified more than once)")
    flag.Var(&filterByPids, "p", "filter by pid (either source or dest, can be specified more than once)")
    flag.Var(&filterByTypes, "t", "filter by type (can be specified more than once).\npossible values: k|signal  u|unix  ud|unix-dgram  us|unix-stream  p|pty  lo|loopback  lt|loopback-tcp  lu|loopback-udp")
    flag.StringVar(&outputFormat, "f", "text", "<text|json> output format (default is text)")

    flag.Parse()

    var collectSignals = false
    var collectUnixStreams = false
    var collectUnixDgrams = false
    var collectPtys = false
    var collectLoopbackTcp = false
    var collectLoopbackUdp = false

    var filteredSrcPids = make(map[uint64]struct{})
    var filteredDstPids = make(map[uint64]struct{})
    for _, pid := range filterByPids {
        filteredSrcPids[pid] = struct{}{}
        filteredDstPids[pid] = struct{}{}
    }
    for _, pid := range filterBySrcPids {
        filteredSrcPids[pid] = struct{}{}
    }
    for _, pid := range filterBySrcPids {
        filteredDstPids[pid] = struct{}{}
    }

    var collectAllTypes = len(filterByTypes) == 0
    if !collectAllTypes {
        if len(filterByTypes) == 1 && (filterByTypes[0] == "a" || filterByTypes[0] == "all") {
            collectAllTypes = true
        }
    }

    if collectAllTypes {
        collectSignals = true
        collectUnixStreams = true
        collectUnixDgrams = true
        collectPtys = true
        collectLoopbackTcp = true
        collectLoopbackUdp = true
    }
    for _, filterType := range filterByTypes {
        switch filterType {
        case "k":
            fallthrough
        case "signal":
            collectSignals = true

        case "us":
            fallthrough
        case "unix-stream":
            collectUnixStreams = true

        case "ud":
            fallthrough
        case "unix-dgram":
            collectUnixDgrams = true

        case "u":
            fallthrough
        case "unix":
            collectUnixStreams = true
            collectUnixDgrams = true

        case "p":
            fallthrough
        case "pty":
            collectPtys = true

        case "lt":
            fallthrough
        case "loopback-tcp":
            collectLoopbackTcp = true

        case "lu":
            fallthrough
        case "loopback-udp":
            collectLoopbackUdp = true

        case "lo":
            fallthrough
        case "loopback":
            collectLoopbackTcp = true
            collectLoopbackUdp = true

        default:
            fmt.Fprintf(os.Stderr, "unrecognized filter type \"%s\"\n", filterType)
            os.Exit(1)
        }
    }


    finalBpfProgram := strings.ReplaceAll(ipcSource, "__DEFINES__", "#define BPF_DEBUG")
    m := bcc.NewModule(finalBpfProgram, []string{})
    defer m.Close()


    bpfBuilder := bpf.NewBpfBuilder()

    if collectSignals {
        if err := collection.InitSignalCollection(bpfBuilder); err != nil {
            fmt.Fprintf(os.Stderr, "failed to initialize signal collection: %v\n", err)
            os.Exit(1)
        }
    }

    collectUnixIpc := collectUnixStreams || collectUnixDgrams
    collectLoopbackIpc := collectLoopbackTcp || collectLoopbackUdp

    needSocketId := collectUnixIpc || collectLoopbackIpc
    if needSocketId {
        if err := collection.InitSocketIdCollection(bpfBuilder); err != nil {
            fmt.Fprintf(os.Stderr, "failed to initialize socket identification: %v\n", err);
            os.Exit(1)
        }
    }

    if collectUnixIpc {
        if err := collection.InitUnixSocketIpcCollection(bpfBuilder, collectUnixStreams, collectUnixDgrams); err != nil {
            fmt.Fprintf(os.Stderr, "failed to initialize unix socket ipc collection: %v\n", err)
            os.Exit(1)
        }
    }

    if collectLoopbackIpc {
        if err := collection.InitLoopbackIpcCollection(bpfBuilder, collectLoopbackTcp, collectLoopbackUdp); err != nil {
            fmt.Fprintf(os.Stderr, "failed to initialize loopback ipc collection: %v\n", err)
            os.Exit(1)
        }
    }

    if collectPtys {
        if err := collection.InitPtyWriteCollection(bpfBuilder); err != nil {
            fmt.Fprintf(os.Stderr, "failed to initialize pty write collection: %v\n", err)
            os.Exit(1)
        }
    }

    bpfModule, err := bpfBuilder.LoadModule()
    if err != nil {
        fmt.Fprintf(os.Stderr, "failed to load bpf module: %v\n", err)
        os.Exit(1)
    }

    var wg sync.WaitGroup
    exitChannel := make(chan struct{})

    if collectSignals {
        wg.Add(1)
        go func() {
            defer wg.Done()
            collection.CollectSignals(bpfModule, exitChannel)
        }()
    }

    var sockId *collection.SocketIdentifier
    if needSocketId {
        sockId, err = collection.NewSocketIdentifier(bpfModule)
        if err != nil {
            fmt.Fprintf(os.Stderr, "failed to create a socket identifier: %v\n", err)
            os.Exit(1)
        }
    }

    if collectUnixIpc {
        wg.Add(1)
        go func() {
            defer wg.Done()
            collection.CollectUnixSocketIpc(bpfModule, exitChannel, sockId)
        }()
    }

    if collectLoopbackIpc {
        wg.Add(1)
        go func() {
            defer wg.Done()
            collection.CollectLoopbackIpc(bpfModule, exitChannel, sockId)
        }()
    }

    if collectPtys {
        wg.Add(1)
        go func() {
            defer wg.Done()
            collection.CollectPtyWrites(bpfModule, exitChannel)
        }()
    }

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, os.Kill)

    <-sig
    close(exitChannel)
    wg.Wait()
}


