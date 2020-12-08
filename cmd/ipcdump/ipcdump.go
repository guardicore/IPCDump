package main

import (
    "time"
    "github.com/guardicode/ipcdump/internal/collection"
    "github.com/guardicode/ipcdump/internal/bpf"
    "github.com/guardicode/ipcdump/internal/events"
    "fmt"
    "os"
    "os/signal"
    "flag"
    "sync"
)

func main() {
    var dumpBytes bool
    var dumpBytesMax uint
    var filterBySrcPids uintArrayFlags
    var filterByDstPids uintArrayFlags
    var filterByPids uintArrayFlags
    var filterByTypes stringArrayFlags
    var outputFormat string

    flag.BoolVar(&dumpBytes, "x", false, "dump IPC bytes where relevant (rather than just event details).")
    flag.UintVar(&dumpBytesMax, "B", 0, "max number of bytes to dump per event, or 0 for complete event (may be large). meaningful only if -x is specified.")
    flag.Var(&filterBySrcPids, "s", "filter by source pid (can be specified more than once)")
    flag.Var(&filterByDstPids, "d", "filter by dest pid (can be specified more than once)")
    flag.Var(&filterByPids, "p", "filter by pid (either source or dest, can be specified more than once)")
    flag.Var(&filterByTypes, "t", "filter by type (can be specified more than once).\npossible values: a|all  k|signal  u|unix  ud|unix-dgram  us|unix-stream  t|pty  lo|loopback  lt|loopback-tcp  lu|loopback-udp  p|pipe")
    flag.StringVar(&outputFormat, "f", "text", "<text|json> output format (default is text)")

    flag.Parse()

    var collectSignals = false
    var collectUnixStreams = false
    var collectUnixDgrams = false
    var collectPtys = false
    var collectLoopbackTcp = false
    var collectLoopbackUdp = false
    var collectPipes = false

    var collectAllTypes = len(filterByTypes) == 0
    if !collectAllTypes {
        if len(filterByTypes) == 1 && (filterByTypes[0] == "a" || filterByTypes[0] == "all") {
            collectAllTypes = true
        }
    }

    if !dumpBytes && dumpBytesMax != 0 {
        fmt.Fprintf(os.Stderr, "cannot set output bytes limit if -x is not specified\n")
        os.Exit(1)
    }

    events.FilterBySrcPids(filterBySrcPids)
    events.FilterByDstPids(filterByDstPids)
    events.FilterByAnyPids(filterByPids)

    var outputFmt events.EventOutputFormat
    switch outputFormat {
    case "text":
        outputFmt = events.EMIT_FMT_TEXT
    case "json":
        outputFmt = events.EMIT_FMT_JSON
    default:
        fmt.Fprintf(os.Stderr, "unrecognized output format \"%s\"\n", outputFormat)
        os.Exit(1)
    }
    if err := events.SetEmitOutputFormat(outputFmt); err != nil {
        fmt.Fprintf(os.Stderr, "failed to set output format: %s\n", err)
        os.Exit(1)
    }

    if collectAllTypes {
        collectSignals = true
        collectUnixStreams = true
        collectUnixDgrams = true
        collectPtys = true
        collectLoopbackTcp = true
        collectLoopbackUdp = true
    } else {
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

            case "t":
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

            case "p":
                fallthrough
            case "pipe":
                collectPipes = true

            default:
                fmt.Fprintf(os.Stderr, "unrecognized filter type \"%s\"\n", filterType)
                os.Exit(1)
            }
        }
    }

    bpfBuilder := bpf.NewBpfBuilder()
    if err := collection.SetupIpcBytesOutput(bpfBuilder, dumpBytes, dumpBytesMax); err != nil {
        fmt.Fprintf(os.Stderr, "failed to set up ipc bytes output: %v\n", err)
        os.Exit(1)
    }

    collection.SetupCommCollectionBpf(bpfBuilder)

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
        if err := collection.SetupSockIdCollectionBpf(bpfBuilder); err != nil {
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

    if collectPipes {
        if err := collection.InitPipeIpcCollection(bpfBuilder); err != nil {
            fmt.Fprintf(os.Stderr, "failed to initialize pipe ipc collection: %v\n", err)
            os.Exit(1)
        }
    }

    bpfModule, err := bpfBuilder.LoadModule()
    if err != nil {
        fmt.Fprintf(os.Stderr, "failed to load bpf module: %v\n", err)
        os.Exit(1)
    }
    fmt.Fprintf(os.Stderr, "bpf module loaded successfully\n")

    commId, err := collection.NewCommIdentifier(bpfModule)
    if err != nil {
        fmt.Fprintf(os.Stderr, "failed to create a process comm identifier: %v\n", err)
        os.Exit(1)
    }

    var wg sync.WaitGroup
    exitChannel := make(chan struct{})

    if collectSignals {
        wg.Add(1)
        go func() {
            defer wg.Done()
            if err := collection.CollectSignals(bpfModule, exitChannel, commId); err != nil {
                fmt.Fprintf(os.Stderr, "signal collection failed: %v\n", err)
                os.Exit(1)
            }
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
            if err := collection.CollectUnixSocketIpc(bpfModule, exitChannel, commId, sockId); err != nil {
                fmt.Fprintf(os.Stderr, "unix socket ipc collection failed: %v\n", err)
                os.Exit(1)
            }
        }()
    }

    if collectLoopbackIpc {
        wg.Add(1)
        go func() {
            defer wg.Done()
            if err := collection.CollectLoopbackIpc(bpfModule, exitChannel, commId, sockId); err != nil {
                fmt.Fprintf(os.Stderr, "loopback ipc collection failed: %v\n", err)
                os.Exit(1)
            }
        }()
    }

    if collectPtys {
        wg.Add(1)
        go func() {
            defer wg.Done()
            if err := collection.CollectPtyWrites(bpfModule, exitChannel, commId); err != nil {
                fmt.Fprintf(os.Stderr, "pty write collection failed: %v\n", err)
                os.Exit(1)
            }
        }()
    }

    if collectPipes {
        wg.Add(1)
        go func() {
            defer wg.Done()
            if err := collection.CollectPipeIpc(bpfModule, exitChannel); err != nil {
                fmt.Fprintf(os.Stderr, "pipe ipc collection failed: %v\n", err)
                os.Exit(1)
            }
        }()
    }
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, os.Kill)

    <-sig

    fmt.Fprintf(os.Stderr, "\n\ngot signal, unloading bpf module...\n\n")
    bpfModule.Close()

    // yes, this is stupid. unfortunately closing the module doesn't guarantee that the perf channels
    // for bpf events stop getting new events, and if the channel buffer fills up, the call to
    // perfTable.poll() blocks indefinitely inside C.perf_reader_poll() (rawCallback() blocks on the
    // write to the the perf channel). since poll() is also in charge of halting the goroutine that
    // Start() launched, this hang blocks it from processing the call to Stop() (which writes to a
    // channel whose other end is handled by poll()). this time.Sleep() (mostly) mitigates this issue
    // by giving the perf event handlers time to empty the remaining events before calling Stop().
    time.Sleep(1 * time.Second)
    close(exitChannel)

    fmt.Fprintf(os.Stderr, "\n\ncleaning up...\n\n")
    wg.Wait()
    fmt.Fprintf(os.Stderr, "\n\ndone.\n\n")
}


