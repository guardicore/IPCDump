package events

import (
    "time"
    "bytes"
    "math"
    "strings"
    "strconv"
    "fmt"
    "sync"
    "errors"
    "encoding/hex"
    "encoding/json"
)

type EventOutputFormat uint
const (
    EMIT_FMT_TEXT = iota
    EMIT_FMT_JSON
    EMIT_FMT_END
)

type outputFunc func(IpcEvent) error

var outputBytesLimit int = 0
var emitFunc outputFunc = outputEmittedIpcEventText

type jsonIpcEventFormat struct {
    SrcPid int64 `json:"src_pid"`
    SrcComm string `json:"src_comm"`
    DstPid int64 `json:"dst_pid"`
    DstComm string `json:"dst_comm"`
    Type string `json:"type"`
    Timestamp time.Time `json:"time"`
    Metadata IpcMetadata `json:"meta,omitempty"`
    Bytes []byte `json:"bytes,omitempty"`
}


func (m IpcMetadata) MarshalJSON() ([]byte, error) {
    buf := &bytes.Buffer{}
    buf.WriteString("{")
    for i, p := range m {
        if i > 0 {
            buf.WriteString(",")
        }
        buf.WriteString(fmt.Sprintf("%q:", p.Name))
        marshaledVal, err := json.Marshal(p.Value)
        if err != nil {
            return nil, fmt.Errorf("failed to marshal ipc metadata with name \"%v\" and value \"%v\": %w",
                p.Name, p.Value, err)
        }
        buf.Write(marshaledVal)
    }
    buf.WriteString("}")
    return buf.Bytes(), nil
}


type indentedWriter struct { }
func (w indentedWriter) Write(p []byte) (n int, err error) {
    fmt.Printf("%s", strings.ReplaceAll(string(p), "\n", "\n\t"))
    return len(p), nil
}


func dumpEventBytes(b []byte) {
    var w indentedWriter
    dumper := hex.Dumper(w)
    defer dumper.Close()

    slice := b
    if outputBytesLimit > 0 && len(slice) > outputBytesLimit {
        slice = b[:outputBytesLimit]
    }
    dumper.Write(slice)
}

func pidStr(pid int64) string {
    if pid < 0 {
        return "<unknown>"
    }
    return strconv.FormatUint((uint64)(pid), 10)
}

func outputEmittedIpcEventText(e IpcEvent) error {
    fmt.Printf("%02d:%02d:%02d.%.9d ",
        e.Timestamp.Hour(), e.Timestamp.Minute(), e.Timestamp.Second(), e.Timestamp.Nanosecond())
    fmt.Printf("%s %s(%s) > %s(%s)", e.Type,
        pidStr(e.Src.Pid), e.Src.Comm, pidStr(e.Dst.Pid), e.Dst.Comm)
    if e.Metadata != nil && len(e.Metadata) > 0 {
        fmt.Printf(": %s %v", e.Metadata[0].Name, e.Metadata[0].Value)
        for _, m := range e.Metadata[1:] {
            fmt.Printf(", %s %v", m.Name, m.Value)
        }
        fmt.Printf("\n")
    }
    if outputBytesLimit != 0 {
        if e.Bytes != nil && len(e.Bytes) > 0 {
            fmt.Printf("\t")
            dumpEventBytes(e.Bytes)
            fmt.Printf("\n")
        }
    }

    return nil
}

func outputEmittedIpcEventJson(e IpcEvent) error {
    jsonEvent := jsonIpcEventFormat{
        SrcPid: e.Src.Pid, SrcComm: e.Src.Comm,
        DstPid: e.Dst.Pid, DstComm: e.Dst.Comm,
        Type: string(e.Type),
        Timestamp: e.Timestamp,
        Metadata: e.Metadata,
    }

    if outputBytesLimit < 0 {
        jsonEvent.Bytes = e.Bytes
    } else if outputBytesLimit > 0 && len(jsonEvent.Bytes) > outputBytesLimit {
        jsonEvent.Bytes = e.Bytes[:outputBytesLimit]
    }

    j, err := json.Marshal(jsonEvent)
    if err != nil {
        return err
    }

    fmt.Println(string(j))
    return nil
}


func SetEmitOutputFormat(outputFmt EventOutputFormat) error {
    switch outputFmt {
    case EMIT_FMT_TEXT:
        emitFunc = outputEmittedIpcEventText
    case EMIT_FMT_JSON:
        emitFunc = outputEmittedIpcEventJson
    default:
        return fmt.Errorf("unrecognized output format %d", outputFmt)
    }
    return nil
}

// negative means unlimited; 0 means no payload byte output.
func SetEmitOutputBytesLimit(limit int) error {
    if limit > math.MaxUint16 {
        return errors.New("specified value was out of range")
    }
    if limit < 0 {
        outputBytesLimit = -1
    } else {
        outputBytesLimit = limit
    }
    return nil
}

// no interspersed writing!
var mu sync.Mutex

func outputIpcEvent(event IpcEvent) error {
    mu.Lock()
    defer mu.Unlock()
    return emitFunc(event)
}

