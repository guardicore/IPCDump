package events

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type EventOutputFormat uint

const (
	EMIT_FMT_TEXT = iota
	EMIT_FMT_JSON
	EMIT_FMT_CSV
	EMIT_FMT_END
)

type outputFunc func(IpcEvent) error
type outputLostFunc func(EmittedEventType, uint64, time.Time) error

var CSVHeader string = "timestamp,type,src_pid,src_comm,dst_pid,dst_comm"
var printCSVHeader = false
var outputBytesLimit int = 0
var limitEventCount bool = false
var eventCountLimit uint = 0
var EmitOutputFunc outputFunc = outputEmittedIpcEventText
var EmitOutputLostFunc outputLostFunc = outputLostIpcEventsText

type jsonIpcEventFormat struct {
	SrcPid    int64       `json:"src_pid"`
	SrcComm   string      `json:"src_comm"`
	DstPid    int64       `json:"dst_pid"`
	DstComm   string      `json:"dst_comm"`
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"time"`
	Metadata  IpcMetadata `json:"meta,omitempty"`
	Bytes     []byte      `json:"bytes,omitempty"`
}

type jsonIpcLostEventFormat struct {
	LostType  string    `json:"lost_type"`
	Count     uint64    `json:"count"`
	Timestamp time.Time `json:"time"`
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

type indentedWriter struct{}

func (w indentedWriter) Write(p []byte) (n int, err error) {
	emitOutput("%s", strings.ReplaceAll(string(p), "\n", "\n\t"))
	return len(p), nil
}

func emitOutput(output string, args ...interface{}) {
	fmt.Printf(output+"\n", args...)
}

func getEventBytes(b []byte) string {
	buf := new(bytes.Buffer)
	dumper := hex.Dumper(buf)
	defer dumper.Close()

	slice := b
	if outputBytesLimit > 0 && len(slice) > outputBytesLimit {
		slice = b[:outputBytesLimit]
	}
	dumper.Write(slice)
	return buf.String()
}

func pidStr(pid int64) string {
	if pid < 0 {
		return "<unknown>"
	}
	return strconv.FormatUint((uint64)(pid), 10)
}

func formatTimestamp(ts time.Time) string {
	return fmt.Sprintf("%02d:%02d:%02d.%.9d", ts.Hour(), ts.Minute(), ts.Second(), ts.Nanosecond())
}

func printTimestamp(ts time.Time) {
	emitOutput(formatTimestamp(ts))
}

func outputEmittedIpcEventText(e IpcEvent) error {
	var output = fmt.Sprintf("%s %s %s(%s) > %s(%s)", formatTimestamp(e.Timestamp),
		e.Type, pidStr(e.Src.Pid), e.Src.Comm, pidStr(e.Dst.Pid), e.Dst.Comm)
	if e.Metadata != nil && len(e.Metadata) > 0 {
		output += fmt.Sprintf(": %s %v", e.Metadata[0].Name, e.Metadata[0].Value)
		for _, m := range e.Metadata[1:] {
			output += fmt.Sprintf(", %s %v", m.Name, m.Value)
		}
		emitOutput(output)
		output = ""
	}
	if outputBytesLimit != 0 {
		if e.Bytes != nil && len(e.Bytes) > 0 {
			output += fmt.Sprintf("\t")
			output += getEventBytes(e.Bytes)
			emitOutput(output)
			output = ""
		}
	}

	return nil
}

func outputLostIpcEventsText(t EmittedEventType, lost uint64, ts time.Time) error {
	printTimestamp(ts)
	emitOutput(" %s: lost %d events", t, lost)
	return nil
}

func outputEmittedIpcEventJson(e IpcEvent) error {
	jsonEvent := jsonIpcEventFormat{
		SrcPid: e.Src.Pid, SrcComm: e.Src.Comm,
		DstPid: e.Dst.Pid, DstComm: e.Dst.Comm,
		Type:      string(e.Type),
		Timestamp: e.Timestamp,
		Metadata:  e.Metadata,
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

func outputLostIpcEventsJson(t EmittedEventType, lost uint64, ts time.Time) error {
	jsonEvent := jsonIpcLostEventFormat{
		LostType:  string(t),
		Count:     lost,
		Timestamp: ts,
	}
	j, err := json.Marshal(jsonEvent)
	if err != nil {
		return err
	}

	fmt.Println(string(j))
	return nil
}

func outputEmittedIpcEventCsv(e IpcEvent) error {
	if printCSVHeader {
		fmt.Print(CSVHeader)
		printCSVHeader = false
	}

	emitOutput("%s,%s,%s,%s,%s,%s", formatTimestamp(e.Timestamp), e.Type,
		pidStr(e.Src.Pid), e.Src.Comm, pidStr(e.Dst.Pid), e.Dst.Comm)
	return nil
}

func outputLostIpcEventsCsv(t EmittedEventType, lost uint64, ts time.Time) error {
	if printCSVHeader {
		fmt.Print(CSVHeader)
		printCSVHeader = false
	}
	emitOutput("%s,%s,-,-,-,-", formatTimestamp(ts), t)
	return nil
}

func SetEmitOutputFormat(outputFmt EventOutputFormat) error {
	switch outputFmt {
	case EMIT_FMT_TEXT:
		EmitOutputFunc = outputEmittedIpcEventText
		EmitOutputLostFunc = outputLostIpcEventsText
	case EMIT_FMT_JSON:
		EmitOutputFunc = outputEmittedIpcEventJson
		EmitOutputLostFunc = outputLostIpcEventsJson
	case EMIT_FMT_CSV:
		printCSVHeader = true
		EmitOutputFunc = outputEmittedIpcEventCsv
		EmitOutputLostFunc = outputLostIpcEventsCsv
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

func SetEmitEventCountLimit(limit uint) error {
	if limit > 0 {
		limitEventCount = true
		eventCountLimit = limit
	}
	return nil
}

// no interspersed writing!
var mu sync.Mutex

func outputIpcEvent(event IpcEvent) error {
	mu.Lock()
	defer mu.Unlock()
	if limitEventCount {
		if eventCountLimit == 0 {
			os.Exit(1)
		}
		eventCountLimit--

	}
	return EmitOutputFunc(event)
}

func outputLostIpcEvents(eventType EmittedEventType, lost uint64, timestamp time.Time) error {
	mu.Lock()
	defer mu.Unlock()
	return EmitOutputLostFunc(eventType, lost, timestamp)
}
