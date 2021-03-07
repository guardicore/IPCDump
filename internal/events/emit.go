package events

import (
	"os"
	"time"
)

type IpcEndpoint struct {
	Pid  int64
	Comm string
}

type EmittedEventType string

const (
	IPC_EVENT_SIGNAL                    = "signal"
	IPC_EVENT_UNIX_SOCK_STREAM          = "unix-stream"
	IPC_EVENT_UNIX_SOCK_DGRAM           = "unix-dgram"
	IPC_EVENT_UNIX_SOCK_STREAM_OR_DGRAM = "unix-stream-or-dgram" // for lost events
	IPC_EVENT_PTY_WRITE                 = "pty"
	IPC_EVENT_LOOPBACK_SOCK_TCP         = "loopback-tcp"
	IPC_EVENT_LOOPBACK_SOCK_UDP         = "loopback-udp"
	IPC_EVENT_LOOPBACK_TCP_OR_UDP       = "loopback-tcp-or-udp" // for lost events
	IPC_EVENT_PIPE                      = "pipe"
)

type IpcMetadataPair struct {
	Name  string
	Value interface{}
}

type IpcMetadata []IpcMetadataPair
type IpcEvent struct {
	Src       IpcEndpoint
	Dst       IpcEndpoint
	Type      EmittedEventType
	Timestamp time.Time
	Metadata  IpcMetadata
	Bytes     []byte
}

var filteredSrcPids = make(map[uint64]struct{})
var filteredDstPids = make(map[uint64]struct{})
var filteredAnyPids = make(map[uint64]struct{})

var filteredSrcComms = make(map[string]struct{})
var filteredDstComms = make(map[string]struct{})
var filteredAnyComms = make(map[string]struct{})

func isFilteringBySrcPid() bool {
	return len(filteredSrcPids) > 0
}
func isFilteringByDstPid() bool {
	return len(filteredDstPids) > 0
}
func isFilteringByAnyPid() bool {
	return len(filteredAnyPids) > 0
}
func isSrcPidAllowed(pid int64) bool {
	if pid < 0 {
		return true
	}
	_, ok := filteredSrcPids[(uint64)(pid)]
	return ok
}
func isDstPidAllowed(pid int64) bool {
	if pid < 0 {
		return true
	}
	_, ok := filteredDstPids[(uint64)(pid)]
	return ok
}
func isAnyPidAllowed(pid int64) bool {
	_, ok := filteredAnyPids[(uint64)(pid)]
	return ok
}

func isFilteringBySrcComm() bool {
	return len(filteredSrcComms) > 0
}
func isFilteringByDstComm() bool {
	return len(filteredDstComms) > 0
}
func isFilteringByAnyComm() bool {
	return len(filteredAnyComms) > 0
}
func isSrcCommAllowed(comm string) bool {
	if len(comm) == 0 {
		return true
	}
	_, ok := filteredSrcComms[comm]
	return ok
}
func isDstCommAllowed(comm string) bool {
	if len(comm) == 0 {
		return true
	}
	_, ok := filteredDstComms[comm]
	return ok
}
func isAnyCommAllowed(comm string) bool {
	_, ok := filteredAnyComms[comm]
	return ok
}

func FilterBySrcPids(pids []uint64) {
	for _, pid := range pids {
		filteredSrcPids[pid] = struct{}{}
	}
}

func FilterByDstPids(pids []uint64) {
	for _, pid := range pids {
		filteredDstPids[pid] = struct{}{}
	}
}

func FilterByAnyPids(pids []uint64) {
	for _, pid := range pids {
		filteredAnyPids[pid] = struct{}{}
	}

}

func FilterBySrcComms(comms []string) {
	for _, comm := range comms {
		filteredSrcComms[comm] = struct{}{}
	}
}

func FilterByDstComms(comms []string) {
	for _, comm := range comms {
		filteredDstComms[comm] = struct{}{}
	}
}

func FilterByAnyComms(comms []string) {
	for _, comm := range comms {
		filteredAnyComms[comm] = struct{}{}
	}
}

func isPidCommAllowed(srcPid int64, dstPid int64, srcComm string, dstComm string) bool {
	filtering := false

	if isFilteringByAnyPid() {
		filtering = true
		if isAnyPidAllowed(srcPid) || isAnyPidAllowed(dstPid) {
			return true
		}
	}

	if isFilteringByDstPid() {
		filtering = true
		if isDstPidAllowed(dstPid) {
			return true
		}
	}

	if isFilteringBySrcPid() {
		filtering = true
		if isSrcPidAllowed(srcPid) {
			return true
		}
	}

	if isFilteringByAnyComm() {
		filtering = true
		if isAnyCommAllowed(srcComm) || isAnyCommAllowed(dstComm) {
			return true
		}
	}

	if isFilteringByDstComm() {
		filtering = true
		if isDstCommAllowed(dstComm) {
			return true
		}
	}

	if isFilteringBySrcComm() {
		filtering = true
		if isSrcCommAllowed(srcComm) {
			return true
		}
	}

	if !filtering {
		return true
	}

	return false
}

type IpcDataEmitter struct {
	skipLostEvents  bool
	limitEventCount bool
	eventCountLimit uint
}

func NewIpcDataEmitter(skipLostEvents bool, limitEventCount bool, eventCountLimit uint) IpcDataEmitter {
	return IpcDataEmitter{skipLostEvents, limitEventCount, eventCountLimit}
}

func (ipc_data_emitter *IpcDataEmitter) checkLimitEventCount() {
	if !ipc_data_emitter.limitEventCount {
		return
	}

	if ipc_data_emitter.eventCountLimit == 0 {
		os.Exit(1)
	}
	ipc_data_emitter.eventCountLimit--
}

func (ipc_data_emitter *IpcDataEmitter) EmitIpcEvent(event IpcEvent) error {
	if !isPidCommAllowed(event.Src.Pid, event.Dst.Pid, event.Src.Comm, event.Dst.Comm) {
		return nil
	}
	ipc_data_emitter.checkLimitEventCount()

	// we *could* filter by type here, too, but it's better to handle that at the hook-placement
	// level so that we don't get too lazy

	return outputIpcEvent(event)
}

func (ipc_data_emitter *IpcDataEmitter) EmitLostIpcEvents(eventType EmittedEventType, lost uint64) error {
	if ipc_data_emitter.skipLostEvents {
		return nil
	}

	ipc_data_emitter.checkLimitEventCount()

	return outputLostIpcEvents(eventType, lost, time.Now())
}
