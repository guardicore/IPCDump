package events

import (
    "time"
)

type IpcEndpoint struct {
    Pid int64
    Comm string
}

type EmittedEventType string

const (
    IPC_EVENT_SIGNAL = "signal"
    IPC_EVENT_UNIX_SOCK_STREAM = "unix-stream"
    IPC_EVENT_UNIX_SOCK_DGRAM = "unix-dgram"
    IPC_EVENT_PTY_WRITE = "pty"
    IPC_EVENT_LOOPBACK_SOCK_TCP = "loopback-tcp"
    IPC_EVENT_LOOPBACK_SOCK_UDP = "loopback-udp"
    IPC_EVENT_PIPE = "pipe"
)

type IpcMetadataPair struct {
    Name string
    Value string
}

type IpcMetadata []IpcMetadataPair
type IpcEvent struct {
    Src IpcEndpoint
    Dst IpcEndpoint
    Type EmittedEventType
    Timestamp time.Time
    Metadata IpcMetadata
    Bytes []byte
}

var filteredSrcPids = make(map[uint64]struct{})
var filteredDstPids = make(map[uint64]struct{})
var filteredAnyPids = make(map[uint64]struct{})

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

func isPidAllowed(srcPid int64, dstPid int64) bool {
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

    if !filtering {
        return true
    }

    return false
}

func EmitIpcEvent(event IpcEvent) error {
    if !isPidAllowed(event.Src.Pid, event.Dst.Pid) {
        return nil
    }

    // we *could* filter by type here, too, but it's better to handle that at the hook-placement
    // level so that we don't get too lazy

    return outputIpcEvent(event)
}
