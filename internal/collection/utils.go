package collection

import (
    "github.com/guardicode/ipcdump/internal/events"
)

func makeIpcEndpointI(commId *CommIdentifier, pid int64, comm [16]byte) events.IpcEndpoint {
    return events.IpcEndpoint{Pid: pid,
        Comm: commId.CommForPid(pid, comm)}
}

func makeIpcEndpoint(commId *CommIdentifier, pid uint64, comm [16]byte) events.IpcEndpoint {
    return makeIpcEndpointI(commId, (int64)(pid), comm)
}

