package collection

import (
	"fmt"

	"github.com/guardicore/ipcdump/internal/bpf"
	"github.com/guardicore/ipcdump/internal/events"
)

const commSource = `
struct __attribute__((packed)) sched_process_free_args_t {
    u16 common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    u32 common_pid;

    char comm[16];
    u32 pid;
    u32 prio;
};

struct __attribute__((packed)) task_rename_args_t {
    u16 common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    u32 common_pid;

    u32 pid;
    char oldcomm[16];
    char newcomm[16];
    u16 oom_score_adj;
};

struct __attribute__((packed)) task_newtask_args_t {
    u16 common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    u32 common_pid;

    u32 pid;
    char comm[16];
    u64 clone_flags;
    u16 oom_score_adj;
};

struct pid_info_t {
    char comm[16];
};

BPF_HASH(pid_comm_map, u64, struct pid_info_t);

int trace_sched_process_free(struct sched_process_free_args_t *args) {
    u64 pid = (u64)args->pid;
    pid_comm_map.delete(&pid);
    return 0;
}

int trace_task_rename(struct task_rename_args_t *args) {
    struct pid_info_t info = {0};
    if (bpf_probe_read(info.comm, sizeof(info.comm), args->newcomm)) {
        return 0;
    }
    u64 pid = (u64)args->pid;
    pid_comm_map.update(&pid, &info);
    return 0;
}

int trace_task_newtask(struct task_newtask_args_t *args) {
    struct pid_info_t info = {0};
    if (bpf_probe_read(info.comm, sizeof(info.comm), args->comm)) {
        return 0;
    }
    u64 pid = (u64)args->pid;
    pid_comm_map.update(&pid, &info);
    return 0;
}

static inline int get_comm_for_pid(u64 pid, char *comm, size_t len) __attribute__((always_inline));
static inline int get_comm_for_pid(u64 pid, char *comm, size_t len) {
    struct pid_info_t *info = pid_comm_map.lookup(&pid);
    if (!info) {
        return -1;
    }
    return bpf_probe_read_str(comm, len, info->comm);
}
`

type CommIdentifier struct {
	pidCommMap map[uint64]string
}

func SetupCommCollectionBpf(bpfBuilder *bpf.BpfBuilder) error {
	bpfBuilder.AddSources(commSource)
	return nil
}

func installCommIdHooks(bpfMod *bpf.BpfModule) error {
	module := bpfMod.Get()
	defer bpfMod.Put()

	// we use process_free rather than process_exit because it happens later, and we sometimes
	// miss very quickly spawning-and-dying processes
	tracepoint, err := module.LoadTracepoint("trace_sched_process_free")
	if err != nil {
		return err
	}
	if err = module.AttachTracepoint("sched:sched_process_free", tracepoint); err != nil {
		return err
	}

	tracepoint, err = module.LoadTracepoint("trace_task_rename")
	if err != nil {
		return err
	}
	if err = module.AttachTracepoint("task:task_rename", tracepoint); err != nil {
		return err
	}

	tracepoint, err = module.LoadTracepoint("trace_task_newtask")
	if err != nil {
		return err
	}
	if err = module.AttachTracepoint("task:task_newtask", tracepoint); err != nil {
		return err
	}

	return nil
}

var commIdHooksInstalled = false

func NewCommIdentifier(bpfMod *bpf.BpfModule) (*CommIdentifier, error) {
	if !commIdHooksInstalled {
		if err := installCommIdHooks(bpfMod); err != nil {
			return nil, err
		}
		commIdHooksInstalled = true
	}

	var c CommIdentifier
	var err error
	c.pidCommMap, err = ScanProcessComms()
	if err != nil {
		return nil, fmt.Errorf("failed initial scan for process comms: %w", err)
	}

	return &c, nil
}

func (c CommIdentifier) CommForPid(pid int64, comm [16]byte) string {
	str := commStr(comm)
	if len(str) != 0 {
		return str
	}

	if pid < 0 {
		return "<unknown>"
	}

	scannedComm, ok := c.pidCommMap[(uint64)(pid)]
	if !ok {
		return "<unknown>"
	}

	return scannedComm
}

func makeIpcEndpointI(commId *CommIdentifier, pid int64, comm [16]byte) events.IpcEndpoint {
	return events.IpcEndpoint{Pid: pid,
		Comm: commId.CommForPid(pid, comm)}
}

func makeIpcEndpoint(commId *CommIdentifier, pid uint64, comm [16]byte) events.IpcEndpoint {
	return makeIpcEndpointI(commId, (int64)(pid), comm)
}
