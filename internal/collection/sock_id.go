package collection

import (
    "fmt"
    "github.com/guardicode/ipcdump/internal/bpf"
)

var sockIdIncludes = `
#include <linux/net.h>
`

var sockIdSource = `
BPF_HASH(sock_pid_map, struct socket*, u64);

int retprobe_sockfd_lookupX(struct pt_regs *ctx) {

    struct socket *sock = (struct socket*)PT_REGS_RC(ctx);
    if (sock) {
        u64 pid = bpf_get_current_pid_tgid() >> 32;
        sock_pid_map.update(&sock, &pid);
    }
    return 0;
}

int probe___sock_release(struct pt_regs *ctx,
                       struct socket *sk) {
    sock_pid_map.delete(&sk);
    return 0;
}


int probe_sk_destruct(struct pt_regs *ctx,
                      struct sock *sk) {
    sock_pid_map.delete(&sk);
    return 0;
}

static inline int get_pid_comm_for_sock(u64 *pid, char *comm, size_t len, struct sock *sk) __attribute__((always_inline));
static inline int get_pid_comm_for_sock(u64 *pid, char *comm, size_t len, struct sock *sk) {
    struct pid_comm_tuple *res = sock_pid_map.lookup(&sk);
    if (!res) {
        *pid = 0;
        return 0;
    }

    *pid = res->pid;
    bpf_probe_read(comm, len, res->comm);
    return 0;
}

static inline int get_pid_comm_for_socket(u64 *pid, char *comm, size_t len, struct socket *sk) __attribute__((always_inline));
static inline int get_pid_comm_for_socket(u64 *pid, char *comm, size_t len, struct socket *sk) {
    struct sock *s = NULL;
    if (bpf_probe_read(&s, sizeof(s), &sk->sk)) {
        *pid = 0;
        return 0;
    }

    return get_pid_comm_for_sock(pid, comm, len, s);
}
`

type inodeProcessInfo struct {
    Fd uint64
    Pid uint64
    ProcessStartTime uint64
}

type SocketIdentifier struct {
    inodeInfoMap map[uint64]inodeProcessInfo
}

func SetupSockIdCollectionBpf(bpfBuilder *bpf.BpfBuilder) error {
    if err := bpfBuilder.AddIncludes(sockIdIncludes); err != nil {
        return err
    }
    bpfBuilder.AddSources(sockIdSource)
    return nil
}

func installSockIdHooks(bpfMod *bpf.BpfModule) error {
    module := bpfMod.Get()
    defer bpfMod.Put()

    kprobe, err := module.LoadKprobe("probe___sock_release")
    if err != nil {
        return err
    }
    if err := module.AttachKprobe("__sock_release", kprobe, -1); err != nil {
        return err
    }

    kprobe, err = module.LoadKprobe("retprobe_sockfd_lookupX")
    if err != nil {
        return err
    }
    if err := module.AttachKretprobe("sockfd_lookup", kprobe, -1); err != nil {
        return err
    }
    if err := module.AttachKretprobe("sockfd_lookup_light", kprobe, -1); err != nil {
        return err
    }

    return nil
}

var sockIdHooksInstalled = false

func NewSocketIdentifier(bpfMod *bpf.BpfModule) (*SocketIdentifier, error) {
    if !sockIdHooksInstalled {
        if err := installSockIdHooks(bpfMod); err != nil {
            return nil, err
        }
        sockIdHooksInstalled = true
    }

    var s SocketIdentifier
    var err error
    s.inodeInfoMap, err = ScanProcessSocketInodes()
    if err != nil {
        return nil, fmt.Errorf("failed initial scan for process socket inodes: %w", err)
    }

    return &s, nil
}

func (s SocketIdentifier) GuessMissingSockPidFromUsermode(inode uint64) (uint64, bool) {
    info, ok := s.inodeInfoMap[inode]
    if (!ok) {
        return 0, false
    }
    return info.Pid, true
}

