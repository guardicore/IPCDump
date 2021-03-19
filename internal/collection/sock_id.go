package collection

import (
	"fmt"

	"github.com/guardicore/ipcdump/internal/bpf"
)

// Lots of hooks here, but they all do pretty much the same thing: any time someone creates a new
// struct sock*, or manipulates an existing one, we mark them as the last user of that socket and
// store their pid/comm for whoever needs them later.
// The cleanup is done in probe_sk_destruct().

var sockIdIncludes = `
#include <linux/net.h>
`

var sockIdSource = `
struct pid_comm_tuple {
    u64 pid;
    char comm[16];
};
BPF_HASH(sock_pid_map, struct sock*, struct pid_comm_tuple);

static inline void map_sock_to_current(struct sock *sk) __attribute__((always_inline));
static inline void map_sock_to_current(struct sock *sk) {
    struct pid_comm_tuple p = {0};
    p.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(p.comm, sizeof(p.comm));

    sock_pid_map.update(&sk, &p);
}

static inline int clone_sock_tuple(struct sock *new, struct sock *orig) __attribute__((always_inline));
static inline int clone_sock_tuple(struct sock *new, struct sock *orig) {
    struct pid_comm_tuple *res = sock_pid_map.lookup(&orig);
    if (!res) {
        bpf_trace_printk("warning: failed to find sock pid/comm in clone_sock_tuple()\n");
        return -1;
    }
    struct pid_comm_tuple res_copy = {0};
    if (bpf_probe_read(&res_copy, sizeof(res_copy), res)) {
        bpf_trace_printk("warning: failed to find copy pid/comm tuple in clone_sock_tuple()\n");
        return -1;
    }
    sock_pid_map.update(&new, &res_copy);
    return 0;
}

static inline void map_socket_to_current(struct socket *sk) __attribute__((always_inline));
static inline void map_socket_to_current(struct socket *sk) {
    struct socket copy;
    if (bpf_probe_read(&copy, sizeof(copy), sk)) {
        bpf_trace_printk("warning: failed to copy socket in map_sock_to_current()\n");
        return;
    }

    if (copy.sk == NULL) {
        bpf_trace_printk("warning: socket %llx had null sock in map_sock_to_current()\n", (unsigned long long)sk);
        return;
    }

    map_sock_to_current(copy.sk);
}

int retprobe_sockfd_lookupX(struct pt_regs *ctx) {

    struct socket *sock = (struct socket*)PT_REGS_RC(ctx);
    if (sock) {
        map_socket_to_current(sock);
    }
    return 0;
}

int retprobe_inet_csk_accept(struct pt_regs *ctx,
                             struct sock *sk, 
                             int flags, 
                             int *err, 
                             bool kern) {
    struct sock *newsock = (struct sock*)PT_REGS_RC(ctx);
    if (!kern && newsock) {
        map_sock_to_current(newsock);
    }
    return 0;
}

BPF_HASH(sk_clones_by_pid_arr, u64, struct sock*);

int probe_sk_clone_lock(struct pt_regs *ctx,
                           struct sock *sk,
                           gfp_t priority) {
    u64 key = bpf_get_current_pid_tgid();
    sk_clones_by_pid_arr.update(&key, &sk);
    return 0;
}

int retprobe_sk_clone_lock(struct pt_regs *ctx) {
    u64 key = bpf_get_current_pid_tgid();
    struct sock **orig = sk_clones_by_pid_arr.lookup(&key);
    if (!orig) {
        bpf_trace_printk("warning: failed to get original socket in retprobe_sk_clone_lock()\n");
        return 0;
    }
    struct sock *clone = (struct sock*)PT_REGS_RC(ctx);
    if (clone != NULL) {
        clone_sock_tuple(clone, *orig);
    }
    sk_clones_by_pid_arr.delete(&key);
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
        return -1;
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
        return -1;
    }
    
    if (s == NULL) {
        *pid = 0;
        return -1;
    }

    return get_pid_comm_for_sock(pid, comm, len, s);
}

`

type inodeProcessInfo struct {
	Fd               uint64
	Pid              uint64
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

	kprobe, err := module.LoadKprobe("probe_sk_destruct")
	if err != nil {
		return err
	}
	if err := module.AttachKprobe("sk_destruct", kprobe, -1); err != nil {
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

	kprobe, err = module.LoadKprobe("retprobe_inet_csk_accept")
	if err != nil {
		return err
	}
	if err := module.AttachKretprobe("inet_csk_accept", kprobe, -1); err != nil {
		return err
	}

	kprobe, err = module.LoadKprobe("retprobe_sk_clone_lock")
	if err != nil {
		return err
	}
	if err := module.AttachKretprobe("sk_clone_lock", kprobe, -1); err != nil {
		return err
	}

	kprobe, err = module.LoadKprobe("probe_sk_clone_lock")
	if err != nil {
		return err
	}
	if err := module.AttachKprobe("sk_clone_lock", kprobe, -1); err != nil {
		return err
	}

	return nil
}

func NewSocketIdentifier(bpfMod *bpf.BpfModule) (*SocketIdentifier, error) {
	if err := installSockIdHooks(bpfMod); err != nil {
		return nil, err
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
	if !ok {
		return 0, false
	}
	return info.Pid, true
}
