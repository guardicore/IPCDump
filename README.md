# ipcdump

[Announcement post](https://www.guardicore.com/labs/ipcdump-guardicores-new-open-source-tool-for-linux-ipc-inspection/)

ipcdump is a tool for tracing interprocess communication (IPC) on Linux. It covers most of the common IPC mechanisms -- pipes, fifos, signals, unix sockets, loopback-based networking, and pseudoterminals. It's a useful tool for debugging multi-process applications, and it's also a simple way to understand how the different moving parts in your system communicate with one another. ipcdump can trace both the metadata and the contents of this communication, and it's particularly well-suited to tracing IPC between short-lived processes, which can be difficult using traditional debugging tools, like strace or gdb. It also has some basic filtering capabilities to help you sift through large quantities of events.
Most of the information ipcdump collects comes from BPF hooks placed on kprobes and tracepoints at key functions in the kernel, although it also fills in some bookkeeping from the /proc filesystem. To this end ipcdump makes heavy use of [gobpf](https://github.com/iovisor/gobpf), which provides golang binding for the [bcc framework](https://github.com/iovisor/bcc).

# Requirements & Usage

* golang >= 1.15.6
### Tested operating systems and kernels
|          |  Ubuntu 18.04 LTS  |  Ubuntu 20.04 LTS  |
|:--------:|:------------------:|:------------------:|
|  4.15.0  |       Tested       |     Not Tested     |
|  5.4.0   |     Not Tested     |       Tested       |
|  5.8.0   |     Not Tested     |       Tested*      |

*Requires building bcc from source
## Building
### Dependencies
1. Install golang
```
snap install go --classic
```
or
directly from [golang website](https://golang.org/dl/)

2. Install BCC using iovisor's [instructions](https://github.com/iovisor/bcc/blob/master/INSTALL.md) depending on the operation system you chose (usually the newer versions will require building from source)

### Building ipcdump
```
git clone https://github.com/guardicore/IPCDump
cd IPCDump/cmd/ipcdump
go build
```

## Usage
```
./ipcdump -h
Usage of ./ipcdump:
  -B uint
        max number of bytes to dump per event, or 0 for complete event (may be large). meaningful only if -x is specified.
  -D value
        filter by destination comm (can be specified more than once)
  -L    do not output lost event information
  -P value
        filter by comm (either source or destination, can be specified more than once)
  -S value
        filter by source comm (can be specified more than once)
  -c uint
        exit after <count> events
  -d value
        filter by destination pid (can be specified more than once)
  -f string
        <text|json> output format (default is text) (default "text")
  -p value
        filter by pid (either source or destination, can be specified more than once)
  -s value
        filter by source pid (can be specified more than once)
  -t value
        filter by type (can be specified more than once).
        possible values: a|all  k|signal  u|unix  ud|unix-dgram  us|unix-stream  t|pty  lo|loopback  lt|loopback-tcp  lu|loopback-udp  p|pipe
  -x    dump IPC bytes where relevant (rather than just event details).
```

## One-liners
Run as root:
```
# dump all ipc on the system
./ipcdump

# dump signals sent between any two processes
./ipcdump -t kill

# dump loopback TCP connection metadata to or from pid 1337
./ipcdump -t loopback-tcp -p 1337

# dump unix socket IPC metadata and contents from Xorg
./ipcdump -t unix -x -S Xorg

# dump json-formatted pipe i/o metadata and first 64 bytes of contents
./ipcdump -t pipe -x -B 64 -f json
```

## Features
- Support for pipes and FIFOs
- Loopback IPC
- Signals (regular and realtime)
- Unix streams and datagrams
- Pseudoterminal-based IPC
- Event filtering based on process PID or name
- Human-friendly or JSON-formatted output

## Design
ipcdump is built of a series of collectors, each of which is in charge of a particular type of IPC event. For example, `IPC_EVENT_LOOPBACK_SOCK_UDP` or `IPC_EVENT_SIGNAL`.

In practice, all of the collectors are built using bpf hooks attached to kprobes and tracepoints. Their implementations are entirely separate, though -- there's no particular reason to assume our information will always come from bpf. That said, the different collectors do have to share a single bpf module, because there's some common code that they need to share. To this end, we share a single BpfBuilder (which is essentially a wrapper around concatenating strings of bcc code) and each collector registers its own code with that builder. The full bcc script is then loaded with gobpf, and each module places the hooks it needs.

There are currently two kinds of bookkeeping that are shared between IPC collectors:
- `SocketIdentifier (internal/collection/sock_id.go)` -- maps between kernel `struct sock*` and the processes that use them.
- `CommIdentifier (internal/collection/comm_id.go)` -- maps between pid numbers and the corresponding process name (`/proc/<pid>/comm`).
The bookkeeping done in each of these is particularly important for short-lived processes; while this information can be filled out later in usermode by parsing `/proc`, often the relevant process will have disappeared by the time the event hits the handler. That said, we do sometimes fill in information from `/proc`. This happens mostly for processes that existed before ipcdump was run; we won't catch events like process naming in this case. `SocketIdentifier` and `CommIdentifier` sort of try and abstract this duality between bcc code and `/proc` parsing behind a single API, although it's not super-clean. By the way, in super-new versions of Linux (5.8), bpf iterators can entirely replace this bookkeeping, although for backwards compatibility we should probably stick to the hooks-and-procfs paradigm for now.

Event output is done through the common `EmitIpcEvent()` function, which takes a standard event format (source process, dest process, metadata key-value pairs, and contents) and outputs it in a unified format.  To save event bandwidth, collectors typically don't output IPC contents if the `-x` flag isn't specified. This is done with some fancy preprocessing magic in `internal/collection/ipc_bytes.go`.

## Contributing
Please do! Check out TODO for the really important stuff. Most of the early work on ipcdump will probably involve making adjustments for different kernel versions and symbols.
