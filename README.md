# ipcdump
ipcdump is a tool for tracing interprocess communication (IPC) on Linux. It covers most of the common IPC mechanisms -- pipes, fifos, signals, unix sockets, loopback-based networking, and pseudoterminals. It's a useful tool for debugging multi-process applications, and it's also a simple way to understand how the different moving parts in your system communicate with one another. ipcdump can trace both the metadata and the contents of this communication, and it's particularly well-suited to tracing IPC between short-lived processes, which can be difficult using traditional debugging tools, like strace or gdb. It also has some basic filtering capabilities to help you sift through large quantities of events.
Most of the information ipcdump collects comes from BPF hooks placed on kprobes and tracepoints at key functions in the kernel, although it also fills in some bookkeeping from the /proc filesystem. To this end ipcdump makes heavy use of [gobpf](https://github.com/iovisor/gobpf), which provides golang binding for the [bcc framework](https://github.com/iovisor/bcc).

Tested on Ubuntu 18.04 LTS running Linux 4.15.0.

## Building
```
git clone https://github.com/guardicode/ipcdump
cd ipcdump/cmd/ipcdump
go build
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
