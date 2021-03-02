package collection

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"
	"unsafe"

	"github.com/guardicode/ipcdump/internal/bpf"
	"github.com/guardicode/ipcdump/internal/events"
	"golang.org/x/sys/unix"
)

var UNIX_MESSAGE_CONTENTS = []byte("IT IS TIME FOR YOU TO RECEIVE MESSAGE #")
var BIND_FILENAME = "i_wait_here"
var ABSTRACT_BIND_NAME = []byte("\x00i_shall_remain_nameless")

type UnixPair struct {
	SrcInode uint64
	Address  []byte
	SrcFd    int
	DstFd    int
	Proto    int
	New      bool
}

func getExpectedUnixAddress(addr []byte) string {
	if len(addr) == 0 {
		return "<anonymous>"
	}
	if addr[0] == 0 {
		return nullStr(append([]byte("@"), addr[1:]...))
	}
	return nullStr(addr)
}

func testUnixPair(t *testing.T, pair UnixPair) {
	for i := 0; i < 1; i++ {
		msg := append(UNIX_MESSAGE_CONTENTS, byte(i))
		startTime := time.Now()
		e := captureEmit(t, "runSocketsTest()", func(*testing.T) {
			if _, err := unix.Write(pair.SrcFd, msg); err != nil {
				t.Fatalf("failed to send msg: %v", err)
			}
			buf := make([]byte, 1024)
			_, _, err := unix.Recvfrom(pair.DstFd, buf, 0)
			if err != nil {
				t.Fatalf("failed to recv msg: %v", err)
			}
		},
			1*time.Second)
		endTime := time.Now()

		if pair.Proto == unix.SOCK_STREAM {
			checkType(t, e, events.IPC_EVENT_UNIX_SOCK_STREAM)
		} else {
			checkType(t, e, events.IPC_EVENT_UNIX_SOCK_DGRAM)
		}
		checkTimestamp(t, e, startTime, endTime)

		if pair.Proto == unix.SOCK_DGRAM {
			checkMetadataUint64(t, e, "src_inode", pair.SrcInode)
			// This is one of the few cases where we'll miss the source pid/comm for new processes.
			// For dgram unix sockets, we rely on the source inode to point us to the originating
			// process.
			// Our tests always pick up their own pid/comm using CommId (rather than the
			// get_pid_comm_for_sock() hook-based bookkeeping) because the test process is always
			// *already running* when the hooks are installed. Normally the SockId would catch this
			// case by mapping the inode to the owner process.
			// However, during the tests, the SockId *already exists as well* before the socket is
			// created. So this is basically the race case that squeezes in between.
			if pair.New {
				checkOwnDstIpc(t, e)
			} else {
				checkOwnIpc(t, e)
			}
		} else {
			checkOwnIpc(t, e)
		}
		addr := getExpectedUnixAddress(pair.Address)
		checkMetadataString(t, e, "path", addr)
		checkContents(t, e, msg)
	}
}

func makeUnixClientServerPair(t *testing.T, proto int, path []byte) UnixPair {
	listenFd, err := unix.Socket(unix.AF_UNIX, proto, 0)
	if err != nil {
		t.Fatalf("failed to create listen socket: %v", err)
	}

	if proto != unix.SOCK_DGRAM {
		defer unix.Close(listenFd)
	}

	var pathInts []int8
	for _, c := range path {
		pathInts = append(pathInts, int8(c))
	}
	var pathArr [108]int8
	copy(pathArr[:], pathInts[:])

	sa := unix.RawSockaddrUnix{Family: unix.AF_UNIX, Path: pathArr}
	_, _, errno := unix.Syscall(
		unix.SYS_BIND,
		uintptr(listenFd),
		uintptr(unsafe.Pointer(&sa)),
		uintptr(unsafe.Sizeof(sa)))

	if errno != 0 {
		t.Fatalf("failed to bind listen socket: %v", errno)
	}

	if proto != unix.SOCK_DGRAM {
		if err := unix.Listen(listenFd, 1); err != nil {
			t.Fatalf("failed to listen on listen socket: %v", err)
		}
	}

	clientFd, err := unix.Socket(unix.AF_UNIX, proto, 0)
	if err != nil {
		t.Fatalf("failed to create client socket: %v", err)
	}

	connectComplete := make(chan struct{})
	go func() {
		time.Sleep(500 * time.Millisecond)
		_, _, errno := unix.Syscall(
			unix.SYS_CONNECT,
			uintptr(clientFd),
			uintptr(unsafe.Pointer(&sa)),
			uintptr(unsafe.Sizeof(sa)))

		if errno != 0 {
			unix.Close(clientFd)
			t.Fatalf("failed to connect client socket: %v", errno)
		}
		connectComplete <- struct{}{}
	}()

	serverFd := -1
	if proto == unix.SOCK_DGRAM {
		serverFd = listenFd
	} else {
		serverFd, _, err = unix.Accept(listenFd)
	}
	<-connectComplete
	if err != nil {
		unix.Close(clientFd)
		t.Fatalf("failed to accept connection on listen socket: %v", err)
	}

	return UnixPair{
		SrcInode: getFdInode(clientFd),
		Address:  path,
		SrcFd:    clientFd,
		DstFd:    serverFd,
		Proto:    proto,
	}
}

func makeSocketPair(t *testing.T, proto int) UnixPair {
	fds, err := unix.Socketpair(unix.AF_UNIX, proto, 0)
	if err != nil {
		t.Fatalf("failed to create socketpair: %v", err)
	}
	return UnixPair{
		SrcInode: getFdInode(fds[0]),
		Address:  []byte{},
		SrcFd:    fds[0],
		DstFd:    fds[1],
		Proto:    proto,
	}
}

func ClosePair(pair UnixPair) {
	unix.Close(pair.SrcFd)
	unix.Close(pair.DstFd)
}

func TestCollectUnixSockIpc(t *testing.T) {
	filterCurrentProcess()

	protocols := []struct {
		Name  string
		Proto int
	}{
		{"stream", unix.SOCK_STREAM},
		{"dgram", unix.SOCK_DGRAM},
	}

	for _, proto := range protocols {
		t.Run(proto.Name, func(t *testing.T) {
			preexistingNamedPair := makeUnixClientServerPair(t, proto.Proto, []byte(path.Join(t.TempDir(), BIND_FILENAME)))
			preexistingNamedPair.New = false
			preexistingAbstractPair := makeUnixClientServerPair(t, proto.Proto, ABSTRACT_BIND_NAME)
			preexistingAbstractPair.New = false
			preexistingAnonymousPair := makeSocketPair(t, proto.Proto)
			preexistingAnonymousPair.New = false

			bpfBuilder := bpf.NewBpfBuilder()
			SetupIpcBytesOutput(bpfBuilder, true, 0)
			SetupCommCollectionBpf(bpfBuilder)
			if err := SetupSockIdCollectionBpf(bpfBuilder); err != nil {
				t.Fatalf("SetupSockIdCollectionBpf failed: %v", err)
			}

			if err := InitUnixSocketIpcCollection(bpfBuilder, true, true); err != nil {
				t.Fatalf("InitUnixSocketIpcCollection() failed: %v", err)
			}

			mod, err := bpfBuilder.LoadModule()
			defer mod.Close()
			if err != nil {
				t.Fatalf("LoadModule() failed: %v", err)
			}

			commId, err := NewCommIdentifier(mod)
			if err != nil {
				t.Fatalf("NewCommIdentifier() failed: %v", err)
			}

			sockId, err := NewSocketIdentifier(mod)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create a socket identifier: %v\n", err)
				os.Exit(1)
			}

			exit := make(chan struct{})
			collectDone := make(chan struct{})
			go func() {
				if err := CollectUnixSocketIpc(mod, exit, commId, sockId); err != nil {
					t.Errorf("CollectUnixSocketIpc() failed: %v", err)
				}
				collectDone <- struct{}{}
			}()
			time.Sleep(1 * time.Second)

			t.Run("preexisting", func(t *testing.T) {
				t.Run("named", func(t *testing.T) {
					testUnixPair(t, preexistingNamedPair)
				})
				t.Run("abstract", func(t *testing.T) {
					testUnixPair(t, preexistingAbstractPair)
				})
				t.Run("anonymous", func(t *testing.T) {
					testUnixPair(t, preexistingAnonymousPair)
				})

				ClosePair(preexistingNamedPair)
				ClosePair(preexistingAbstractPair)
				ClosePair(preexistingAnonymousPair)
			})

			t.Run("new", func(t *testing.T) {
				newNamedPair := makeUnixClientServerPair(t, proto.Proto, []byte(path.Join(t.TempDir(), BIND_FILENAME)))
				newNamedPair.New = true
				newAbstractPair := makeUnixClientServerPair(t, proto.Proto, ABSTRACT_BIND_NAME)
				newAbstractPair.New = true
				newAnonymousPair := makeSocketPair(t, proto.Proto)
				newAnonymousPair.New = true

				t.Run("named", func(t *testing.T) {
					testUnixPair(t, newNamedPair)
				})
				t.Run("abstract", func(t *testing.T) {
					testUnixPair(t, newAbstractPair)
				})
				t.Run("anonymous", func(t *testing.T) {
					testUnixPair(t, newAnonymousPair)
				})

				ClosePair(newNamedPair)
				ClosePair(newAbstractPair)
				ClosePair(newAnonymousPair)
			})

			exit <- struct{}{}
			timeoutTest(t, "CollectUnixSocketIpc()", func(*testing.T) { <-collectDone }, 1*time.Second)
		})
	}
}
