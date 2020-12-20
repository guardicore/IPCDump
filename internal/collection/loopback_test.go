package collection

import (
    "testing"
    "fmt"
    "os"
    "strconv"
    "reflect"
    "net"
    "time"
    "syscall"
    "github.com/guardicode/ipcdump/internal/events"
    "github.com/guardicode/ipcdump/internal/bpf"
)

// TODO: rewrite this with unix.Syscalls. working around net.Conn is a pain

var MESSAGE_CONTENTS = []byte("SEND_ME_OVER_PLEASE! PLEASE PLEASE PLEASE RIGHT NOW WOULD BE GREAT. MESSAGE #")

type expectedLoopbackValues struct {
    Type events.EmittedEventType
    Inode uint64
    StartTime time.Time
    EndTime time.Time
    SrcPort uint16
    SrcServ string
    DstPort uint16
    DstServ string
    Contents []byte
}

func connProto(addr string) uint8 {
    switch addr {
    case "tcp":
        fallthrough
    case "tcp6":
        return syscall.IPPROTO_TCP

    case "udp":
        fallthrough
    case "udp6":
        return syscall.IPPROTO_UDP

    default:
        fmt.Fprintf(os.Stderr, "warning: unidentified protocol %s in connProto()\n", addr)
        return 0xff
    }
}

func connIpcType(conn net.Conn) events.EmittedEventType {
    n := conn.LocalAddr().Network()
    switch connProto(n) {
    case syscall.IPPROTO_TCP:
        return events.IPC_EVENT_LOOPBACK_SOCK_TCP

    case syscall.IPPROTO_UDP:
        return events.IPC_EVENT_LOOPBACK_SOCK_UDP

    default:
        fmt.Fprintf(os.Stderr, "warning: unidentified protocol %s in connIpcType()\n", n)
        return ""
    }
}

func checkLoopbackEvent(t *testing.T, e *events.IpcEvent, expected expectedLoopbackValues) {
    checkType(t, e, expected.Type)
    checkOwnIpc(t, e)
    checkTimestamp(t, e, expected.StartTime, expected.EndTime)

    checkMetadataUint64(t, e, "dst_inode", expected.Inode)
    checkMetadataUint16(t, e, "src_port", expected.SrcPort)
    checkMetadataString(t, e, "src_serv", expected.SrcServ)
    checkMetadataUint16(t, e, "dst_port", expected.DstPort)
    checkMetadataString(t, e, "dst_serv", expected.DstServ)
    checkContents(t, e, expected.Contents)
}

func getAddrIp(addr string) net.IP {
    h, _, _ := net.SplitHostPort(addr)
    return net.ParseIP(h)
}

func getAddrPort(addr string) uint16 {
    _, p, _ := net.SplitHostPort(addr)
    i, _ := strconv.Atoi(p)
    return uint16(i)
}

func getConnPort(conn net.Conn) uint16 {
    return getAddrPort(conn.LocalAddr().String())
}

func getServ(conn net.Conn) string {
    return servName(connProto(conn.LocalAddr().Network()), getConnPort(conn))
}

// adapted from https://github.com/higebu/netfd/blob/master/netfd.go
func getSockInode(c net.Conn) uint64 {
    v := reflect.ValueOf(c)
	netfd := reflect.Indirect(reflect.Indirect(v).FieldByName("fd"))
    pfd := netfd.FieldByName("pfd")
	fd := int(pfd.FieldByName("Sysfd").Int())
	return getFdInode(fd)
}

func runSocketsTest(t *testing.T, client, server net.Conn, serviceName string) {
    expected := expectedLoopbackValues{
        Inode: getSockInode(server),
        SrcPort: getConnPort(client),
        SrcServ: getServ(client),
        DstPort: getConnPort(server),
        DstServ: serviceName,
        Type: connIpcType(server),
    }
    for i := 0; i < 10; i++ {
        msg := append(MESSAGE_CONTENTS, byte(i))
        expected.Contents = msg
        e := captureEmit(t, "runSocketsTest()", func(*testing.T) {
            expected.StartTime = time.Now()
            client.Write(msg)

            buf := make([]byte, 1024)
            server.Read(buf)
        },
        1 * time.Second)
        expected.EndTime = time.Now()
        checkLoopbackEvent(t, e, expected)
    }
}

func clientServerPair(t *testing.T, network, addr string) (net.Conn, net.Conn) {
    var client net.Conn
    dialComplete := make(chan struct{})
    go func() {
        time.Sleep(500 * time.Millisecond)
        var err error
        client, err = net.Dial(network, addr)
        if err != nil {
            t.Fatalf("failed to dial: %v", err)
        }
        dialComplete<- struct{}{}
    }()

    var server net.Conn
    p := connProto(network)
    if p == syscall.IPPROTO_TCP {
        ln, err := net.Listen(network, addr)
        if err != nil {
            t.Fatalf("failed to create listener: %v", err)
        }
        defer ln.Close()
        server, err = ln.Accept()
        if err != nil {
            t.Fatalf("failed to accept: %v", err)
        }
    } else if p == syscall.IPPROTO_UDP {
        udpAddr := net.UDPAddr{
            Port: int(getAddrPort(addr)),
            IP: getAddrIp(addr),
        }
        var err error
        server, err = net.ListenUDP("udp", &udpAddr)
        if err != nil {
            t.Fatalf("failed to listen udp: %v", err)
        }
    }

    <-dialComplete
    return client, server
}

func TestCollectLoopbackIpcTcp(t *testing.T) {
    filterCurrentProcess()


    protoTests := []struct{
        Network string
        Addr string
        Serv string
        CollectTcp bool
        CollectUdp bool
    }{
        { "udp", "127.0.0.1:5555", "rplay", true, true },
        { "udp6", "[::1]:39393", "39393/udp", false, true },
        { "tcp6", "[::1]:5666", "nrpe", true, true },
        { "tcp", "localhost:14141", "14141/tcp", true, false },
    }

    for _, p := range protoTests {
        testName := fmt.Sprintf("%s-%s-%s", p.Network, p.Addr, p.Serv)
        t.Run(testName, func (t *testing.T) {

            preexistingClient, preexistingServer := clientServerPair(t, p.Network, p.Addr)

            bpfBuilder := bpf.NewBpfBuilder()

            SetupIpcBytesOutput(bpfBuilder, true, 0)
            SetupCommCollectionBpf(bpfBuilder)
            if err := SetupSockIdCollectionBpf(bpfBuilder); err != nil {
                t.Fatalf("SetupSockIdCollectionBpf failed: %v", err)
            }

            if err := InitLoopbackIpcCollection(bpfBuilder, p.CollectTcp, p.CollectUdp); err != nil {
                t.Fatalf("InitLoopbackIpcCollection() failed: %v", err)
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
                if err := CollectLoopbackIpc(mod, exit, commId, sockId); err != nil {
                    t.Errorf("CollectLoopbackIpc() failed: %v", err)
                }
                collectDone <- struct{}{}
            }()
            time.Sleep(1 * time.Second)

            t.Run("preexistingSocketsTest", func(t *testing.T) {
                runSocketsTest(t, preexistingClient, preexistingServer, p.Serv)
            })
            preexistingClient.Close()
            preexistingServer.Close()

            t.Run("newSocketsTest", func(t *testing.T) {
                newClient, newServer := clientServerPair(t, p.Network, p.Addr)
                runSocketsTest(t, newClient, newServer, p.Serv)
                newClient.Close()
                newServer.Close()
            })

            exit <- struct{}{}
            timeoutTest(t, "CollectLoopbackIpc()", func(*testing.T){ <-collectDone }, 1 * time.Second)
        })
    }
}
