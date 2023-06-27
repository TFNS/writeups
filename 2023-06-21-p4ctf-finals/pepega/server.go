package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/florianl/go-nflog"
	"github.com/ghedo/go.pkt/layers"
	"github.com/ghedo/go.pkt/packet"
	"github.com/ghedo/go.pkt/packet/ipv4"
	"github.com/ghedo/go.pkt/packet/tcp"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type PacketInfo struct {
	ArrivedAt time.Time

	FromIP   net.IP
	FromPort uint16

	ToIP   net.IP
	ToPort uint16
}

func GetPacketInfo(data []byte) (*PacketInfo, error) {
	netPacket, err := layers.UnpackAll(data, packet.IPv4)
	if err != nil {
		return nil, err
	}

	ipInfo, ok := netPacket.(*ipv4.Packet)
	if !ok {
		return nil, errors.New("not ip packet")
	}

	tcpInfo, ok := netPacket.Payload().(*tcp.Packet)
	if !ok {
		return nil, errors.New("not tcp packet")
	}

	return &PacketInfo{
		FromIP:   ipInfo.SrcAddr,
		FromPort: tcpInfo.SrcPort,
		ToIP:     ipInfo.DstAddr,
		ToPort:   tcpInfo.DstPort,
	}, nil
}

func GetPacketStream() (chan PacketInfo, error) {
	ctx, cancel := context.WithCancel(context.Background())
	config := nflog.Config{
		Group:    nflogGroup,
		Copymode: nflog.NfUlnlCopyPacket,
		Bufsize:  64,
		Logger:   log.New(os.Stderr, "nflog", log.LstdFlags),
	}

	nf, err := nflog.Open(&config)
	if err != nil {
		cancel()
		return nil, err
	}

	go func() {
		<-ctx.Done()
		nf.Close()
	}()
	packetStream := make(chan PacketInfo, 65000)

	funcHook := func(msg nflog.Msg) int {
		var packetData []byte
		if msg, exists := msg[nflog.AttrPayload]; exists {
			if msg, ok := msg.([]byte); ok {
				packetData = msg
			}
		}

		var packetTime time.Time
		if msg, exists := msg[nflog.AttrTimestamp]; exists {
			if msg, ok := msg.(time.Time); ok {
				packetTime = msg
			}
		}

		info, err := GetPacketInfo(packetData)
		if err != nil {
			log.Printf("invalid packet raw=%q", packetData)
			return 0
		}
		info.ArrivedAt = packetTime

		select {
		case packetStream <- *info:
		default:
			log.Fatalf("closed channel or overflow")
			cancel()
		}
		return 0
	}

	err = nf.Register(ctx, funcHook)
	if err != nil {
		cancel()
		return nil, err
	}

	return packetStream, nil
}

func workerFirewall() {
	packetStream, err := GetPacketStream()
	if err != nil {
		log.Fatal("packetStream err", err)
	}
	for pkt := range packetStream {
		if GlobalDB.Ban(pkt.FromIP.String(), time.Minute) {
			log.Printf("banning suspicious connection = %+v\n", pkt)
		}
	}
}

type localDB struct {
	mu     sync.RWMutex
	banned map[string]time.Time
}

func NewLocalDB() *localDB {
	return &localDB{
		banned: make(map[string]time.Time),
	}
}

func (c *localDB) Ban(remoteIP string, expireDuration time.Duration) bool {
	c.mu.Lock()
	c.banned[remoteIP] = time.Now().Add(expireDuration)
	c.mu.Unlock()
	return true
}

func (c *localDB) IsBanned(remoteIP string) bool {
	c.mu.RLock()
	expireAt, exists := c.banned[remoteIP]
	c.mu.RUnlock()
	if !exists {
		return false
	}
	if time.Since(expireAt).Seconds() > 0 {
		return false
	}
	return true
}

func setupNftables() {
	nftScript := `#!/usr/sbin/nft -f

	table inet chall_pepega_%interface% {}
	delete table inet chall_pepega_%interface%
	table inet chall_pepega_%interface% {
		chain input {
			type filter hook input priority 0; policy accept;
			iif "%interface%" tcp dport %port% log group %nfgroup%
		}
	}
	`
	nftScript = strings.ReplaceAll(nftScript, "%interface%", interfaceString)
	nftScript = strings.ReplaceAll(nftScript, "%port%", portString)
	nftScript = strings.ReplaceAll(nftScript, "%nfgroup%", strconv.Itoa(int(nflogGroup)))

	cmd := exec.Command("/usr/sbin/nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nftScript)

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Error executing nft script: err=%+v\nerror output:\n%s\n", err, output)
	}
}

func getInterfaceIP(interfaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP, nil
			}
		}
	}

	return nil, fmt.Errorf("no IP address found for interface %s", interfaceName)
}

func workerHttp() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Welcome to the 🐸packets!!! Now please get fast 🐸 flag!")
	})
	http.HandleFunc("/flag", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}
		remoteAddrStr, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error extracting remote address, ip=%s", r.RemoteAddr), http.StatusInternalServerError)
			return
		}
		remoteAddr := net.ParseIP(remoteAddrStr).To4()
		if len(remoteAddr) != 4 {
			http.Error(w, fmt.Sprintf("Error parsing remote address, ip=%s, ip=%s", r.RemoteAddr, remoteAddrStr), http.StatusInternalServerError)
			return
		}

		for i := 1; i <= 5; i++ {
			fmt.Fprintf(w, "Validating your request [%d/5], please wait 🐸🐸🐸\n", i)
			flusher.Flush()

			if GlobalDB.IsBanned(remoteAddr.String()) {
				fmt.Fprintln(w, "Sad 🐸 You are banned 😢")
				return
			}
			time.Sleep(time.Second)
		}

		fmt.Fprintf(w, "Here you go!!! 🐸 Flag: %s", flagString)
	})

	serverIP, err := getInterfaceIP(interfaceString)
	if err != nil {
		log.Fatal("getInterfaceIP err: ", err)
	}
	log.Printf("Listen on %s:%s\n", serverIP, portString)

	server := &http.Server{
		Addr:         serverIP.String() + ":" + portString,
		Handler:      http.DefaultServeMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal("Error creating listener: ", err)
	}
	rawListener, err := listener.(*net.TCPListener).File()
	if err != nil {
		log.Fatal("Error getting raw listener file: ", err)
	}
	if err := syscall.SetsockoptString(int(rawListener.Fd()), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, interfaceString); err != nil {
		log.Fatal("Error setting SO_BINDTODEVICE option: ", err)
	}
	if err := server.Serve(listener); err != nil {
		log.Fatal("server.ListenAndServe err: ", err)
	}
}

var GlobalDB *localDB
var flagString string
var portString string
var interfaceString string
var nflogGroup uint16

func main() {
	flagString = os.Getenv("FLAG")
	if len(flagString) == 0 {
		log.Fatal("flag is empty")
	}

	portString = os.Getenv("LISTEN_PORT")
	if len(portString) == 0 {
		portString = "8080"
	}

	interfaceString = os.Getenv("LISTEN_INTERFACE")
	if len(interfaceString) == 0 {
		interfaceString = "eth0"
	}

	nflogGroupStr := os.Getenv("NFLOG_GROUP")
	if len(nflogGroupStr) == 0 {
		nflogGroupStr = "100"
	}
	nflogGroup64, err := strconv.ParseUint(nflogGroupStr, 10, 16)
	if err != nil {
		log.Fatal("invalid nflog group")
	}
	nflogGroup = uint16(nflogGroup64)

	GlobalDB = NewLocalDB()

	setupNftables()

	go workerFirewall()
	workerHttp()
}
