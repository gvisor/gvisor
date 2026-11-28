// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package container

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/netproxy/hello"
	pb "gvisor.dev/gvisor/pkg/netproxy/hello/hello_go_proto"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/sandbox"
)

const (
	peerNIC     = tcpip.NICID(1)
	peerTCPPort = 8080
	peerWait    = time.Minute
)

// peerConfig returns a Config for a dual-stack link with addresses ip4/24 and
// ip6/64, default routes through .1 and ::1 of those subnets, and a route to
// 198.51.100.0/24 through the IPv4 gateway.
func peerConfig(ip4, ip6 string) *pb.Config {
	a4, a6 := netip.MustParseAddr(ip4), netip.MustParseAddr(ip6)
	route := func(dst, gw string) *pb.Route {
		p := netip.MustParsePrefix(dst)
		r := &pb.Route{Dst: p.Addr().AsSlice(), DstPrefixLen: uint32(p.Bits())}
		if gw != "" {
			r.Gateway = netip.MustParseAddr(gw).AsSlice()
		}
		return r
	}
	return &pb.Config{
		Mtu: 1400,
		Addresses: []*pb.Address{
			{Ip: a4.AsSlice(), PrefixLen: 24},
			{Ip: a6.AsSlice(), PrefixLen: 64},
		},
		Routes: []*pb.Route{
			route("192.0.2.0/24", ""),
			route("0.0.0.0/0", "192.0.2.1"),
			route("198.51.100.0/24", "192.0.2.1"),
			route("2001:db8::/64", ""),
			route("::/0", "2001:db8::1"),
		},
	}
}

// helloPeer is a network proxy peer on a SOCK_SEQPACKET socket. For the i-th
// connection it receives the Offer, answers with configs[i], and once runsc
// acks, forwards the link's packets to a netstack. The netstack accepts TCP
// connections to any address on peerTCPPort, reads a line, and answers with
// "pong <source> <destination>" as it saw them.
type helloPeer struct {
	path string
	// conns receives the result of each connection, in order.
	conns chan peerConn
}

// peerConn is the result of one connection to a helloPeer.
type peerConn struct {
	// offer is the Offer that runsc sent, if any.
	offer *pb.Offer
	// err is nil once the link's packets are forwarded, or why the hello or
	// the forwarding failed.
	err error
}

// newHelloPeer starts a peer listening on a new socket.
func newHelloPeer(t *testing.T, configs ...*pb.Config) *helloPeer {
	t.Helper()
	dir, err := os.MkdirTemp(testutil.TmpDir(), "peer")
	if err != nil {
		t.Fatalf("os.MkdirTemp() failed: %v", err)
	}
	path := filepath.Join(dir, "peer.sock")
	if len(path) >= len(unix.RawSockaddrUnix{}.Path) {
		os.RemoveAll(dir)
		if dir, err = os.MkdirTemp("/tmp", "peer"); err != nil {
			t.Fatalf("os.MkdirTemp() failed: %v", err)
		}
		path = filepath.Join(dir, "peer.sock")
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatalf("net.ListenUnix(%q) failed: %v", path, err)
	}
	p := &helloPeer{
		path:  path,
		conns: make(chan peerConn, len(configs)),
	}
	done := make(chan struct{})
	var links []*peerLink
	t.Cleanup(func() {
		ln.Close()
		<-done
		for _, l := range links {
			l.close()
		}
	})
	go func() {
		defer close(done)
		for _, cfg := range configs {
			conn, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			offer, l, err := serveHello(conn, cfg)
			conn.Close()
			if l != nil {
				links = append(links, l)
			}
			p.conns <- peerConn{offer: offer, err: err}
		}
	}()
	return p
}

// peerLink is a netstack and the file whose FD its link endpoint uses. The
// endpoint doesn't own the FD, so the file must stay open until the netstack
// is destroyed.
type peerLink struct {
	stack *stack.Stack
	file  *os.File
}

// close destroys the netstack, then closes the file.
func (l *peerLink) close() {
	l.stack.Destroy()
	l.file.Close()
}

// serveHello runs the hello on conn, answering with cfg, and returns the
// Offer and the link whose packets are forwarded to a netstack.
func serveHello(conn *net.UnixConn, cfg *pb.Config) (*pb.Offer, *peerLink, error) {
	offer, err := exchangeHello(conn, cfg)
	if err != nil {
		return offer, nil, err
	}
	l, err := forward(conn, cfg.GetMtu())
	return offer, l, err
}

// exchangeHello answers the Offer on conn with cfg and waits for the Ack.
func exchangeHello(conn *net.UnixConn, cfg *pb.Config) (*pb.Offer, error) {
	if err := conn.SetDeadline(time.Now().Add(peerWait)); err != nil {
		return nil, err
	}
	buf := make([]byte, hello.MaxMessageSize+1)
	recv := func(want hello.Type) (hello.Header, any, error) {
		n, err := conn.Read(buf)
		if err != nil {
			return hello.Header{}, nil, fmt.Errorf("reading %v: %w", want, err)
		}
		h, msg, err := hello.Unmarshal(buf[:n])
		if err != nil {
			return h, nil, fmt.Errorf("decoding %v: %w", want, err)
		}
		if h.Type != want {
			return h, nil, fmt.Errorf("got %v %v, want %v", h.Type, msg, want)
		}
		return h, msg, nil
	}
	h, msg, err := recv(hello.TypeOffer)
	if err != nil {
		return nil, err
	}
	offer := msg.(*pb.Offer)
	b, err := hello.Marshal(hello.Header{Type: hello.TypeConfig, Major: hello.Major, XID: h.XID}, cfg)
	if err != nil {
		return offer, err
	}
	if _, err := conn.Write(b); err != nil {
		return offer, fmt.Errorf("sending Config: %w", err)
	}
	if _, _, err := recv(hello.TypeAck); err != nil {
		return offer, err
	}
	return offer, conn.SetDeadline(time.Time{})
}

// forward returns a link whose packets on conn are forwarded to a netstack.
func forward(conn *net.UnixConn, mtu uint32) (*peerLink, error) {
	f, err := conn.File()
	if err != nil {
		return nil, err
	}
	ep, err := fdbased.New(&fdbased.Options{FDs: []int{int(f.Fd())}, MTU: mtu})
	if err != nil {
		f.Close()
		return nil, err
	}
	l := &peerLink{
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		}),
		file: f,
	}
	s := l.stack
	if err := s.CreateNIC(peerNIC, ep); err != nil {
		l.close()
		return nil, fmt.Errorf("CreateNIC: %v", err)
	}
	if err := s.SetPromiscuousMode(peerNIC, true); err != nil {
		l.close()
		return nil, fmt.Errorf("SetPromiscuousMode: %v", err)
	}
	if err := s.SetSpoofing(peerNIC, true); err != nil {
		l.close()
		return nil, fmt.Errorf("SetSpoofing: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: peerNIC},
		{Destination: header.IPv6EmptySubnet, NIC: peerNIC},
	})
	// A dual-stack listener accepts IPv4 connections too.
	ln, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: peerNIC, Port: peerTCPPort}, ipv6.ProtocolNumber)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("ListenTCP: %v", err)
	}
	go serveEcho(ln)
	return l, nil
}

// serveEcho answers each connection accepted on ln until ln closes.
func serveEcho(ln *gonet.TCPListener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(peerWait))
			if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
				return
			}
			src := c.RemoteAddr().(*net.TCPAddr).IP
			dst := c.LocalAddr().(*net.TCPAddr).IP
			fmt.Fprintf(c, "pong %v %v\n", src, dst)
		}()
	}
}

// nextOffer returns the Offer of the next connection to p, once the
// connection's packets are forwarded.
func (p *helloPeer) nextOffer(t *testing.T) *pb.Offer {
	t.Helper()
	select {
	case c := <-p.conns:
		if c.err != nil {
			t.Fatalf("peer hello failed (Offer %v): %v", c.offer, c.err)
		}
		return c.offer
	case <-time.After(peerWait):
		t.Fatalf("runsc did not finish a hello with the peer at %q", p.path)
	}
	return nil
}

// peerTestConfig returns a configuration that takes the proxy link from the
// peer at path.
func peerTestConfig(t *testing.T, path string) *config.Config {
	conf := testutil.TestConfig(t)
	conf.Network = config.NetworkSandbox
	conf.NetworkProxyPath = path
	conf.NetworkProxyConfig = config.NetworkProxyConfigPeer
	return conf
}

// guestOutput runs cmd with /bin/sh in cont and returns its output.
func guestOutput(t *testing.T, conf *config.Config, cont *Container, cmd string) string {
	t.Helper()
	out, err := executeCombinedOutput(conf, cont, nil, "/bin/sh", "-c", cmd)
	if err != nil {
		t.Fatalf("%q failed: %v (output: %s)", cmd, err, out)
	}
	return string(out)
}

// procNetRoute returns the rows of /proc/net/route as "iface dst/len via gw".
func procNetRoute(t *testing.T, out string) []string {
	t.Helper()
	hexAddr := func(s string) netip.Addr {
		var v uint32
		if _, err := fmt.Sscanf(s, "%x", &v); err != nil {
			t.Fatalf("parsing /proc/net/route address %q: %v", s, err)
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		return netip.AddrFrom4(b)
	}
	var rows []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 8 {
			t.Fatalf("short /proc/net/route row %q", line)
		}
		mask := hexAddr(f[7]).AsSlice()
		bits := 0
		for _, b := range mask {
			for ; b&0x80 != 0; b <<= 1 {
				bits++
			}
		}
		rows = append(rows, fmt.Sprintf("%s %v/%d via %v", f[0], hexAddr(f[1]), bits, hexAddr(f[2])))
	}
	slices.Sort(rows)
	return rows
}

// ipRoutes returns the routes in the output of "ip route" as "dst via gw dev
// name", with "via gw" omitted for an on-link route.
func ipRoutes(out string) []string {
	var rows []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		row := f[0]
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "via" || f[i] == "dev" {
				row += " " + f[i] + " " + f[i+1]
			}
		}
		rows = append(rows, row)
	}
	slices.Sort(rows)
	return rows
}

// checkPeerNetwork checks that the network of cont is the one that
// peerConfig(ip4, ip6) describes, plus loopback, and that TCP connections
// through each kind of route reach the peer from the configured addresses.
func checkPeerNetwork(t *testing.T, conf *config.Config, cont *Container, ip4, ip6 string) {
	t.Helper()

	var links []string
	for _, line := range strings.Split(strings.TrimSpace(guestOutput(t, conf, cont, "ip -o link show")), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name := strings.TrimSuffix(f[1], ":")
		if name == "eth0" {
			if i := slices.Index(f, "mtu"); i < 0 || i+1 == len(f) || f[i+1] != "1400" {
				t.Errorf("eth0 is %q, want mtu 1400", line)
			}
		}
		links = append(links, name)
	}
	if want := []string{"lo", "eth0"}; !slices.Equal(links, want) {
		t.Errorf("links = %q, want %q", links, want)
	}

	var addrs []string
	for _, line := range strings.Split(strings.TrimSpace(guestOutput(t, conf, cont, "ip -o addr show dev eth0")), "\n") {
		f := strings.Fields(line)
		if i := slices.IndexFunc(f, func(s string) bool { return s == "inet" || s == "inet6" }); i >= 0 && i+1 < len(f) {
			addrs = append(addrs, f[i+1])
		}
	}
	if want := []string{ip4 + "/24", ip6 + "/64"}; !slices.Equal(addrs, want) {
		t.Errorf("eth0 addresses = %q, want %q", addrs, want)
	}

	wantV4 := []string{
		"eth0 0.0.0.0/0 via 192.0.2.1",
		"eth0 192.0.2.0/24 via 0.0.0.0",
		"eth0 198.51.100.0/24 via 192.0.2.1",
	}
	if got := procNetRoute(t, guestOutput(t, conf, cont, "cat /proc/net/route")); !slices.Equal(got, wantV4) {
		t.Errorf("/proc/net/route = %q, want %q", got, wantV4)
	}
	wantV6 := []string{
		"2001:db8::/64 dev eth0",
		"::1 dev lo",
		"default via 2001:db8::1 dev eth0",
	}
	if got := ipRoutes(guestOutput(t, conf, cont, "ip -6 route show")); !slices.Equal(got, wantV6) {
		t.Errorf("ip -6 route = %q, want %q", got, wantV6)
	}

	for _, tc := range []struct{ dst, src string }{
		{"198.51.100.7", ip4},     // Through the 198.51.100.0/24 route.
		{"203.0.113.7", ip4},      // Through the IPv4 default route.
		{"2001:db8:ffff::7", ip6}, // Through the IPv6 default route.
	} {
		cmd := fmt.Sprintf(`python3 -c 'import socket, sys
s = socket.create_connection((sys.argv[1], %d), timeout=10)
s.sendall(b"ping\n")
print(s.makefile().readline().strip())' %s`, peerTCPPort, tc.dst)
		got := strings.TrimSpace(guestOutput(t, conf, cont, cmd))
		if want := fmt.Sprintf("pong %s %s", tc.src, tc.dst); got != want {
			t.Errorf("connection to %s: got %q, want %q", tc.dst, got, want)
		}
	}
}

// TestNetworkPeerCreate checks that a sandbox in --network-proxy-config=peer
// mode has exactly the network that the peer's Config describes, and that
// traffic flows through it.
func TestNetworkPeerCreate(t *testing.T) {
	peer := newHelloPeer(t, peerConfig("192.0.2.2", "2001:db8::2"))
	conf := peerTestConfig(t, peer.path)
	spec, _ := sleepSpecConf(t)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{ID: testutil.RandomContainerID(), Spec: spec, BundleDir: bundleDir}
	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()
	if err := cont.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	if o := peer.nextOffer(t); o.GetRestore() || o.GetSandboxId() != args.ID || o.GetLinkCount() != 1 {
		t.Errorf("Offer = %v, want restore false, sandbox_id %q and link_count 1", o, args.ID)
	}
	checkPeerNetwork(t, conf, cont, "192.0.2.2", "2001:db8::2")
}

// TestNetworkPeerCheckpointRestore checks that a restored sandbox asks the
// peer again, with Offer.restore set and its own ID, and takes the network
// from the new Config.
func TestNetworkPeerCheckpointRestore(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}
	peer := newHelloPeer(t,
		peerConfig("192.0.2.2", "2001:db8::2"),
		peerConfig("192.0.2.3", "2001:db8::3"))
	conf := peerTestConfig(t, peer.path)
	spec, _ := sleepSpecConf(t)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{ID: testutil.RandomContainerID(), Spec: spec, BundleDir: bundleDir}
	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()
	if err := cont.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}
	if o := peer.nextOffer(t); o.GetRestore() || o.GetSandboxId() != args.ID {
		t.Errorf("create Offer = %v, want restore false and sandbox_id %q", o, args.ID)
	}
	checkPeerNetwork(t, conf, cont, "192.0.2.2", "2001:db8::2")

	checkpointDir := makeTempDir(t, "checkpoint-peer-test")
	if err := cont.Checkpoint(conf, checkpointDir, sandbox.CheckpointOpts{}); err != nil {
		t.Fatalf("error checkpointing container: %v", err)
	}
	cont.Destroy()

	args2 := Args{ID: testutil.RandomContainerID(), Spec: spec, BundleDir: bundleDir}
	cont2, err := New(conf, args2)
	if err != nil {
		t.Fatalf("error creating restored container: %v", err)
	}
	defer cont2.Destroy()
	if err := cont2.Restore(conf, checkpointDir, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
		t.Fatalf("error restoring container: %v", err)
	}
	if o := peer.nextOffer(t); !o.GetRestore() || o.GetSandboxId() != args2.ID {
		t.Errorf("restore Offer = %v, want restore true and sandbox_id %q", o, args2.ID)
	}
	checkPeerNetwork(t, conf, cont2, "192.0.2.3", "2001:db8::3")
}
