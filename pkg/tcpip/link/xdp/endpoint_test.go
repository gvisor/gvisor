// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package xdp

import (
	"bytes"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/stopfd"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/runsc/sandbox/bpf"
)

func TestSetAddress(t *testing.T) {
	ep := &endpoint{
		addr: "xyz",
	}
	addrs := []tcpip.LinkAddress{"abc", "def"}
	for _, addr := range addrs {
		ep.SetLinkAddress(addr)

		if want, v := addr, ep.LinkAddress(); want != v {
			t.Errorf("LinkAddress() = %v, want %v", v, want)
		}
	}
}

type fakeNetworkDispatcher struct{}

func (*fakeNetworkDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
}

func (*fakeNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// TestReattachAfterDetach checks that an endpoint can be reattached after
// detaching. It polls a socketpair that never becomes readable, since an
// AF_XDP socket needs privileges.
func TestReattachAfterDetach(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair = %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	stopFD, err := stopfd.New()
	if err != nil {
		t.Fatalf("stopfd.New = %v", err)
	}
	exited := make(chan struct{}, 1)
	ep := &endpoint{
		fd:     fds[0],
		stopFD: stopFD,
		closed: func(tcpip.Error) { exited <- struct{}{} },
	}
	defer ep.Close()

	for i := 0; i < 3; i++ {
		ep.Attach(&fakeNetworkDispatcher{})
		select {
		case <-exited:
			t.Fatalf("attachment %d: dispatch loop exited while attached", i)
		case <-time.After(100 * time.Millisecond):
		}

		detached := make(chan struct{})
		go func() {
			ep.Attach(nil)
			close(detached)
		}()
		select {
		case <-detached:
		case <-time.After(10 * time.Second):
			t.Fatalf("attachment %d: Attach(nil) did not return", i)
		}
		select {
		case <-exited:
		default:
			t.Fatalf("attachment %d: dispatch loop still running after Attach(nil)", i)
		}
	}
}

const testEtherType tcpip.NetworkProtocolNumber = 0x88b5

// blockingNetworkDispatcher blocks the first test packet until unblock is
// closed.
type blockingNetworkDispatcher struct {
	once    sync.Once
	entered chan struct{}
	unblock chan struct{}
}

func (d *blockingNetworkDispatcher) DeliverNetworkPacket(proto tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {
	if proto != testEtherType {
		return
	}
	d.once.Do(func() {
		close(d.entered)
		<-d.unblock
	})
}

func (*blockingNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
}

type chanNetworkDispatcher struct {
	ch chan struct{}
}

func (d *chanNetworkDispatcher) DeliverNetworkPacket(proto tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {
	if proto != testEtherType {
		return
	}
	select {
	case d.ch <- struct{}{}:
	default:
	}
}

func (*chanNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func skipOrFatal(t *testing.T, op string, err error) {
	t.Helper()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, ebpf.ErrNotSupported) {
		t.Skipf("%s: %v", op, err)
	}
	t.Fatalf("%s = %v", op, err)
}

// newVethEndpoint creates a veth pair in a new network namespace and an
// AF_XDP endpoint on one end. The returned function sends a test frame from
// the other end.
func newVethEndpoint(t *testing.T) (stack.LinkEndpoint, func()) {
	t.Helper()
	// The thread stays in the new network namespace until the test exits.
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		skipOrFatal(t, "Unshare(CLONE_NEWNET)", err)
	}
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "xdp0"}, PeerName: "xdp1"}); err != nil {
		skipOrFatal(t, "LinkAdd(veth)", err)
	}
	var attrs [2]*netlink.LinkAttrs
	for i, name := range []string{"xdp0", "xdp1"} {
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("LinkByName(%q) = %v", name, err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatalf("LinkSetUp(%q) = %v", name, err)
		}
		attrs[i] = l.Attrs()
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpf.AFXDPProgram))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader = %v", err)
	}
	var objs struct {
		Program *ebpf.Program `ebpf:"xdp_prog"`
		SockMap *ebpf.Map     `ebpf:"sock_map"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		skipOrFatal(t, "LoadAndAssign", err)
	}
	t.Cleanup(func() {
		objs.Program.Close()
		objs.SockMap.Close()
	})
	xdpLink, err := link.AttachRawLink(link.RawLinkOptions{
		Program: objs.Program,
		Attach:  ebpf.AttachXDP,
		Target:  attrs[0].Index,
	})
	if err != nil {
		skipOrFatal(t, "AttachRawLink", err)
	}
	t.Cleanup(func() { xdpLink.Close() })

	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		skipOrFatal(t, "Socket(AF_XDP)", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	ep, err := New(&Options{
		FD:             fd,
		Address:        tcpip.LinkAddress(attrs[0].HardwareAddr),
		InterfaceIndex: attrs[0].Index,
		Bind:           true,
	})
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	t.Cleanup(ep.Close)
	key, val := uint32(0), uint32(fd)
	if err := objs.SockMap.Update(&key, &val, 0); err != nil {
		t.Fatalf("SockMap.Update = %v", err)
	}

	pfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		t.Fatalf("Socket(AF_PACKET) = %v", err)
	}
	t.Cleanup(func() { unix.Close(pfd) })
	frame := make([]byte, header.EthernetMinimumSize+46)
	header.Ethernet(frame).Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress(attrs[1].HardwareAddr),
		DstAddr: tcpip.LinkAddress(attrs[0].HardwareAddr),
		Type:    testEtherType,
	})
	to := &unix.SockaddrLinklayer{Ifindex: attrs[1].Index}
	send := func() {
		if err := unix.Sendto(pfd, frame, 0, to); err != nil {
			t.Fatalf("Sendto = %v", err)
		}
	}
	return ep, send
}

// TestDetachWhileReceiving checks that an AF_XDP endpoint can be detached
// while packets are queued, and reattached afterwards. It needs root.
func TestDetachWhileReceiving(t *testing.T) {
	ep, send := newVethEndpoint(t)

	d := &blockingNetworkDispatcher{entered: make(chan struct{}), unblock: make(chan struct{})}
	ep.Attach(d)
	send()
	select {
	case <-d.entered:
	case <-time.After(10 * time.Second):
		t.Fatalf("packet not delivered")
	}
	// Queue packets in the RX ring while dispatch is blocked.
	for i := 0; i < 8; i++ {
		send()
	}
	time.Sleep(100 * time.Millisecond)
	detached := make(chan struct{})
	go func() {
		ep.Attach(nil)
		close(detached)
	}()
	for ep.IsAttached() {
		time.Sleep(time.Millisecond)
	}
	close(d.unblock)
	select {
	case <-detached:
	case <-time.After(10 * time.Second):
		t.Fatalf("Attach(nil) did not return")
	}

	c := &chanNetworkDispatcher{ch: make(chan struct{}, 1)}
	ep.Attach(c)
	send()
	select {
	case <-c.ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("no packet delivered after reattach")
	}
	ep.Attach(nil)
}
