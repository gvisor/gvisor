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

package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/netproxy/hello"
	pb "gvisor.dev/gvisor/pkg/netproxy/hello/hello_go_proto"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
)

// testHelloTimeout bounds the hello in tests that expect a reply.
const testHelloTimeout = 5 * time.Second

// fakePeer is the peer end of a network proxy socket.
type fakePeer struct {
	t  *testing.T
	fd int
}

// peerSocketPair returns runsc's end of a SOCK_SEQPACKET socket pair and a
// fakePeer for the other end.
func peerSocketPair(t *testing.T) (*os.File, *fakePeer) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("Socketpair() failed: %v", err)
	}
	f := os.NewFile(uintptr(fds[0]), "runsc-end")
	t.Cleanup(func() {
		f.Close()
		unix.Close(fds[1])
	})
	return f, &fakePeer{t: t, fd: fds[1]}
}

// recv reads one hello from runsc, failing the test after a timeout. The
// fakePeer methods report failures with Errorf, since they run on goroutines
// other than the test's.
func (p *fakePeer) recv() (hello.Header, proto.Message) {
	p.t.Helper()
	tv := unix.NsecToTimeval(testHelloTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(p.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		p.t.Errorf("SetsockoptTimeval() failed: %v", err)
		return hello.Header{}, nil
	}
	buf := make([]byte, hello.MaxMessageSize+1)
	n, err := unix.Read(p.fd, buf)
	if err != nil {
		p.t.Errorf("peer read failed: %v", err)
		return hello.Header{}, nil
	}
	h, msg, err := hello.Unmarshal(buf[:n])
	if err != nil {
		p.t.Errorf("peer received an invalid hello: %v", err)
	}
	return h, msg
}

// send sends msg with header h to runsc.
func (p *fakePeer) send(h hello.Header, msg proto.Message) {
	p.t.Helper()
	b, err := hello.Marshal(h, msg)
	if err != nil {
		p.t.Errorf("Marshal() failed: %v", err)
		return
	}
	p.write(b)
}

// write sends b as one datagram to runsc.
func (p *fakePeer) write(b []byte) {
	p.t.Helper()
	if _, err := unix.Write(p.fd, b); err != nil {
		p.t.Errorf("peer write failed: %v", err)
	}
}

// recvOffer reads runsc's Offer.
func (p *fakePeer) recvOffer() (hello.Header, *pb.Offer) {
	p.t.Helper()
	h, msg := p.recv()
	offer, ok := msg.(*pb.Offer)
	if !ok {
		p.t.Errorf("peer received %v (%T), want an Offer", h.Type, msg)
	}
	return h, offer
}

// recvError reads an Error from runsc that echoes xid.
func (p *fakePeer) recvError(xid uint32) *pb.Error {
	p.t.Helper()
	h, msg := p.recv()
	e, ok := msg.(*pb.Error)
	if !ok {
		p.t.Errorf("peer received %v (%v), want an Error", h.Type, msg)
		return nil
	}
	if h.XID != xid {
		p.t.Errorf("Error xid = %#x, want %#x", h.XID, xid)
	}
	return e
}

// wantNothing fails the test unless no datagram is queued for the peer.
func (p *fakePeer) wantNothing() {
	p.t.Helper()
	buf := make([]byte, hello.MaxMessageSize+1)
	n, _, err := unix.Recvfrom(p.fd, buf, unix.MSG_DONTWAIT)
	if !errors.Is(err, unix.EAGAIN) {
		p.t.Errorf("peer non-blocking recv = %d bytes (% x), %v; want EAGAIN", n, buf[:min(n, 16)], err)
	}
}

// runHello runs peerHello on f against a goroutine running peer, and returns
// peerHello's error and the Config it accepted.
func runHello(t *testing.T, f *os.File, timeout time.Duration, peer func()) (*pb.Config, error) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		peer()
	}()
	var accepted *pb.Config
	err := peerHello(f, "/test/peer.sock", peerOffer("sandbox-id", false), timeout, func(c *pb.Config) error {
		accepted = c
		return nil
	})
	<-done
	return accepted, err
}

func peerConfig() *pb.Config {
	return &pb.Config{
		Mtu: 1400,
		Addresses: []*pb.Address{
			{Ip: net.IPv4(10, 0, 0, 2).To4(), PrefixLen: 24},
			{Ip: net.ParseIP("2001:db8::2"), PrefixLen: 64},
		},
		Routes: []*pb.Route{
			{Dst: net.IPv4(10, 0, 0, 0).To4(), DstPrefixLen: 24},
			{Dst: net.IPv4zero.To4(), Gateway: net.IPv4(10, 0, 0, 1).To4(), Mtu: 1300},
			{Dst: net.ParseIP("2001:db8::"), DstPrefixLen: 64},
			{Dst: net.IPv6zero, Gateway: net.ParseIP("2001:db8::1")},
		},
	}
}

func TestPeerHello(t *testing.T) {
	f, peer := peerSocketPair(t)
	want := peerConfig()
	var offerH hello.Header
	var offer *pb.Offer
	got, err := runHello(t, f, testHelloTimeout, func() {
		offerH, offer = peer.recvOffer()
		peer.send(hello.Header{Type: hello.TypeConfig, Major: hello.Major, XID: offerH.XID}, want)
		h, msg := peer.recv()
		if _, ok := msg.(*pb.Ack); !ok || h.XID != offerH.XID {
			t.Errorf("peer received %v with xid %#x, want an Ack with xid %#x", h.Type, h.XID, offerH.XID)
		}
	})
	if err != nil {
		t.Fatalf("peerHello() failed: %v", err)
	}
	if !proto.Equal(got, want) {
		t.Errorf("peerHello() accepted %v, want %v", got, want)
	}
	if offerH.Major != hello.Major {
		t.Errorf("Offer major = %d, want %d", offerH.Major, hello.Major)
	}
	wantOffer := &pb.Offer{SupportedMajors: []uint32{hello.Major}, SandboxId: "sandbox-id", LinkIndex: 0, LinkCount: 1}
	if !proto.Equal(offer, wantOffer) {
		t.Errorf("Offer = %v, want %v", offer, wantOffer)
	}
	if err := hello.ValidateOffer(offer); err != nil {
		t.Errorf("ValidateOffer() = %v", err)
	}

	// The hello is consumed, so the sentry reads only what follows it.
	peer.wantNothing()
	if n, _, err := unix.Recvfrom(int(f.Fd()), make([]byte, 64), unix.MSG_DONTWAIT); !errors.Is(err, unix.EAGAIN) {
		t.Errorf("runsc end non-blocking recv = %d, %v; want EAGAIN", n, err)
	}
	for _, opt := range []int{unix.SO_RCVTIMEO, unix.SO_SNDTIMEO} {
		tv, err := unix.GetsockoptTimeval(int(f.Fd()), unix.SOL_SOCKET, opt)
		if err != nil {
			t.Fatalf("GetsockoptTimeval(%d) failed: %v", opt, err)
		}
		if tv.Sec != 0 || tv.Usec != 0 {
			t.Errorf("socket timeout %d = %+v after hello, want 0", opt, tv)
		}
	}
}

func TestPeerOffer(t *testing.T) {
	o := peerOffer(strings.Repeat("s", 200), true)
	if !o.GetRestore() {
		t.Errorf("peerOffer(isRestore=true).Restore = false, want true")
	}
	if o.GetLinkIndex() != 0 || o.GetLinkCount() != 1 {
		t.Errorf("peerOffer() link %d of %d, want 0 of 1", o.GetLinkIndex(), o.GetLinkCount())
	}
	if err := hello.ValidateOffer(o); err != nil {
		t.Errorf("ValidateOffer(peerOffer()) = %v, want nil", err)
	}
}

func TestPeerHelloDiscardsPacketsBeforeConfig(t *testing.T) {
	f, peer := peerSocketPair(t)
	if err := unix.SetsockoptInt(peer.fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4*hello.MaxMessageSize); err != nil {
		t.Fatalf("SetsockoptInt(SO_SNDBUF) failed: %v", err)
	}
	large := make([]byte, hello.MaxMessageSize+100)
	large[0] = 0x45
	_, err := runHello(t, f, testHelloTimeout, func() {
		h, _ := peer.recvOffer()
		peer.write([]byte{0x45, 0, 0, 20})
		peer.write([]byte{0x60, 0, 0, 0})
		peer.write(large)
		peer.send(hello.Header{Type: hello.TypeConfig, Major: hello.Major, XID: h.XID}, peerConfig())
		peer.recv()
	})
	if err != nil {
		t.Fatalf("peerHello() with IP packets before the Config failed: %v", err)
	}
}

func TestPeerHelloPacketsAfterConfigReachSentry(t *testing.T) {
	f, peer := peerSocketPair(t)
	packet := []byte{0x45, 0, 0, 20, 1, 2, 3}
	_, err := runHello(t, f, testHelloTimeout, func() {
		h, _ := peer.recvOffer()
		peer.send(hello.Header{Type: hello.TypeConfig, Major: hello.Major, XID: h.XID}, peerConfig())
		peer.write(packet)
	})
	if err != nil {
		t.Fatalf("peerHello() failed: %v", err)
	}
	buf := make([]byte, 64)
	n, _, err := unix.Recvfrom(int(f.Fd()), buf, unix.MSG_DONTWAIT)
	if err != nil || !bytes.Equal(buf[:n], packet) {
		t.Errorf("runsc end recv = % x, %v; want the packet % x", buf[:n], err, packet)
	}
}

func TestPeerHelloSilentPeer(t *testing.T) {
	f, peer := peerSocketPair(t)
	const timeout = 200 * time.Millisecond
	start := time.Now()
	_, err := runHello(t, f, timeout, func() { peer.recvOffer() })
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), `network proxy peer at "/test/peer.sock" sent no hello reply within 200ms`) {
		t.Errorf("peerHello() = %v, want a timeout error", err)
	}
	if elapsed < timeout || elapsed > timeout+2*time.Second {
		t.Errorf("peerHello() returned after %v, want about %v", elapsed, timeout)
	}
	// runsc sends nothing after the Offer to a silent peer.
	peer.wantNothing()
}

// TestPeerHelloPacketsDoNotExtendDeadline checks that a peer that sends only
// IP packets still times out.
func TestPeerHelloPacketsDoNotExtendDeadline(t *testing.T) {
	f, peer := peerSocketPair(t)
	const timeout = 300 * time.Millisecond
	stop := make(chan struct{})
	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		peer.recvOffer()
		for time.Since(start) < timeout+2*time.Second {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				unix.Write(peer.fd, []byte{0x45, 0, 0, 20})
			}
		}
	}()
	err := peerHello(f, "/test/peer.sock", peerOffer("id", false), timeout, func(*pb.Config) error { return nil })
	elapsed := time.Since(start)
	close(stop)
	<-done
	if err == nil || !strings.Contains(err.Error(), "sent no hello reply") || !strings.Contains(err.Error(), "IP packets discarded") {
		t.Errorf("peerHello() = %v, want a timeout error that counts the IP packets", err)
	}
	if elapsed > timeout+2*time.Second {
		t.Errorf("peerHello() returned after %v, want about %v", elapsed, timeout)
	}
}

func TestPeerHelloEOF(t *testing.T) {
	for _, tc := range []struct {
		name    string
		packets int
		how     int
	}{
		{name: "shutdown", how: unix.SHUT_RDWR},
		{name: "shutdown writes", how: unix.SHUT_WR},
		{name: "after IP packets", packets: 2, how: unix.SHUT_RDWR},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, peer := peerSocketPair(t)
			_, err := runHello(t, f, testHelloTimeout, func() {
				peer.recvOffer()
				for range tc.packets {
					peer.write([]byte{0x45, 0, 0, 20})
				}
				unix.Shutdown(peer.fd, tc.how)
			})
			if err == nil || !strings.Contains(err.Error(), "closed the connection during hello") {
				t.Errorf("peerHello() = %v, want an EOF error", err)
			}
			if want := fmt.Sprintf("(%d IP packets discarded)", tc.packets); tc.packets > 0 && !strings.Contains(err.Error(), want) {
				t.Errorf("peerHello() = %v, want it to say %q", err, want)
			}
		})
	}
}

func TestPeerHelloPeerError(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    *pb.Error
		want string
	}{
		{
			name: "not ready",
			e:    &pb.Error{Code: pb.ErrorCode_ERROR_CODE_NOT_READY, Message: "no config for sandbox abc"},
			want: `network proxy peer at "/test/peer.sock" refused (NOT_READY): "no config for sandbox abc"`,
		},
		{
			name: "with field",
			e:    &pb.Error{Code: pb.ErrorCode_ERROR_CODE_INVALID_VALUE, Field: "link_count", Message: "only one link"},
			want: `refused (INVALID_VALUE, field "link_count"): "only one link"`,
		},
		{
			name: "unknown code",
			e:    &pb.Error{Code: 42, Message: "future"},
			want: `refused (42): "future"`,
		},
		{
			name: "unsupported version",
			e:    &pb.Error{Code: pb.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION, SupportedMajors: []uint32{2}},
			want: `network proxy peer at "/test/peer.sock" supports hello majors [2]; runsc supports [1]`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, peer := peerSocketPair(t)
			_, err := runHello(t, f, testHelloTimeout, func() {
				h, _ := peer.recvOffer()
				// An Error from a peer of another major is still read.
				peer.send(hello.Header{Type: hello.TypeError, Major: 2, XID: h.XID}, tc.e)
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("peerHello() = %v, want an error containing %q", err, tc.want)
			}
			// runsc doesn't answer a peer's Error.
			peer.wantNothing()
		})
	}
}

func TestPeerHelloRefusesInvalidConfig(t *testing.T) {
	c := peerConfig()
	c.Routes = append(c.Routes[:3], &pb.Route{Dst: net.IPv4(10, 0, 0, 0).To4(), DstPrefixLen: 8, Gateway: net.IPv4(192, 168, 1, 1).To4()})
	f, peer := peerSocketPair(t)
	var got *pb.Error
	_, err := runHello(t, f, testHelloTimeout, func() {
		h, _ := peer.recvOffer()
		peer.send(hello.Header{Type: hello.TypeConfig, Major: hello.Major, XID: h.XID}, c)
		got = peer.recvError(h.XID)
	})
	const want = `invalid hello from network proxy peer at "/test/peer.sock": routes[3] 10.0.0.0/8: gateway 192.168.1.1 is not within any address prefix or on-link route`
	if err == nil || err.Error() != want {
		t.Errorf("peerHello() = %v, want %q", err, want)
	}
	if got.GetCode() != pb.ErrorCode_ERROR_CODE_INVALID_VALUE || got.GetField() != "routes[3].gateway" || !strings.Contains(got.GetMessage(), "not within any address prefix") {
		t.Errorf("peer received %v, want INVALID_VALUE for routes[3].gateway", got)
	}
}

func TestPeerHelloRefusals(t *testing.T) {
	valid := func(xid uint32) []byte {
		b, err := hello.Marshal(hello.Header{Type: hello.TypeConfig, Major: hello.Major, XID: xid}, peerConfig())
		if err != nil {
			t.Errorf("Marshal() failed: %v", err)
		}
		return b
	}
	for _, tc := range []struct {
		name  string
		reply func(xid uint32) []byte
		code  pb.ErrorCode
		field string
	}{
		{
			name:  "not a hello",
			reply: func(uint32) []byte { return []byte{0x00, 1, 2, 3} },
			code:  pb.ErrorCode_ERROR_CODE_MALFORMED,
		},
		{
			name:  "IP version 5",
			reply: func(uint32) []byte { return []byte{0x55, 0, 0, 20} },
			code:  pb.ErrorCode_ERROR_CODE_MALFORMED,
		},
		{
			name:  "empty datagram",
			reply: func(uint32) []byte { return []byte{} },
			code:  pb.ErrorCode_ERROR_CODE_MALFORMED,
		},
		{
			name: "bad magic",
			reply: func(xid uint32) []byte {
				b := valid(xid)
				b[3] = 'X'
				return b
			},
			code: pb.ErrorCode_ERROR_CODE_MALFORMED,
		},
		{
			name:  "truncated",
			reply: func(xid uint32) []byte { return valid(xid)[:hello.HeaderSize-1] },
			code:  pb.ErrorCode_ERROR_CODE_MALFORMED,
		},
		{
			name: "oversized",
			reply: func(xid uint32) []byte {
				return append(valid(xid), make([]byte, hello.MaxMessageSize)...)
			},
			code: pb.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED,
		},
		{
			name: "one byte over the limit",
			reply: func(xid uint32) []byte {
				b := valid(xid)
				return append(b, make([]byte, hello.MaxMessageSize+1-len(b))...)
			},
			code: pb.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED,
		},
		{
			name:  "xid mismatch",
			reply: func(xid uint32) []byte { return valid(xid + 1) },
			code:  pb.ErrorCode_ERROR_CODE_MALFORMED,
		},
		{
			name: "unexpected Ack",
			reply: func(xid uint32) []byte {
				b, _ := hello.Marshal(hello.Header{Type: hello.TypeAck, Major: hello.Major, XID: xid}, &pb.Ack{})
				return b
			},
			code: pb.ErrorCode_ERROR_CODE_MALFORMED,
		},
		{
			name: "unexpected Offer",
			reply: func(xid uint32) []byte {
				b, _ := hello.Marshal(hello.Header{Type: hello.TypeOffer, Major: hello.Major, XID: xid}, peerOffer("x", false))
				return b
			},
			code: pb.ErrorCode_ERROR_CODE_MALFORMED,
		},
		{
			name: "body does not decode",
			reply: func(xid uint32) []byte {
				b := append(valid(xid)[:hello.HeaderSize], 0xff, 0xff)
				b[8], b[9] = 0, byte(len(b))
				return b
			},
			code: pb.ErrorCode_ERROR_CODE_MALFORMED,
		},
		{
			name: "major not offered",
			reply: func(xid uint32) []byte {
				b, _ := hello.Marshal(hello.Header{Type: hello.TypeConfig, Major: 2, XID: xid}, peerConfig())
				return b
			},
			code: pb.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION,
		},
		{
			name: "unknown required feature",
			reply: func(xid uint32) []byte {
				c := peerConfig()
				c.RequiredFeatures = []string{"virtio_net_hdr"}
				b, _ := hello.Marshal(hello.Header{Type: hello.TypeConfig, Major: hello.Major, XID: xid}, c)
				return b
			},
			code:  pb.ErrorCode_ERROR_CODE_UNKNOWN_FEATURE,
			field: "required_features[0]",
		},
		{
			name: "link_index mismatch",
			reply: func(xid uint32) []byte {
				c := peerConfig()
				one := uint32(1)
				c.LinkIndex = &one
				b, _ := hello.Marshal(hello.Header{Type: hello.TypeConfig, Major: hello.Major, XID: xid}, c)
				return b
			},
			code:  pb.ErrorCode_ERROR_CODE_INVALID_VALUE,
			field: "link_index",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, peer := peerSocketPair(t)
			if err := unix.SetsockoptInt(peer.fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4*hello.MaxMessageSize); err != nil {
				t.Fatalf("SetsockoptInt(SO_SNDBUF) failed: %v", err)
			}
			var got *pb.Error
			accepted, err := runHello(t, f, testHelloTimeout, func() {
				h, _ := peer.recvOffer()
				peer.write(tc.reply(h.XID))
				got = peer.recvError(h.XID)
			})
			if err == nil || !strings.Contains(err.Error(), "invalid hello from network proxy peer") {
				t.Errorf("peerHello() = %v, want an invalid hello error", err)
			}
			if accepted != nil {
				t.Errorf("peerHello() accepted %v, want nothing accepted", accepted)
			}
			if got.GetCode() != tc.code || got.GetField() != tc.field {
				t.Errorf("peer received Error %v, want code %v, field %q", got, hello.CodeName(tc.code), tc.field)
			}
			if tc.code == pb.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION && !slices.Equal(got.GetSupportedMajors(), []uint32{hello.Major}) {
				t.Errorf("peer received supported_majors %v, want [%d]", got.GetSupportedMajors(), hello.Major)
			}
		})
	}
}

func TestPeerHelloAcceptRefuses(t *testing.T) {
	f, peer := peerSocketPair(t)
	var got *pb.Error
	done := make(chan struct{})
	go func() {
		defer close(done)
		h, _ := peer.recvOffer()
		peer.send(hello.Header{Type: hello.TypeConfig, Major: hello.Major, XID: h.XID}, peerConfig())
		got = peer.recvError(h.XID)
	}()
	err := peerHello(f, "/test/peer.sock", peerOffer("id", false), testHelloTimeout, func(*pb.Config) error {
		return errors.New("no room")
	})
	<-done
	if err == nil || !strings.Contains(err.Error(), "no room") {
		t.Errorf("peerHello() = %v, want the accept error", err)
	}
	if got.GetCode() != pb.ErrorCode_ERROR_CODE_REFUSED || got.GetMessage() != "no room" {
		t.Errorf("peer received %v, want REFUSED with message \"no room\"", got)
	}
}

func TestPeerHelloAckFails(t *testing.T) {
	f, peer := peerSocketPair(t)
	_, err := runHello(t, f, testHelloTimeout, func() {
		h, _ := peer.recvOffer()
		// runsc's writes fail with EPIPE once the peer stops reading.
		unix.Shutdown(peer.fd, unix.SHUT_RD)
		peer.send(hello.Header{Type: hello.TypeConfig, Major: hello.Major, XID: h.XID}, peerConfig())
	})
	if err == nil || !strings.Contains(err.Error(), "sending hello Ack") || !errors.Is(err, unix.EPIPE) {
		t.Errorf("peerHello() = %v, want EPIPE sending the Ack", err)
	}
}

func TestPeerLinksAndRoutes(t *testing.T) {
	conf := &config.Config{
		NumNetworkChannels:          4,
		NetworkProcessorsPerChannel: 2,
		GVisorGRO:                   true,
		GVisorGSO:                   true,
		TXChecksumOffload:           true,
		PauseExternalNetworking:     true,
		AllowConnectedOnSave:        true,
		QDisc:                       config.QDiscFIFO,
	}
	args, err := peerLinksAndRoutes(conf, []*pb.Config{peerConfig()}, false)
	if err != nil {
		t.Fatalf("peerLinksAndRoutes() failed: %v", err)
	}
	if len(args.LoopbackLinks) != 1 || !args.LoopbackLinks[0].GVisorGRO || !loopbackLinksEqual(args.LoopbackLinks, []sentryapi.LoopbackLink{sentryapi.DefaultLoopbackLink}) {
		t.Errorf("LoopbackLinks = %+v, want the default loopback link with GRO", args.LoopbackLinks)
	}
	if !args.PauseExternalNetworking || !args.AllowConnectedOnSave || args.AllowExternalLoopbackTraffic {
		t.Errorf("args = %+v, want PauseExternalNetworking and AllowConnectedOnSave, and no external loopback traffic", args)
	}
	if len(args.XDPLinks) != 0 || len(args.FilePayload.Files) != 0 {
		t.Errorf("args has XDP links %v and files %v, want none", args.XDPLinks, args.FilePayload.Files)
	}
	wantLink := sentryapi.FDBasedLink{
		Name:      "eth0",
		MTU:       1400,
		Multicast: true,
		QDisc:     config.QDiscFIFO,
		Addresses: []sentryapi.IPWithPrefix{
			{Address: net.IPv4(10, 0, 0, 2), PrefixLen: 24},
			{Address: net.ParseIP("2001:db8::2"), PrefixLen: 64},
		},
		Routes: []sentryapi.Route{
			{Destination: *parseCIDR(t, "10.0.0.0/24")},
			{Destination: *parseCIDR(t, "2001:db8::/64")},
		},
	}
	if !fdbasedLinksEqual(args.FDBasedLinks, []sentryapi.FDBasedLink{wantLink}) {
		t.Fatalf("FDBasedLinks = %+v, want %+v", args.FDBasedLinks, wantLink)
	}
	l := args.FDBasedLinks[0]
	if !l.IsProxy || l.NumChannels != 1 || l.ProcessorsPerChannel != 2 || !l.GVisorGRO {
		t.Errorf("link = %+v, want IsProxy, one channel, 2 processors and GRO", l)
	}
	if !l.TXChecksumOffload || !l.RXChecksumOffload {
		t.Errorf("link offloads TX %v RX %v, want both from --tx-checksum-offload", l.TXChecksumOffload, l.RXChecksumOffload)
	}
	if l.GSOMaxSize != tcpip.GVisorGSOMaxSize || !l.GVisorGSOEnabled {
		t.Errorf("link GSOMaxSize %d GVisorGSOEnabled %v, want gVisor GSO", l.GSOMaxSize, l.GVisorGSOEnabled)
	}
	if len(l.LinkAddress) != 0 || len(l.Neighbors) != 0 {
		t.Errorf("link has L2 address %v and neighbors %v, want none", l.LinkAddress, l.Neighbors)
	}
	wantV4 := sentryapi.DefaultRoute{Name: "eth0", Route: sentryapi.Route{Destination: *parseCIDR(t, "0.0.0.0/0"), Gateway: net.IPv4(10, 0, 0, 1), MTU: 1300}}
	if !defaultRouteEqual(args.Defaultv4Gateway, wantV4) || args.Defaultv4Gateway.Route.MTU != 1300 {
		t.Errorf("Defaultv4Gateway = %+v, want %+v", args.Defaultv4Gateway, wantV4)
	}
	wantV6 := sentryapi.DefaultRoute{Name: "eth0", Route: sentryapi.Route{Destination: *parseCIDR(t, "::/0"), Gateway: net.ParseIP("2001:db8::1")}}
	if !defaultRouteEqual(args.Defaultv6Gateway, wantV6) {
		t.Errorf("Defaultv6Gateway = %+v, want %+v", args.Defaultv6Gateway, wantV6)
	}
	if r := args.FDBasedLinks[0].Routes[0]; r.Gateway != nil {
		t.Errorf("on-link route gateway = %v, want nil", r.Gateway)
	}
}

func TestPeerLinksAndRoutesOptions(t *testing.T) {
	t.Run("offloads from the peer", func(t *testing.T) {
		c := peerConfig()
		c.Ifname = "net0"
		c.Offloads = &pb.Offloads{RxCsum: true}
		args, err := peerLinksAndRoutes(&config.Config{TXChecksumOffload: true, NumNetworkChannels: 1}, []*pb.Config{c}, false)
		if err != nil {
			t.Fatalf("peerLinksAndRoutes() failed: %v", err)
		}
		l := args.FDBasedLinks[0]
		if l.Name != "net0" || l.TXChecksumOffload || !l.RXChecksumOffload {
			t.Errorf("link %q offloads TX %v RX %v, want net0 with RX only", l.Name, l.TXChecksumOffload, l.RXChecksumOffload)
		}
		if args.Defaultv4Gateway.Name != "net0" || args.Defaultv6Gateway.Name != "net0" {
			t.Errorf("default routes on %q and %q, want net0", args.Defaultv4Gateway.Name, args.Defaultv6Gateway.Name)
		}
		if l.GVisorGSOEnabled || l.GSOMaxSize != 0 {
			t.Errorf("link has GSO %d, want none without --software-gso", l.GSOMaxSize)
		}
	})

	t.Run("TX offload only from the peer", func(t *testing.T) {
		c := peerConfig()
		c.Offloads = &pb.Offloads{TxCsum: true}
		args, err := peerLinksAndRoutes(&config.Config{RXChecksumOffload: true, NumNetworkChannels: 1}, []*pb.Config{c}, false)
		if err != nil {
			t.Fatalf("peerLinksAndRoutes() failed: %v", err)
		}
		if l := args.FDBasedLinks[0]; !l.TXChecksumOffload || l.RXChecksumOffload {
			t.Errorf("link offloads TX %v RX %v, want TX only", l.TXChecksumOffload, l.RXChecksumOffload)
		}
	})

	t.Run("on-link default routes", func(t *testing.T) {
		c := peerConfig()
		c.Addresses = []*pb.Address{
			{Ip: net.IPv4(192, 0, 2, 7).To4(), PrefixLen: 32},
			{Ip: net.ParseIP("2001:db8::7"), PrefixLen: 128},
		}
		c.Routes = []*pb.Route{
			{Dst: net.IPv4zero.To4()},
			{Dst: net.IPv6zero},
		}
		args, err := peerLinksAndRoutes(&config.Config{NumNetworkChannels: 1}, []*pb.Config{c}, false)
		if err != nil {
			t.Fatalf("peerLinksAndRoutes() failed: %v", err)
		}
		wantV4 := sentryapi.DefaultRoute{Name: "eth0", Route: sentryapi.Route{Destination: *parseCIDR(t, "0.0.0.0/0")}}
		if !defaultRouteEqual(args.Defaultv4Gateway, wantV4) || args.Defaultv4Gateway.Route.Gateway != nil {
			t.Errorf("Defaultv4Gateway = %+v, want %+v", args.Defaultv4Gateway, wantV4)
		}
		wantV6 := sentryapi.DefaultRoute{Name: "eth0", Route: sentryapi.Route{Destination: *parseCIDR(t, "::/0")}}
		if !defaultRouteEqual(args.Defaultv6Gateway, wantV6) || args.Defaultv6Gateway.Route.Gateway != nil {
			t.Errorf("Defaultv6Gateway = %+v, want %+v", args.Defaultv6Gateway, wantV6)
		}
		if len(args.FDBasedLinks[0].Routes) != 0 {
			t.Errorf("link routes = %v, want none", args.FDBasedLinks[0].Routes)
		}
	})

	t.Run("IPv6 disabled", func(t *testing.T) {
		args, err := peerLinksAndRoutes(&config.Config{NumNetworkChannels: 1}, []*pb.Config{peerConfig()}, true)
		if err != nil {
			t.Fatalf("peerLinksAndRoutes() failed: %v", err)
		}
		l := args.FDBasedLinks[0]
		if len(l.Addresses) != 1 || l.Addresses[0].Address.To4() == nil || len(l.Routes) != 1 || l.Routes[0].Destination.IP.To4() == nil {
			t.Errorf("link addresses %v routes %v, want only IPv4", l.Addresses, l.Routes)
		}
		if !args.Defaultv6Gateway.Route.Empty() || args.Defaultv4Gateway.Route.Empty() {
			t.Errorf("default routes v4 %+v v6 %+v, want only IPv4", args.Defaultv4Gateway, args.Defaultv6Gateway)
		}
		for _, a := range args.LoopbackLinks[0].Addresses {
			if a.Address.To4() == nil {
				t.Errorf("loopback has IPv6 address %v with IPv6 disabled", a)
			}
		}
		for _, r := range args.LoopbackLinks[0].Routes {
			if r.Destination.IP.To4() == nil {
				t.Errorf("loopback has IPv6 route %v with IPv6 disabled", r.Destination)
			}
		}
		if len(sentryapi.DefaultLoopbackLink.Addresses) != 2 {
			t.Errorf("DefaultLoopbackLink was modified: %+v", sentryapi.DefaultLoopbackLink)
		}
	})

	t.Run("IPv6 only with IPv6 disabled", func(t *testing.T) {
		c := peerConfig()
		c.Addresses = c.Addresses[1:]
		c.Routes = c.Routes[2:]
		_, err := peerLinksAndRoutes(&config.Config{NumNetworkChannels: 1}, []*pb.Config{c}, true)
		var e *hello.Error
		if !errors.As(err, &e) || e.Code != pb.ErrorCode_ERROR_CODE_REFUSED || e.Field != "addresses" {
			t.Errorf("peerLinksAndRoutes() = %v, want a REFUSED hello error for addresses", err)
		}
	})
}

// SetNetworkArgs implements sentryapi.ContMgrSetNetworkArgs.
func (cm *containerManager) SetNetworkArgs(args *sentryapi.CreateLinksAndRoutesArgs, _ *struct{}) error {
	// The server closes the received files when the call returns.
	files := make([]*os.File, 0, len(args.FilePayload.Files))
	for _, f := range args.FilePayload.Files {
		fd, err := unix.Dup(int(f.Fd()))
		if err != nil {
			return err
		}
		files = append(files, os.NewFile(uintptr(fd), f.Name()))
	}
	args.FilePayload.Files = files
	cm.networkArgs <- args
	return nil
}

// fakeSentry returns a client connected to a containerManager, and the
// channel that receives the network args the client sets.
func fakeSentry(t *testing.T) (*urpc.Client, <-chan *sentryapi.CreateLinksAndRoutesArgs) {
	t.Helper()
	serverSock, clientSock, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("unet.SocketPair() failed: %v", err)
	}
	networkArgs := make(chan *sentryapi.CreateLinksAndRoutesArgs, 1)
	server := urpc.NewServer()
	server.Register(&containerManager{networkArgs: networkArgs})
	server.StartHandling(serverSock)
	client := urpc.NewClient(clientSock)
	t.Cleanup(func() {
		client.Close()
		server.Stop(0)
	})
	return client, networkArgs
}

// listenPeer listens for runsc's connection at a new path, and runs serve on
// the accepted connection in a goroutine.
func listenPeer(t *testing.T, serve func(p *fakePeer)) (string, chan struct{}) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "peer.sock")
	lfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("Socket() failed: %v", err)
	}
	t.Cleanup(func() { unix.Close(lfd) })
	// accept(2) honors SO_RCVTIMEO, so the goroutine below ends even if
	// nothing connects.
	tv := unix.NsecToTimeval(testHelloTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(lfd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		t.Fatalf("SetsockoptTimeval() failed: %v", err)
	}
	if err := unix.Bind(lfd, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatalf("Bind(%q) failed: %v", path, err)
	}
	if err := unix.Listen(lfd, 1); err != nil {
		t.Fatalf("Listen() failed: %v", err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	go func() {
		defer close(done)
		fd, _, err := unix.Accept4(lfd, unix.SOCK_CLOEXEC)
		if errors.Is(err, unix.EAGAIN) {
			return
		}
		if err != nil {
			t.Errorf("Accept4() failed: %v", err)
			return
		}
		t.Cleanup(func() { unix.Close(fd) })
		serve(&fakePeer{t: t, fd: fd})
	}()
	return path, done
}

func TestCreateInterfacesAndRoutesFromPeer(t *testing.T) {
	for _, isRestore := range []bool{false, true} {
		name := "create"
		if isRestore {
			name = "restore"
		}
		t.Run(name, func(t *testing.T) {
			var offer *pb.Offer
			var peerFD int
			packet := []byte{0x45, 0, 0, 20, 9, 9}
			path, peerDone := listenPeer(t, func(p *fakePeer) {
				var h hello.Header
				h, offer = p.recvOffer()
				p.send(hello.Header{Type: hello.TypeConfig, Major: hello.Major, XID: h.XID}, peerConfig())
				if h, msg := p.recv(); h.Type != hello.TypeAck {
					t.Errorf("peer received %v (%v), want an Ack", h.Type, msg)
				}
				p.write(packet)
				peerFD = p.fd
			})
			conn, networkArgs := fakeSentry(t)
			conf := &config.Config{
				Network:            config.NetworkSandbox,
				NetworkProxyPath:   path,
				NetworkProxyConfig: config.NetworkProxyConfigPeer,
				NumNetworkChannels: 1,
				PCAP:               filepath.Join(t.TempDir(), "net.pcap"),
			}
			if err := createInterfacesAndRoutesFromPeer(conn, conf, "sandbox-id", false, isRestore); err != nil {
				t.Fatalf("createInterfacesAndRoutesFromPeer() failed: %v", err)
			}
			<-peerDone
			if offer.GetRestore() != isRestore || offer.GetSandboxId() != "sandbox-id" || offer.GetLinkCount() != 1 {
				t.Errorf("Offer = %v, want restore %v for sandbox-id, link 0 of 1", offer, isRestore)
			}

			var args *sentryapi.CreateLinksAndRoutesArgs
			select {
			case args = <-networkArgs:
			case <-time.After(testHelloTimeout):
				t.Fatal("the sentry received no network args")
			}
			if args.IsRestore != isRestore {
				t.Errorf("IsRestore = %v, want %v", args.IsRestore, isRestore)
			}
			if len(args.FDBasedLinks) != 1 || !args.FDBasedLinks[0].IsProxy || args.FDBasedLinks[0].MTU != 1400 || args.Defaultv4Gateway.Name != "eth0" {
				t.Errorf("args = %+v, want one proxy link eth0 with MTU 1400 and the IPv4 default route", args)
			}
			for _, f := range args.FilePayload.Files {
				defer f.Close()
			}
			// The link's socket comes before the PCAP file.
			if len(args.FilePayload.Files) != 2 || !args.PCAP {
				t.Fatalf("sentry received %d files and PCAP %v, want the socket and the PCAP file", len(args.FilePayload.Files), args.PCAP)
			}
			sentryEnd := args.FilePayload.Files[0]

			// The sentry's first datagram is the peer's packet, not the hello.
			buf := make([]byte, 64)
			if n, _, err := unix.Recvfrom(int(sentryEnd.Fd()), buf, unix.MSG_DONTWAIT); err != nil {
				t.Errorf("sentry recv failed: %v", err)
			} else if !bytes.Equal(buf[:n], packet) {
				t.Errorf("sentry recv = % x, want % x", buf[:n], packet)
			}
			if _, err := unix.Write(int(sentryEnd.Fd()), packet); err != nil {
				t.Fatalf("sentry write failed: %v", err)
			}
			if n, _, err := unix.Recvfrom(peerFD, buf, unix.MSG_DONTWAIT); err != nil {
				t.Errorf("peer recv failed: %v", err)
			} else if !bytes.Equal(buf[:n], packet) {
				t.Errorf("peer recv = % x, want % x", buf[:n], packet)
			}
		})
	}
}

// TestSetupNetworkPeer checks that in peer mode, setupNetwork takes the link
// from the peer without opening the sandbox process's network namespace.
func TestSetupNetworkPeer(t *testing.T) {
	path, peerDone := listenPeer(t, func(p *fakePeer) {
		h, _ := p.recvOffer()
		p.send(hello.Header{Type: hello.TypeConfig, Major: hello.Major, XID: h.XID}, peerConfig())
		p.recv()
	})
	conn, networkArgs := fakeSentry(t)
	conf := &config.Config{
		Network:            config.NetworkSandbox,
		NetworkProxyPath:   path,
		NetworkProxyConfig: config.NetworkProxyConfigPeer,
		NumNetworkChannels: 1,
	}
	// PID 0 has no /proc entry, so any use of the namespace fails.
	s := &Sandbox{ID: "sandbox-id"}
	if err := s.setupNetwork(conn, 0, &specs.Spec{}, conf, false, false); err != nil {
		t.Fatalf("setupNetwork() failed: %v", err)
	}
	<-peerDone
	args := <-networkArgs
	for _, f := range args.FilePayload.Files {
		f.Close()
	}
	if len(args.FDBasedLinks) != 1 || !args.FDBasedLinks[0].IsProxy || args.FDBasedLinks[0].MTU != 1400 {
		t.Errorf("FDBasedLinks = %+v, want the peer's proxy link with MTU 1400", args.FDBasedLinks)
	}
}

// TestNetNSModeSendsNoHello checks that with --network-proxy-config=netns,
// runsc writes nothing on the --network-proxy-path socket.
func TestNetNSModeSendsNoHello(t *testing.T) {
	requireRoot(t)
	link := setupVethInterface(t, "eth0", "10.0.0.2", 24, 32)
	setupLoopback(t)
	addRoute(t, nil, net.IPv4(10, 0, 0, 1))

	accepted := make(chan *fakePeer, 1)
	path, peerDone := listenPeer(t, func(p *fakePeer) { accepted <- p })
	conn, networkArgs := fakeSentry(t)
	conf := &config.Config{
		Network:            config.NetworkSandbox,
		NetworkProxyPath:   path,
		NumNetworkChannels: 1,
	}
	if _, err := createInterfacesAndRoutesFromNS(conn, "/proc/thread-self/ns/net", conf, false, false, false, nil); err != nil {
		t.Fatalf("createInterfacesAndRoutesFromNS() failed: %v", err)
	}
	<-peerDone
	args := <-networkArgs
	for _, f := range args.FilePayload.Files {
		defer f.Close()
	}
	if len(args.FDBasedLinks) != 1 || !args.FDBasedLinks[0].IsProxy || args.FDBasedLinks[0].Name != link.Attrs().Name {
		t.Fatalf("FDBasedLinks = %+v, want the proxy link eth0", args.FDBasedLinks)
	}
	(<-accepted).wantNothing()
}

// TestDialExternalUDSSendsNothing checks that dialing the peer, the only
// socket operation of runsc in netns mode, writes nothing on the socket.
func TestDialExternalUDSSendsNothing(t *testing.T) {
	accepted := make(chan *fakePeer, 1)
	path, peerDone := listenPeer(t, func(p *fakePeer) { accepted <- p })
	f, err := dialExternalUDS(path)
	if err != nil {
		t.Fatalf("dialExternalUDS() failed: %v", err)
	}
	defer f.Close()
	<-peerDone
	(<-accepted).wantNothing()
}

// TestCreateInterfacesAndRoutesFromPeerPCAPFails checks that a local failure
// after a valid Config is reported to the peer as INTERNAL instead of an Ack.
func TestCreateInterfacesAndRoutesFromPeerPCAPFails(t *testing.T) {
	var got *pb.Error
	path, peerDone := listenPeer(t, func(p *fakePeer) {
		h, _ := p.recvOffer()
		p.send(hello.Header{Type: hello.TypeConfig, Major: hello.Major, XID: h.XID}, peerConfig())
		got = p.recvError(h.XID)
	})
	conn, networkArgs := fakeSentry(t)
	conf := &config.Config{
		NetworkProxyPath:   path,
		NetworkProxyConfig: config.NetworkProxyConfigPeer,
		NumNetworkChannels: 1,
		PCAP:               filepath.Join(t.TempDir(), "missing", "net.pcap"),
	}
	err := createInterfacesAndRoutesFromPeer(conn, conf, "id", false, false)
	<-peerDone
	if err == nil || !strings.Contains(err.Error(), "PCAP") {
		t.Errorf("createInterfacesAndRoutesFromPeer() = %v, want the PCAP error", err)
	}
	if got.GetCode() != pb.ErrorCode_ERROR_CODE_INTERNAL {
		t.Errorf("peer received %v, want INTERNAL", got)
	}
	select {
	case args := <-networkArgs:
		t.Errorf("the sentry received network args %+v after a failed hello", args)
	default:
	}
}

func TestCreateInterfacesAndRoutesFromPeerFails(t *testing.T) {
	path, peerDone := listenPeer(t, func(p *fakePeer) {
		h, _ := p.recvOffer()
		p.send(hello.Header{Type: hello.TypeError, Major: hello.Major, XID: h.XID}, &pb.Error{Code: pb.ErrorCode_ERROR_CODE_NOT_READY, Message: "later"})
	})
	conn, networkArgs := fakeSentry(t)
	conf := &config.Config{NetworkProxyPath: path, NetworkProxyConfig: config.NetworkProxyConfigPeer, NumNetworkChannels: 1}
	err := createInterfacesAndRoutesFromPeer(conn, conf, "id", false, false)
	<-peerDone
	if err == nil || !strings.Contains(err.Error(), `refused (NOT_READY): "later"`) {
		t.Errorf("createInterfacesAndRoutesFromPeer() = %v, want the peer's refusal", err)
	}
	select {
	case args := <-networkArgs:
		t.Errorf("the sentry received network args %+v after a refused hello", args)
	default:
	}
}
