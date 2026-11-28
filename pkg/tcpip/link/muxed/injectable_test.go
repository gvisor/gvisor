// Copyright 2019 The gVisor Authors.
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

package muxed

import (
	"bytes"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestInjectableEndpointMTU(t *testing.T) {
	endpoint, _, _ := makeTestInjectableEndpoint(t, stack.CapabilityNone)

	mtus := []uint32{100, 200}
	for _, mtu := range mtus {
		endpoint.SetMTU(mtu)

		if want, v := mtu, endpoint.MTU(); want != v {
			t.Errorf("MTU() = %v, want %v", v, want)
		}
	}
}

func TestInjectableEndpointRawDispatch(t *testing.T) {
	endpoint, sock, dstIP := makeTestInjectableEndpoint(t, stack.CapabilityNone)

	v := buffer.NewViewWithData([]byte{0xFA})
	defer v.Release()
	endpoint.InjectOutbound(dstIP, v)

	buf := make([]byte, ipv4.MaxTotalSize)
	bytesRead, err := sock.Read(buf)
	if err != nil {
		t.Fatalf("Unable to read from socketpair: %v", err)
	}
	if got, want := buf[:bytesRead], []byte{0xFA}; !bytes.Equal(got, want) {
		t.Fatalf("Read %v from the socketpair, wanted %v", got, want)
	}
}

func TestInjectableEndpointDispatch(t *testing.T) {
	endpoint, sock, dstIP := makeTestInjectableEndpoint(t, stack.CapabilityRXChecksumOffloadPerPacket)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 1,
		Payload:            buffer.MakeWithData([]byte{0xFB}),
	})
	defer pkt.DecRef()
	pkt.TransportHeader().Push(1)[0] = 0xFA
	pkt.EgressRoute.RemoteAddress = dstIP
	pkt.NetworkProtocolNumber = ipv4.ProtocolNumber

	var pkts stack.PacketBufferList
	pkts.PushBack(pkt)
	if _, err := endpoint.WritePackets(pkts); err != nil {
		t.Fatalf("Unable to write packets: %s", err)
	}

	buf := make([]byte, 6500)
	bytesRead, err := sock.Read(buf)
	if err != nil {
		t.Fatalf("Unable to read from socketpair: %v", err)
	}
	if got, want := buf[:bytesRead], []byte{0xFA, 0xFB}; !bytes.Equal(got, want) {
		t.Fatalf("Read %v from the socketpair, wanted %v", got, want)
	}

	// Mixed children may use only their common receive-checksum capabilities.
	for _, test := range []struct {
		name string
		caps stack.LinkEndpointCapabilities
		want [2]bool
	}{
		{"no offload", 0, [2]bool{false, false}},
		{"global offload", stack.CapabilityRXChecksumOffload, [2]bool{false, false}},
		{"per packet", stack.CapabilityRXChecksumOffloadPerPacket, [2]bool{false, true}},
		{"both", stack.CapabilityRXChecksumOffload | stack.CapabilityRXChecksumOffloadPerPacket, [2]bool{false, true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			other, _, otherIP := makeTestInjectableEndpoint(t, test.caps)
			endpoint.routes[tcpip.AddrFrom4([4]byte{1, 2, 3, 5})] = other.routes[otherIP]
			s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
			defer s.Destroy()
			if err := s.CreateNIC(1, endpoint); err != nil {
				t.Fatal(err)
			}
			for _, child := range endpoint.routes {
				for i, validated := range []bool{false, true} {
					pkt.RXChecksumValidated = validated
					child.InjectInbound(ipv4.ProtocolNumber, pkt)
					if got, want := pkt.RXChecksumValidated, test.want[i]; got != want {
						t.Errorf("RXChecksumValidated = %t, want %t", got, want)
					}
				}
			}
		})
	}
}

func TestInjectableEndpointDispatchHdrOnly(t *testing.T) {
	endpoint, sock, dstIP := makeTestInjectableEndpoint(t, stack.CapabilityNone)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 1,
	})
	defer pkt.DecRef()
	pkt.TransportHeader().Push(1)[0] = 0xFA
	pkt.EgressRoute.RemoteAddress = dstIP
	pkt.NetworkProtocolNumber = ipv4.ProtocolNumber

	var pkts stack.PacketBufferList
	pkts.PushBack(pkt)
	if _, err := endpoint.WritePackets(pkts); err != nil {
		t.Fatalf("Unable to write packets: %s", err)
	}
	buf := make([]byte, 6500)
	bytesRead, err := sock.Read(buf)
	if err != nil {
		t.Fatalf("Unable to read from socketpair: %v", err)
	}
	if got, want := buf[:bytesRead], []byte{0xFA}; !bytes.Equal(got, want) {
		t.Fatalf("Read %v from the socketpair, wanted %v", got, want)
	}
}

func makeTestInjectableEndpoint(t *testing.T, caps stack.LinkEndpointCapabilities) (*InjectableEndpoint, *os.File, tcpip.Address) {
	dstIP := tcpip.AddrFromSlice(net.ParseIP("1.2.3.4").To4())
	pair, err := unix.Socketpair(unix.AF_UNIX,
		unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal("Failed to create socket pair:", err)
	}
	underlyingEndpoint, err := fdbased.NewInjectable(pair[1], 6500, caps)
	if err != nil {
		t.Fatalf("fdbased.NewInjectable(%d, 6500, %v) failed: %s", pair[1], caps, err)
	}
	routes := map[tcpip.Address]stack.InjectableLinkEndpoint{dstIP: underlyingEndpoint}
	endpoint := NewInjectableEndpoint(routes)
	sock := os.NewFile(uintptr(pair[0]), "test route end")
	t.Cleanup(func() {
		sock.Close()
		unix.Close(pair[1])
	})
	return endpoint, sock, dstIP
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
