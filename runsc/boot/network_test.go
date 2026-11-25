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

package boot

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/pkg/waiter"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
)

type testUniqueIDProvider struct {
	next atomicbitops.Uint64
}

func (p *testUniqueIDProvider) UniqueID() uint64 {
	return p.next.Add(1)
}

func buildICMPv4EchoPacket(src, dst tcpip.Address) []byte {
	totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize
	buf := make([]byte, totalLen)
	icmpPkt := header.ICMPv4(buf[header.IPv4MinimumSize:])
	icmpPkt.SetType(header.ICMPv4Echo)
	icmpPkt.SetCode(header.ICMPv4UnusedCode)
	icmpPkt.SetChecksum(0)
	icmpPkt.SetChecksum(^checksum.Checksum(icmpPkt, 0))
	ip := header.IPv4(buf[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		Protocol:    uint8(icmp.ProtocolNumber4),
		TTL:         64,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	return buf
}

func buildICMPv6EchoPacket(src, dst tcpip.Address) []byte {
	totalLen := header.IPv6MinimumSize + header.ICMPv6MinimumSize
	buf := make([]byte, totalLen)
	icmpPkt := header.ICMPv6(buf[header.IPv6MinimumSize:])
	icmpPkt.SetType(header.ICMPv6EchoRequest)
	icmpPkt.SetCode(header.ICMPv6UnusedCode)
	icmpPkt.SetChecksum(0)
	icmpPkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpPkt,
		Src:    src,
		Dst:    dst,
	}))
	ip := header.IPv6(buf[:header.IPv6MinimumSize])
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     header.ICMPv6MinimumSize,
		TransportProtocol: icmp.ProtocolNumber6,
		HopLimit:          64,
		SrcAddr:           src,
		DstAddr:           dst,
	})
	return buf
}

func wrapEthernetFrame(dstMAC, srcMAC tcpip.LinkAddress, proto tcpip.NetworkProtocolNumber, payload []byte) []byte {
	frame := make([]byte, header.EthernetMinimumSize+len(payload))
	header.Ethernet(frame[:header.EthernetMinimumSize]).Encode(&header.EthernetFields{
		SrcAddr: srcMAC,
		DstAddr: dstMAC,
		Type:    proto,
	})
	copy(frame[header.EthernetMinimumSize:], payload)
	return frame
}

func waitForStatIncrement(t *testing.T, name string, stat *tcpip.StatCounter, baseline uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if stat.Value() >= baseline+1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to increment from %d (got %d)", name, baseline, stat.Value())
}

func TestCreateLinksAndRoutesExternalLoopback(t *testing.T) {
	proxyIPv4 := net.IPv4(10, 0, 0, 2).To4()
	proxyIPv6 := net.ParseIP("fd00::2").To16()
	ethIPv4 := net.IPv4(192, 168, 1, 2).To4()
	loopbackIPv4 := tcpip.AddrFrom4([4]byte{127, 0, 0, 11})
	ethMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	peerMAC := tcpip.LinkAddress([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})

	for _, tc := range []struct {
		name                         string
		allowExternalLoopbackTraffic bool
	}{
		{
			name:                         "enabled",
			allowExternalLoopbackTraffic: true,
		},
		{
			name:                         "disabled",
			allowExternalLoopbackTraffic: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creator := &sandboxNetstackCreator{
				clock: tcpip.NewStdClock(),
				uid:   &testUniqueIDProvider{},
			}
			inetStack, err := creator.CreateStack()
			if err != nil {
				t.Fatalf("CreateStack(): %v", err)
			}
			s := inetStack.(*netstack.Stack).Stack
			defer s.Destroy()

			proxyFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
			if err != nil {
				t.Fatalf("Socketpair(proxy): %v", err)
			}
			proxyEPFile := os.NewFile(uintptr(proxyFDs[0]), "proxy-ep")
			proxyPeerFile := os.NewFile(uintptr(proxyFDs[1]), "proxy-peer")
			defer proxyEPFile.Close()
			defer proxyPeerFile.Close()

			ethFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
			if err != nil {
				t.Fatalf("Socketpair(eth0): %v", err)
			}
			ethEPFile := os.NewFile(uintptr(ethFDs[0]), "eth0-ep")
			ethPeerFile := os.NewFile(uintptr(ethFDs[1]), "eth0-peer")
			defer ethEPFile.Close()
			defer ethPeerFile.Close()

			n := &Network{Stack: s}
			args := &sentryapi.CreateLinksAndRoutesArgs{
				FilePayload: urpc.FilePayload{
					Files: []*os.File{proxyEPFile, ethEPFile},
				},
				FDBasedLinks: []sentryapi.FDBasedLink{
					{
						Name: "proxy",
						MTU:  1500,
						Addresses: []sentryapi.IPWithPrefix{
							{Address: proxyIPv4, PrefixLen: 24},
							{Address: proxyIPv6, PrefixLen: 64},
						},
						NumChannels:   1,
						IsPacket:      []bool{false},
						PreConfigured: true,
						IsProxy:       true,
					},
					{
						Name:        "eth0",
						MTU:         1500,
						LinkAddress: ethMAC,
						Addresses: []sentryapi.IPWithPrefix{
							{Address: ethIPv4, PrefixLen: 24},
						},
						NumChannels:   1,
						IsPacket:      []bool{false},
						PreConfigured: true,
						IsProxy:       false,
					},
				},
				AllowExternalLoopbackTraffic: tc.allowExternalLoopbackTraffic,
			}
			if err := n.CreateLinksAndRoutes(args, nil); err != nil {
				t.Fatalf("CreateLinksAndRoutes(): %v", err)
			}

			// Stack-wide IPv4 AllowExternalLoopbackTrafficOption must remain false
			// even when AllowExternalLoopbackTraffic is enabled for the UDS proxy.
			var opt tcpip.AllowExternalLoopbackTrafficOption
			if err := s.NetworkProtocolOption(ipv4.ProtocolNumber, &opt); err != nil {
				t.Fatalf("NetworkProtocolOption(ipv4, AllowExternalLoopbackTrafficOption): %v", err)
			}
			if bool(opt) {
				t.Errorf("stack-wide IPv4 AllowExternalLoopbackTrafficOption = true, want false")
			}

			invalidSrc := s.Stats().IP.InvalidSourceAddressesReceived
			delivered := s.Stats().IP.PacketsDelivered

			// 1. IPv4 loopback-sourced packet on the proxy link.
			beforeDelivered := delivered.Value()
			beforeInvalidSrc := invalidSrc.Value()
			v4ProxyPkt := buildICMPv4EchoPacket(loopbackIPv4, tcpip.AddrFromSlice(proxyIPv4))
			if _, err := proxyPeerFile.Write(v4ProxyPkt); err != nil {
				t.Fatalf("proxyPeerFile.Write(v4): %v", err)
			}
			if tc.allowExternalLoopbackTraffic {
				waitForStatIncrement(t, "PacketsDelivered", delivered, beforeDelivered)
				if got := invalidSrc.Value() - beforeInvalidSrc; got != 0 {
					t.Errorf("proxy IPv4 loopback src InvalidSourceAddressesReceived delta = %d, want 0", got)
				}
			} else {
				waitForStatIncrement(t, "InvalidSourceAddressesReceived", invalidSrc, beforeInvalidSrc)
				if got := delivered.Value() - beforeDelivered; got != 0 {
					t.Errorf("proxy IPv4 loopback src PacketsDelivered delta = %d, want 0", got)
				}
			}

			// 2. IPv6 loopback-sourced packet on the proxy link must always be rejected.
			beforeDelivered = delivered.Value()
			beforeInvalidSrc = invalidSrc.Value()
			v6ProxyPkt := buildICMPv6EchoPacket(header.IPv6Loopback, tcpip.AddrFromSlice(proxyIPv6))
			if _, err := proxyPeerFile.Write(v6ProxyPkt); err != nil {
				t.Fatalf("proxyPeerFile.Write(v6): %v", err)
			}
			waitForStatIncrement(t, "InvalidSourceAddressesReceived", invalidSrc, beforeInvalidSrc)
			if got := delivered.Value() - beforeDelivered; got != 0 {
				t.Errorf("proxy IPv6 loopback src PacketsDelivered delta = %d, want 0", got)
			}

			// 3. IPv4 loopback-sourced packet on an extra non-proxy link must always be rejected.
			beforeDelivered = delivered.Value()
			beforeInvalidSrc = invalidSrc.Value()
			v4EthFrame := wrapEthernetFrame(
				tcpip.LinkAddress(ethMAC),
				peerMAC,
				header.IPv4ProtocolNumber,
				buildICMPv4EchoPacket(loopbackIPv4, tcpip.AddrFromSlice(ethIPv4)),
			)
			if _, err := ethPeerFile.Write(v4EthFrame); err != nil {
				t.Fatalf("ethPeerFile.Write(v4): %v", err)
			}
			waitForStatIncrement(t, "InvalidSourceAddressesReceived", invalidSrc, beforeInvalidSrc)
			if got := delivered.Value() - beforeDelivered; got != 0 {
				t.Errorf("eth0 IPv4 loopback src PacketsDelivered delta = %d, want 0", got)
			}
		})
	}
}

// noARPLink holds a sandbox stack with one fdbased link that does not resolve
// link addresses, and the peer end of the link.
type noARPLink struct {
	s    *stack.Stack
	peer *os.File
	nic  tcpip.NICID
}

var (
	noARPZeroMAC = tcpip.LinkAddress(make([]byte, header.EthernetAddressSize))
	noARPPeerMAC = tcpip.LinkAddress([]byte{0x02, 0, 0, 0, 0, 0x09})
)

func newNoARPLink(t *testing.T) *noARPLink {
	t.Helper()
	creator := &sandboxNetstackCreator{clock: tcpip.NewStdClock(), uid: &testUniqueIDProvider{}}
	inetStack, err := creator.CreateStack()
	if err != nil {
		t.Fatalf("CreateStack(): %v", err)
	}
	s := inetStack.(*netstack.Stack).Stack

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	epFile := os.NewFile(uintptr(fds[0]), "eth0-ep")
	peer := os.NewFile(uintptr(fds[1]), "eth0-peer")
	// Destroy the stack before closing the peer: the dispatcher does not
	// stop on EOF.
	t.Cleanup(func() { epFile.Close(); peer.Close() })
	t.Cleanup(s.Destroy)

	n := &Network{Stack: s}
	args := &sentryapi.CreateLinksAndRoutesArgs{
		FilePayload: urpc.FilePayload{Files: []*os.File{epFile}},
		FDBasedLinks: []sentryapi.FDBasedLink{{
			Name:        "eth0",
			MTU:         1500,
			Multicast:   true,
			LinkAddress: make(net.HardwareAddr, header.EthernetAddressSize),
			NoARP:       true,
			Addresses: []sentryapi.IPWithPrefix{
				{Address: net.IPv4(10, 0, 0, 2).To4(), PrefixLen: 24},
				{Address: net.ParseIP("fd00::2"), PrefixLen: 64},
			},
			Routes: []sentryapi.Route{
				{Destination: net.IPNet{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.CIDRMask(24, 32)}},
				{Destination: net.IPNet{IP: net.ParseIP("fd00::"), Mask: net.CIDRMask(64, 128)}},
				{Destination: net.IPNet{IP: net.IPv4(224, 0, 0, 0).To4(), Mask: net.CIDRMask(4, 32)}},
				{Destination: net.IPNet{IP: net.ParseIP("ff00::"), Mask: net.CIDRMask(8, 128)}},
			},
			NumChannels:   1,
			IsPacket:      []bool{false},
			PreConfigured: true,
		}},
		Defaultv4Gateway: sentryapi.DefaultRoute{Name: "eth0", Route: sentryapi.Route{
			Destination: net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			Gateway:     net.IPv4(10, 0, 0, 1).To4(),
		}},
		Defaultv6Gateway: sentryapi.DefaultRoute{Name: "eth0", Route: sentryapi.Route{
			Destination: net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			Gateway:     net.ParseIP("fd00::1"),
		}},
	}
	if err := n.CreateLinksAndRoutes(args, nil); err != nil {
		t.Fatalf("CreateLinksAndRoutes(): %v", err)
	}
	for id, info := range s.NICInfo() {
		if info.Name == "eth0" {
			return &noARPLink{s: s, peer: peer, nic: id}
		}
	}
	t.Fatalf("no NIC named eth0 in %v", s.NICInfo())
	return nil
}

// nextFrame returns the first frame from the sandbox that is ARP, an NDP
// neighbor solicitation, or carries the given transport protocol.
func (l *noARPLink) nextFrame(t *testing.T, transport uint8) header.Ethernet {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ms := int(time.Until(deadline).Milliseconds())
		if ms <= 0 {
			t.Fatalf("timed out waiting for a frame")
		}
		pfd := []unix.PollFd{{Fd: int32(l.peer.Fd()), Events: unix.POLLIN}}
		n, err := unix.Poll(pfd, ms)
		if err == unix.EINTR || n == 0 {
			continue
		}
		if err != nil {
			t.Fatalf("Poll: %v", err)
		}
		b := make([]byte, 2048)
		n, err = unix.Read(int(l.peer.Fd()), b)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		eth := header.Ethernet(b[:n])
		switch eth.Type() {
		case header.ARPProtocolNumber:
			return eth
		case header.IPv4ProtocolNumber:
			if header.IPv4(eth[header.EthernetMinimumSize:]).Protocol() == transport {
				return eth
			}
		case header.IPv6ProtocolNumber:
			ip := header.IPv6(eth[header.EthernetMinimumSize:])
			if ip.NextHeader() == uint8(header.ICMPv6ProtocolNumber) &&
				header.ICMPv6(ip.Payload()).Type() == header.ICMPv6NeighborSolicit {
				return eth
			}
			if ip.NextHeader() == transport {
				return eth
			}
		}
	}
}

func (l *noARPLink) inject(t *testing.T, proto tcpip.NetworkProtocolNumber, pkt []byte) {
	t.Helper()
	if _, err := l.peer.Write(wrapEthernetFrame(noARPZeroMAC, noARPPeerMAC, proto, pkt)); err != nil {
		t.Fatalf("Write: %v", err)
	}
}

// sendUDP sends a UDP datagram from the sandbox stack to addr.
func (l *noARPLink) sendUDP(t *testing.T, proto tcpip.NetworkProtocolNumber, addr tcpip.Address, port uint16) {
	t.Helper()
	var wq waiter.Queue
	ep, err := l.s.NewEndpoint(udp.ProtocolNumber, proto, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint: %s", err)
	}
	t.Cleanup(ep.Close)
	ep.SocketOptions().SetBroadcast(true)
	to := tcpip.FullAddress{NIC: l.nic, Addr: addr, Port: port}
	if _, err := ep.Write(bytes.NewReader([]byte("hello")), tcpip.WriteOptions{To: &to}); err != nil {
		t.Fatalf("Write: %s", err)
	}
}

// TestCreateLinksAndRoutesNoARP checks the frames that the sandbox sends on a
// link created with FDBasedLink.NoARP. The expected destination addresses are
// those that Linux uses on an IFF_NOARP Ethernet device: the multicast address
// for multicast, and the device's own address for everything else.
func TestCreateLinksAndRoutesNoARP(t *testing.T) {
	own := noARPZeroMAC
	for _, tc := range []struct {
		name    string
		send    func(t *testing.T, l *noARPLink)
		proto   tcpip.NetworkProtocolNumber
		l4      uint8
		wantDst tcpip.LinkAddress
	}{
		{
			name: "IPv4 via gateway",
			send: func(t *testing.T, l *noARPLink) {
				l.inject(t, header.IPv4ProtocolNumber, buildICMPv4EchoPacket(tcpip.AddrFrom4([4]byte{192, 0, 2, 5}), tcpip.AddrFrom4([4]byte{10, 0, 0, 2})))
			},
			proto: header.IPv4ProtocolNumber, l4: uint8(header.ICMPv4ProtocolNumber), wantDst: own,
		},
		{
			name: "IPv4 on link",
			send: func(t *testing.T, l *noARPLink) {
				l.inject(t, header.IPv4ProtocolNumber, buildICMPv4EchoPacket(tcpip.AddrFrom4([4]byte{10, 0, 0, 7}), tcpip.AddrFrom4([4]byte{10, 0, 0, 2})))
			},
			proto: header.IPv4ProtocolNumber, l4: uint8(header.ICMPv4ProtocolNumber), wantDst: own,
		},
		{
			name: "IPv6 via gateway",
			send: func(t *testing.T, l *noARPLink) {
				l.inject(t, header.IPv6ProtocolNumber, buildICMPv6EchoPacket(tcpip.AddrFrom16Slice(net.ParseIP("2001:db8::5")), tcpip.AddrFrom16Slice(net.ParseIP("fd00::2"))))
			},
			proto: header.IPv6ProtocolNumber, l4: uint8(header.ICMPv6ProtocolNumber), wantDst: own,
		},
		{
			name: "IPv6 on link",
			send: func(t *testing.T, l *noARPLink) {
				l.inject(t, header.IPv6ProtocolNumber, buildICMPv6EchoPacket(tcpip.AddrFrom16Slice(net.ParseIP("fd00::7")), tcpip.AddrFrom16Slice(net.ParseIP("fd00::2"))))
			},
			proto: header.IPv6ProtocolNumber, l4: uint8(header.ICMPv6ProtocolNumber), wantDst: own,
		},
		{
			name: "IPv4 limited broadcast",
			send: func(t *testing.T, l *noARPLink) {
				l.sendUDP(t, header.IPv4ProtocolNumber, tcpip.AddrFrom4([4]byte{255, 255, 255, 255}), 67)
			},
			proto: header.IPv4ProtocolNumber, l4: uint8(header.UDPProtocolNumber), wantDst: own,
		},
		{
			name: "IPv4 subnet broadcast",
			send: func(t *testing.T, l *noARPLink) {
				l.sendUDP(t, header.IPv4ProtocolNumber, tcpip.AddrFrom4([4]byte{10, 0, 0, 255}), 67)
			},
			proto: header.IPv4ProtocolNumber, l4: uint8(header.UDPProtocolNumber), wantDst: own,
		},
		{
			name: "IPv4 multicast",
			send: func(t *testing.T, l *noARPLink) {
				l.sendUDP(t, header.IPv4ProtocolNumber, tcpip.AddrFrom4([4]byte{224, 0, 0, 251}), 5353)
			},
			proto: header.IPv4ProtocolNumber, l4: uint8(header.UDPProtocolNumber),
			wantDst: tcpip.LinkAddress([]byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}),
		},
		{
			name: "IPv6 multicast",
			send: func(t *testing.T, l *noARPLink) {
				l.sendUDP(t, header.IPv6ProtocolNumber, tcpip.AddrFrom16Slice(net.ParseIP("ff02::fb")), 5353)
			},
			proto: header.IPv6ProtocolNumber, l4: uint8(header.UDPProtocolNumber),
			wantDst: tcpip.LinkAddress([]byte{0x33, 0x33, 0x00, 0x00, 0x00, 0xfb}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newNoARPLink(t)
			tc.send(t, l)
			eth := l.nextFrame(t, tc.l4)
			if got := eth.Type(); got != tc.proto {
				t.Fatalf("got a frame of type %v (destination %v), want type %v", got, eth.DestinationAddress(), tc.proto)
			}
			if got := eth.DestinationAddress(); got != tc.wantDst {
				t.Errorf("DestinationAddress() = %v, want %v", got, tc.wantDst)
			}
			if got := eth.SourceAddress(); got != own {
				t.Errorf("SourceAddress() = %v, want %v", got, own)
			}
		})
	}
}
