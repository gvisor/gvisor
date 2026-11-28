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
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/urpc"
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

// TestCreateLinksAndRoutesOnLinkDefaultRoute checks that a default route
// without a gateway is installed, and that it routes any destination directly
// out of its link.
func TestCreateLinksAndRoutesOnLinkDefaultRoute(t *testing.T) {
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

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair(): %v", err)
	}
	epFile := os.NewFile(uintptr(fds[0]), "proxy-ep")
	peerFile := os.NewFile(uintptr(fds[1]), "proxy-peer")
	defer epFile.Close()
	defer peerFile.Close()

	local4 := net.IPv4(192, 0, 2, 7).To4()
	local6 := net.ParseIP("2001:db8::7")
	n := &Network{Stack: s}
	args := &sentryapi.CreateLinksAndRoutesArgs{
		FilePayload: urpc.FilePayload{Files: []*os.File{epFile}},
		FDBasedLinks: []sentryapi.FDBasedLink{{
			Name: "eth0",
			MTU:  1500,
			Addresses: []sentryapi.IPWithPrefix{
				{Address: local4, PrefixLen: 32},
				{Address: local6, PrefixLen: 128},
			},
			NumChannels: 1,
			IsProxy:     true,
		}},
		Defaultv4Gateway: sentryapi.DefaultRoute{Name: "eth0", Route: sentryapi.Route{
			Destination: net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
		}},
		Defaultv6Gateway: sentryapi.DefaultRoute{Name: "eth0", Route: sentryapi.Route{
			Destination: net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}},
	}
	if err := n.CreateLinksAndRoutes(args, nil); err != nil {
		t.Fatalf("CreateLinksAndRoutes(): %v", err)
	}

	for _, tc := range []struct {
		proto  tcpip.NetworkProtocolNumber
		local  net.IP
		remote string
	}{
		{header.IPv4ProtocolNumber, local4, "198.51.100.1"},
		{header.IPv6ProtocolNumber, local6, "2001:db9::1"},
	} {
		remote := tcpip.AddrFromSlice(net.ParseIP(tc.remote))
		if tc.proto == header.IPv4ProtocolNumber {
			remote = tcpip.AddrFromSlice(net.ParseIP(tc.remote).To4())
		}
		r, err := s.FindRoute(0, tcpip.Address{}, remote, tc.proto, false)
		if err != nil {
			t.Errorf("FindRoute(%v): %v", remote, err)
			continue
		}
		// An empty next hop sends to the remote address directly.
		if r.RemoteAddress() != remote || r.NextHop() != (tcpip.Address{}) || r.LocalAddress() != tcpip.AddrFromSlice(tc.local) {
			t.Errorf("route to %v has remote %v, next hop %q and local address %v, want %v, none and %v", remote, r.RemoteAddress(), r.NextHop(), r.LocalAddress(), remote, tc.local)
		}
		r.Release()
	}
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
