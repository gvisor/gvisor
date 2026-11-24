// Copyright 2021 The gVisor Authors.
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

package bridge_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/link/veth"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestWritePacketFromBridge(t *testing.T) {
	const (
		channelLinkAddr1 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x05")
		channelLinkAddr2 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		remoteLinkAddr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
		bridgeLinkAddr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")

		netProto = 55
		nicID1   = 5
		nicID2   = 6
		bridgeID = 7
	)

	// Create two channel-based endpoints as receivers, they are both
	// bound to the same bridge device and are both expected to receive the
	// packets that are written by the bridge.
	ch1 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr1)
	ch2 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr2)
	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	s := stack.New(stack.Options{})

	if err := s.CreateNIC(nicID1, ethernet.New(ch1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID1, err)
	}
	if err := s.CreateNIC(nicID2, ethernet.New(ch2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID2, err)
	}
	if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}
	if err := s.SetNICCoordinator(nicID1, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID1, bridgeID)
	}
	if err := s.SetNICCoordinator(nicID2, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID2, bridgeID)
	}
	// When writing packets, the bridge will try all available bridge ports.
	if err := s.WritePacketToRemote(bridgeID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	for _, c := range []*channel.Endpoint{ch1, ch2} {
		pkt := c.Read()
		if pkt == nil {
			t.Fatal("expected to read a packet")
		}

		eth := header.Ethernet(pkt.LinkHeader().Slice())
		pkt.DecRef()
		if got := eth.SourceAddress(); got != bridgeLinkAddr {
			t.Errorf("got eth.SourceAddress() = %s, want = %s", got, bridgeLinkAddr)
		}
		if got := eth.DestinationAddress(); got != remoteLinkAddr {
			t.Errorf("got eth.DestinationAddress() = %s, want = %s", got, remoteLinkAddr)
		}
		if got := eth.Type(); got != netProto {
			t.Errorf("got eth.Type() = %d, want = %d", got, netProto)
		}
	}
}

type testNotification struct {
	ch chan bool
}

func (n *testNotification) WriteNotify() {
	n.ch <- true
}

// The test verifies that packates that are forwarded by
// a bridge will flooded to all bridge ports.
func TestWritePacketBetweenDevices(t *testing.T) {
	const (
		channelLinkAddr1 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x04")
		channelLinkAddr2 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x05")
		vethLinkAddr1    = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		vethLinkAddr2    = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
		remoteLinkAddr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")
		bridgeLinkAddr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x09")

		netProto = 55
		nicID1   = 4
		nicID2   = 5
		vethID   = 6
		bridgeID = 9
	)
	// Creates a pair of veth devices which will be attached to different
	// network stacks.
	veth1, veth2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	veth1.SetLinkAddress(vethLinkAddr1)
	veth2.SetLinkAddress(vethLinkAddr2)
	ch1 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr1)
	ch2 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr2)

	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	s := stack.New(stack.Options{})
	secondStack := stack.New(stack.Options{})
	if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}
	if err := s.CreateNIC(nicID1, ethernet.New(ch1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID1, err)
	}
	if err := s.SetNICCoordinator(nicID1, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID1, bridgeID)
	}
	if err := s.CreateNIC(nicID2, ethernet.New(ch2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID2, err)
	}
	if err := s.SetNICCoordinator(nicID2, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID2, bridgeID)
	}
	if err := s.CreateNIC(vethID, ethernet.New(veth1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethID, err)
	}
	// Attach one veth device to stack s, and attach the other
	// veth to stack secondStack.
	if err := s.SetNICCoordinator(vethID, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator")
	}
	if err := secondStack.CreateNIC(vethID, ethernet.New(veth2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethID, err)
	}

	n1 := &testNotification{ch: make(chan bool, 1)}
	n2 := &testNotification{ch: make(chan bool, 1)}
	ch1.AddNotify(n1)
	ch2.AddNotify(n2)
	// Write a packet to the veth device at the stack secondStack, the packet
	// will be available at the veth device at the stack s.
	if err := secondStack.WritePacketToRemote(vethID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	<-n1.ch
	<-n2.ch
	// No FDB entry, a package floods all bridge ports except the port that
	// is attached to the veth device.
	for _, c := range []*channel.Endpoint{ch1, ch2} {
		pkt := c.Read()
		if pkt == nil {
			t.Fatal("expected to read a packet")
		}

		pkt.LinkHeader().Consume(header.EthernetMinimumSize)
		eth := header.Ethernet(pkt.LinkHeader().Slice())
		pkt.DecRef()
		if got := eth.SourceAddress(); got != vethLinkAddr2 {
			t.Errorf("got eth.SourceAddress() = %s, want = %s", got, vethLinkAddr2)
		}
		if got := eth.DestinationAddress(); got != remoteLinkAddr {
			t.Errorf("got eth.DestinationAddress() = %s, want = %s", got, remoteLinkAddr)
		}
		if got := eth.Type(); got != netProto {
			t.Errorf("got eth.Type() = %d, want = %d", got, netProto)
		}
	}
}

func TestBridgeFDB(t *testing.T) {
	const (
		channelLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x03")
		remoteLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")
		bridgeLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x09")

		netProto = 55
		nicID    = 4
		vethID1  = 7
		vethID2  = 8
		bridgeID = 9
	)
	veth1, veth2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	ch := channel.New(1, header.EthernetMinimumSize, channelLinkAddr)
	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	s := stack.New(stack.Options{})
	secondStack := stack.New(stack.Options{})

	if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}
	if err := s.CreateNIC(nicID, ethernet.New(ch)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}
	if err := s.SetNICCoordinator(nicID, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID, bridgeID)
	}
	if err := s.CreateNIC(vethID1, ethernet.New(veth1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethID1, err)
	}
	if err := s.SetNICCoordinator(vethID1, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", vethID1, bridgeID)
	}
	if err := secondStack.CreateNIC(vethID2, ethernet.New(veth2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethID2, err)
	}
	n := &testNotification{ch: make(chan bool, 1)}
	ch.AddNotify(n)
	// Write a packet to the veth device at secondStack, the
	// packet will be available at stack s via veth.
	if err := secondStack.WritePacketToRemote(vethID2, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	<-n.ch
	pkt := ch.Read()
	defer pkt.DecRef()
	if pkt == nil {
		t.Fatal("expected to read a packet")
	}
	// When forwarding the packet via the bridge device, the packet's
	// source MAC address will be used as lookup key to the bridge
	// FDB.
	var e stack.BridgeFDBEntry
	start := time.Now()
	for {
		e = bridgeEndpoint.FindFDBEntry(veth2.LinkAddress())
		if len(e.PortLinkAddress()) != 0 {
			break
		}
		if time.Since(start) > 30*time.Second {
			t.Fatalf("failed to find FDB entry for %s after 30 seconds", veth2.LinkAddress())
		}
		time.Sleep(time.Second)
	}
	if e.PortLinkAddress() != veth1.LinkAddress() {
		t.Fatalf("bridgeEndpoint.FindFDBEntry(%s) = %s, want = %s", veth2.LinkAddress(), e.PortLinkAddress(), veth1.LinkAddress())
	}
	// No FDB entry is expected for devices other than veth1.
	if e := bridgeEndpoint.FindFDBEntry(channelLinkAddr); len(e.PortLinkAddress()) != 0 {
		t.Fatalf("bridgeEndpoint.FindFDBEntry(%s) = %s, want = \"\"", channelLinkAddr, e.PortLinkAddress())
	}
}

func TestSetCoordinator(t *testing.T) {
	const (
		bridgeLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")
		bridgeID       = 6
	)

	s := stack.New(stack.Options{})
	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}
	if err := s.SetNICCoordinator(bridgeID, bridgeID); err == nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d) = %s, want = %s", bridgeID, bridgeID, err, tcpip.ErrNoSuchFile{})
	}
}

type testPacketEndpoint struct {
	count int
}

func (p *testPacketEndpoint) HandlePacket(tcpip.NICID, tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	p.count++
}

func TestNicExitingStackExitsBridgeToo(t *testing.T) {
	const (
		netProto        = 55
		nicID           = 5
		bridgeID        = 7
		bridgeLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x09")
		channelLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x04")
		remoteLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
	)

	src := stack.New(stack.Options{})
	defer src.Destroy()

	// Create a bridge in src.
	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	if err := src.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}

	// Create a channel-endpoint-based nic in src with non-default options so we
	// also verify SetNICStack preserves Context, DeliverLinkPackets,
	// EnableExperimentIPOption, and AllowExternalIPv4LoopbackTraffic.
	const wantContext = "port-nic-context"
	ch := channel.New(2, header.EthernetMinimumSize, channelLinkAddr)
	if err := src.CreateNICWithOptions(nicID, ethernet.New(ch), stack.NICOptions{
		Name:                             "port0",
		Context:                          wantContext,
		DeliverLinkPackets:               true,
		EnableExperimentIPOption:         true,
		AllowExternalIPv4LoopbackTraffic: true,
	}); err != nil {
		t.Fatalf("src.CreateNICWithOptions(%d, _): %s", nicID, err)
	}
	// And add it to the bridge.
	if err := src.SetNICCoordinator(nicID, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID, bridgeID)
	}

	// The bridge should forward pkts to the nic.
	if err := src.WritePacketToRemote(bridgeID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	pkt := ch.Read()
	if pkt == nil {
		t.Fatal("expected to read a packet")
	}
	pkt.DecRef()

	// Now move the nic into dst.
	dst := stack.New(stack.Options{})
	defer dst.Destroy()
	dstNICID, err := src.SetNICStack(nicID, dst, "")
	if err != nil {
		t.Fatalf("s.SetNICStack(%d, %p) = %s, want nil", nicID, dst, err)
	}

	// Verify Context, EnableExperimentIPOption, AllowExternalIPv4LoopbackTraffic,
	// and DeliverLinkPackets were preserved on the moved NIC in dst.
	info, ok := dst.SingleNICInfo(dstNICID)
	if !ok {
		t.Fatalf("dst.SingleNICInfo(%d) = (_, false), want true", dstNICID)
	}
	if info.Context != wantContext {
		t.Errorf("dst.SingleNICInfo(%d).Context = %v, want %q", dstNICID, info.Context, wantContext)
	}
	dstNIC, nicErr := dst.GetNICByID(dstNICID)
	if nicErr != nil {
		t.Fatalf("dst.GetNICByID(%d) = (_, %s), want nil", dstNICID, nicErr)
	}
	if !dstNIC.GetExperimentIPOptionEnabled() {
		t.Errorf("dstNIC.GetExperimentIPOptionEnabled() = false, want true")
	}
	if !dstNIC.AllowExternalIPv4LoopbackTraffic() {
		t.Errorf("dstNIC.AllowExternalIPv4LoopbackTraffic() = false, want true")
	}
	var pktEP testPacketEndpoint
	if err := dst.RegisterPacketEndpoint(dstNICID, header.EthernetProtocolAll, &pktEP); err != nil {
		t.Fatalf("dst.RegisterPacketEndpoint(%d, _): %s", dstNICID, err)
	}
	defer dst.UnregisterPacketEndpoint(dstNICID, header.EthernetProtocolAll, &pktEP)
	if err := dst.WritePacketToRemote(dstNICID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("dst.WritePacketToRemote(%d, %s, _): %s", dstNICID, remoteLinkAddr, err)
	}
	if pkt := ch.Read(); pkt != nil {
		pkt.DecRef()
	}
	if pktEP.count != 1 {
		t.Errorf("pktEP.count = %d, want 1 (DeliverLinkPackets preserved)", pktEP.count)
	}

	// The bridge should no longer forward pkts to the nic, lest it defeat the purpose of network
	// namespaces.
	if err := src.WritePacketToRemote(bridgeID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	pkt = ch.Read()
	if pkt != nil {
		pkt.DecRef()
		t.Fatal("did not expect to read a packet")
	}
}

// makeEthernetFrame builds an inbound frame whose ethernet header is still in
// the payload, for injection into a channel endpoint wrapped by ethernet.New.
func makeEthernetFrame(src, dst tcpip.LinkAddress, proto tcpip.NetworkProtocolNumber, payload []byte) *stack.PacketBuffer {
	frame := make([]byte, header.EthernetMinimumSize+len(payload))
	header.Ethernet(frame).Encode(&header.EthernetFields{
		SrcAddr: src,
		DstAddr: dst,
		Type:    proto,
	})
	copy(frame[header.EthernetMinimumSize:], payload)
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
	})
}

// drainChannels releases every packet queued on the given endpoints.
func drainChannels(eps ...*channel.Endpoint) {
	for _, ep := range eps {
		for pkt := ep.Read(); pkt != nil; pkt = ep.Read() {
			pkt.DecRef()
		}
	}
}

const (
	dispatchPort1Addr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x10")
	dispatchPort2Addr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x11")
	dispatchBridgeAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x12")
	dispatchUnknownAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x13")
	// dispatchRemoteAddr is a host the bridge learns behind port 2.
	dispatchRemoteAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x14")
	// dispatchSrcAddr is a host behind port 1 that sends the test frames.
	dispatchSrcAddr       = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x15")
	dispatchMulticastAddr = tcpip.LinkAddress("\x01\x00\x5e\x00\x00\x01")
	dispatchNewPort1Addr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x16")
	dispatchNewPort2Addr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x17")
	dispatchPort1ID       = 11
	dispatchPort2ID       = 12
	dispatchBridgeID      = 13
)

var (
	dispatchBridgeIP = tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	dispatchSrcIP    = tcpip.AddrFrom4([4]byte{192, 0, 2, 2})
)

// dispatchTestContext is a bridge with two ports. It records the packet type
// of every frame the bridge passes up.
type dispatchTestContext struct {
	s        *stack.Stack
	bridge   *stack.BridgeEndpoint
	ch1, ch2 *channel.Endpoint
	// classifying is whether port 1 classifies frames itself, as the ethernet
	// wrapper does. Otherwise port 1 behaves like a tap, fdbased, xdp or
	// sharedmem port, which leave the packet type unset.
	classifying bool
	passedUp    []tcpip.PacketType
}

// HandlePacket implements stack.PacketEndpoint.
func (c *dispatchTestContext) HandlePacket(_ tcpip.NICID, _ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	c.passedUp = append(c.passedUp, pkt.PktType)
}

func newDispatchTestContext(t *testing.T, classifying bool) *dispatchTestContext {
	t.Helper()
	c := &dispatchTestContext{
		bridge:      stack.NewBridgeEndpoint(1500),
		ch1:         channel.New(1, 1500, dispatchPort1Addr),
		ch2:         channel.New(1, 1500, dispatchPort2Addr),
		classifying: classifying,
	}
	c.bridge.SetLinkAddress(dispatchBridgeAddr)
	c.s = stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
	})
	t.Cleanup(func() {
		drainChannels(c.ch1, c.ch2)
		c.ch1.Close()
		c.ch2.Close()
		c.s.Destroy()
	})
	if err := c.s.CreateNICWithOptions(dispatchBridgeID, c.bridge, stack.NICOptions{DeliverLinkPackets: true}); err != nil {
		t.Fatalf("s.CreateNICWithOptions(%d, _, _): %s", dispatchBridgeID, err)
	}
	port1 := stack.LinkEndpoint(c.ch1)
	if classifying {
		port1 = ethernet.New(c.ch1)
	}
	if err := c.s.CreateNIC(dispatchPort1ID, port1); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", dispatchPort1ID, err)
	}
	if err := c.s.CreateNIC(dispatchPort2ID, ethernet.New(c.ch2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", dispatchPort2ID, err)
	}
	for _, id := range []tcpip.NICID{dispatchPort1ID, dispatchPort2ID} {
		if err := c.s.SetNICCoordinator(id, dispatchBridgeID); err != nil {
			t.Fatalf("s.SetNICCoordinator(%d, %d): %s", id, dispatchBridgeID, err)
		}
	}
	if err := c.s.RegisterPacketEndpoint(dispatchBridgeID, header.EthernetProtocolAll, c); err != nil {
		t.Fatalf("s.RegisterPacketEndpoint(%d, _, _): %s", dispatchBridgeID, err)
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: dispatchBridgeIP, PrefixLen: 24},
	}
	if err := c.s.AddProtocolAddress(dispatchBridgeID, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", dispatchBridgeID, protocolAddr, err)
	}

	// Learn a host behind port 2 so that frames to it are forwarded, not
	// flooded.
	learn := makeEthernetFrame(dispatchRemoteAddr, dispatchUnknownAddr, header.IPv4ProtocolNumber, nil)
	c.ch2.InjectInbound(header.IPv4ProtocolNumber, learn)
	learn.DecRef()
	drainChannels(c.ch1, c.ch2)
	return c
}

// injectFromPort1 injects a frame into port 1. A port
// that doesn't classify frames delivers them with the ethernet header already
// in the link header, as a tap does.
func (c *dispatchTestContext) injectFromPort1(src, dst tcpip.LinkAddress, proto tcpip.NetworkProtocolNumber, payload []byte) {
	pkt := makeEthernetFrame(src, dst, proto, payload)
	defer pkt.DecRef()
	if !c.classifying {
		pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	}
	c.ch1.InjectInbound(proto, pkt)
}

type dispatchTest struct {
	name string
	dst  tcpip.LinkAddress
	// wantUpcall is whether the bridge passes the frame up, and wantPktType
	// the packet type it is passed up with.
	wantUpcall  bool
	wantPktType tcpip.PacketType
	// wantIP is whether IPv4 counts the frame as received.
	wantIP bool
	// wantFwd is whether port 2 sends out the frame.
	wantFwd bool
}

// check injects an IPv4 frame for test.dst into port 1 and checks what the
// bridge does with it.
func (c *dispatchTestContext) check(t *testing.T, test dispatchTest) {
	t.Helper()
	c.passedUp = nil
	ipRx := c.s.Stats().IP.PacketsReceived
	ipBefore := ipRx.Value()
	c.injectFromPort1(dispatchSrcAddr, test.dst, header.IPv4ProtocolNumber, nil)

	switch {
	case !test.wantUpcall && len(c.passedUp) != 0:
		t.Errorf("got frames passed up with packet types %v, want none", c.passedUp)
	case test.wantUpcall && (len(c.passedUp) != 1 || c.passedUp[0] != test.wantPktType):
		t.Errorf("got frames passed up with packet types %v, want [%d]", c.passedUp, test.wantPktType)
	}
	var wantIP uint64
	if test.wantIP {
		wantIP = 1
	}
	if got := ipRx.Value() - ipBefore; got != wantIP {
		t.Errorf("got %d frames received by IPv4, want %d", got, wantIP)
	}
	if fwd := c.ch2.Read(); fwd == nil {
		if test.wantFwd {
			t.Error("frame was not forwarded to port 2")
		}
	} else {
		if !test.wantFwd {
			t.Error("frame was forwarded to port 2")
		}
		fwd.LinkHeader().Consume(header.EthernetMinimumSize)
		if got := header.Ethernet(fwd.LinkHeader().Slice()).DestinationAddress(); got != test.dst {
			t.Errorf("got forwarded destination = %s, want = %s", got, test.dst)
		}
		fwd.DecRef()
	}
	drainChannels(c.ch1, c.ch2)
}

// portKinds runs a test with port 1 wrapped by the ethernet endpoint, which
// classifies frames, and with a bare port, which doesn't.
var portKinds = []struct {
	name        string
	classifying bool
}{
	{name: "ethernet port", classifying: true},
	{name: "unclassified port", classifying: false},
}

// TestBridgeDispatchOnlyForLocalOrMulticast checks that only group frames and
// frames addressed to the bridge or to one of its ports are passed up; other
// frames are only forwarded. Frames for the bridge or a port are not
// forwarded. The bridge classifies every frame it passes up.
func TestBridgeDispatchOnlyForLocalOrMulticast(t *testing.T) {
	tests := []dispatchTest{
		{name: "unicast to host behind other port", dst: dispatchRemoteAddr, wantFwd: true},
		{name: "unknown unicast", dst: dispatchUnknownAddr, wantFwd: true},
		{name: "unicast to bridge", dst: dispatchBridgeAddr, wantUpcall: true, wantPktType: tcpip.PacketHost, wantIP: true},
		{name: "unicast to receiving port", dst: dispatchPort1Addr, wantUpcall: true, wantPktType: tcpip.PacketHost, wantIP: true},
		{name: "unicast to other port", dst: dispatchPort2Addr, wantUpcall: true, wantPktType: tcpip.PacketOtherHost},
		{name: "broadcast", dst: header.EthernetBroadcastAddress, wantUpcall: true, wantPktType: tcpip.PacketBroadcast, wantIP: true, wantFwd: true},
		{name: "multicast", dst: dispatchMulticastAddr, wantUpcall: true, wantPktType: tcpip.PacketMulticast, wantIP: true, wantFwd: true},
	}
	for _, kind := range portKinds {
		for _, test := range tests {
			t.Run(kind.name+"/"+test.name, func(t *testing.T) {
				newDispatchTestContext(t, kind.classifying).check(t, test)
			})
		}
	}
}

// TestBridgePortAddressChange checks that the bridge tracks changes to its
// ports' addresses after they are added, as br_fdb_changeaddr does.
func TestBridgePortAddressChange(t *testing.T) {
	tests := []dispatchTest{
		{name: "new receiving port address", dst: dispatchNewPort1Addr, wantUpcall: true, wantPktType: tcpip.PacketHost, wantIP: true},
		{name: "new other port address", dst: dispatchNewPort2Addr, wantUpcall: true, wantPktType: tcpip.PacketOtherHost},
		{name: "old receiving port address", dst: dispatchPort1Addr, wantFwd: true},
		{name: "old other port address", dst: dispatchPort2Addr, wantFwd: true},
	}
	for _, kind := range portKinds {
		for _, test := range tests {
			t.Run(kind.name+"/"+test.name, func(t *testing.T) {
				c := newDispatchTestContext(t, kind.classifying)
				if err := c.s.SetNICAddress(dispatchPort1ID, dispatchNewPort1Addr); err != nil {
					t.Fatalf("s.SetNICAddress(%d, %s): %s", dispatchPort1ID, dispatchNewPort1Addr, err)
				}
				if err := c.s.SetNICAddress(dispatchPort2ID, dispatchNewPort2Addr); err != nil {
					t.Fatalf("s.SetNICAddress(%d, %s): %s", dispatchPort2ID, dispatchNewPort2Addr, err)
				}
				c.check(t, test)
			})
		}
	}
}

// TestBridgeDoesNotLearnLocalAddresses checks that, as in br_fdb_update, the
// bridge doesn't learn its own or its ports' addresses as source addresses.
func TestBridgeDoesNotLearnLocalAddresses(t *testing.T) {
	tests := []struct {
		name        string
		src         tcpip.LinkAddress
		wantLearned bool
	}{
		{name: "remote host", src: dispatchSrcAddr, wantLearned: true},
		{name: "bridge", src: dispatchBridgeAddr},
		{name: "receiving port", src: dispatchPort1Addr},
		{name: "other port", src: dispatchPort2Addr},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newDispatchTestContext(t, true /* classifying */)
			c.injectFromPort1(test.src, header.EthernetBroadcastAddress, header.IPv4ProtocolNumber, nil)
			var want tcpip.LinkAddress
			if test.wantLearned {
				want = dispatchPort1Addr
			}
			if got := c.bridge.FindFDBEntry(test.src).PortLinkAddress(); got != want {
				t.Errorf("got FDB entry for %s on port %q, want %q", test.src, got, want)
			}
		})
	}
}

// TestBridgeARPRequests checks that, as in arp_rcv, the bridge doesn't answer
// an ARP request in a frame addressed to another port.
func TestBridgeARPRequests(t *testing.T) {
	tests := []struct {
		name      string
		dst       tcpip.LinkAddress
		wantReply bool
	}{
		{name: "bridge", dst: dispatchBridgeAddr, wantReply: true},
		{name: "receiving port", dst: dispatchPort1Addr, wantReply: true},
		{name: "other port", dst: dispatchPort2Addr, wantReply: false},
		{name: "broadcast", dst: header.EthernetBroadcastAddress, wantReply: true},
	}
	for _, kind := range portKinds {
		for _, test := range tests {
			t.Run(kind.name+"/"+test.name, func(t *testing.T) {
				c := newDispatchTestContext(t, kind.classifying)
				request := make([]byte, header.ARPSize)
				h := header.ARP(request)
				h.SetIPv4OverEthernet()
				h.SetOp(header.ARPRequest)
				copy(h.HardwareAddressSender(), dispatchSrcAddr)
				copy(h.ProtocolAddressSender(), dispatchSrcIP.AsSlice())
				copy(h.ProtocolAddressTarget(), dispatchBridgeIP.AsSlice())
				replies := c.s.Stats().ARP.OutgoingRepliesSent
				before := replies.Value()
				c.injectFromPort1(dispatchSrcAddr, test.dst, header.ARPProtocolNumber, request)
				var want uint64
				if test.wantReply {
					want = 1
				}
				if got := replies.Value() - before; got != want {
					t.Errorf("got %d ARP replies, want %d", got, want)
				}
			})
		}
	}
}

func TestBridgeFDBSaveRestore(t *testing.T) {
	const (
		channelLinkAddr     = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x03")
		channelPeerAddr     = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x04")
		vethLinkAddr1       = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		vethLinkAddr2       = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
		bridgeLinkAddr      = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x09")
		unpreservedLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x0a")
		unpreservedPeerAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x0b")

		netProto      = 55
		nicID         = 4
		vethID1       = 7
		vethID2       = 8
		bridgeID      = 9
		unpreservedID = 10
	)

	veth1, veth2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	veth1.SetLinkAddress(vethLinkAddr1)
	veth2.SetLinkAddress(vethLinkAddr2)
	ch := channel.New(4, header.EthernetMinimumSize, channelLinkAddr)
	unpreservedCh := channel.New(4, header.EthernetMinimumSize, unpreservedLinkAddr)
	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)

	s := stack.New(stack.Options{})
	secondStack := stack.New(stack.Options{})

	if err := s.CreateNICWithOptions(bridgeID, bridgeEndpoint, stack.NICOptions{Name: "br0", Kind: stack.NICKindBridge, Preserve: true}); err != nil {
		t.Fatalf("s.CreateNICWithOptions(%d, _): %s", bridgeID, err)
	}
	// Mark channel endpoint ch0 with Preserve so Stack preserves it across
	// save/restore alongside the bridge and real veth port.
	if err := s.CreateNICWithOptions(nicID, ethernet.New(ch), stack.NICOptions{Name: "ch0", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("s.CreateNICWithOptions(%d, _): %s", nicID, err)
	}
	if err := s.SetNICCoordinator(nicID, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d): %s", nicID, bridgeID, err)
	}
	if err := s.CreateNICWithOptions(vethID1, ethernet.New(veth1), stack.NICOptions{Name: "veth1", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("s.CreateNICWithOptions(%d, _): %s", vethID1, err)
	}
	if err := s.SetNICCoordinator(vethID1, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d): %s", vethID1, bridgeID, err)
	}
	// Enslave an unpreserved NIC (empty Kind, like a host-FD-backed eth0) to
	// verify that a removeConf=false checkpoint omits it from the saved bridge
	// without detaching it from the live bridge.
	if err := s.CreateNICWithOptions(unpreservedID, ethernet.New(unpreservedCh), stack.NICOptions{Name: "eth0"}); err != nil {
		t.Fatalf("s.CreateNICWithOptions(%d, _): %s", unpreservedID, err)
	}
	if err := s.SetNICCoordinator(unpreservedID, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d): %s", unpreservedID, bridgeID, err)
	}
	if err := secondStack.CreateNICWithOptions(vethID2, ethernet.New(veth2), stack.NICOptions{Name: "veth2", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("secondStack.CreateNICWithOptions(%d, _): %s", vethID2, err)
	}

	n := &testNotification{ch: make(chan bool, 1)}
	notifyHandle := ch.AddNotify(n)
	if err := secondStack.WritePacketToRemote(vethID2, channelPeerAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("secondStack.WritePacketToRemote(%d, %s, _): %s", vethID2, channelPeerAddr, err)
	}
	select {
	case <-n.ch:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for packet across veth and bridge before save")
	}
	ch.RemoveNotify(notifyHandle)
	pkt := ch.Read()
	if pkt == nil {
		t.Fatal("ch.Read() = nil before save, want non-nil")
	}
	pkt.DecRef()
	// The bridge learns the source address of a frame after it forwards the
	// frame, on the veth worker goroutine. Wait for the entry, so that the
	// frames below are forwarded to veth1 and not flooded to ch.
	for deadline := time.Now().Add(10 * time.Second); bridgeEndpoint.FindFDBEntry(vethLinkAddr2).PortLinkAddress() != vethLinkAddr1; {
		if time.Now().After(deadline) {
			t.Fatalf("bridgeEndpoint.FindFDBEntry(%s) = %s, want %s", vethLinkAddr2, bridgeEndpoint.FindFDBEntry(vethLinkAddr2).PortLinkAddress(), vethLinkAddr1)
		}
		time.Sleep(time.Millisecond)
	}
	drainChannels(unpreservedCh)

	// Also learn channelPeerAddr on port nicID and unpreservedPeerAddr on
	// unpreservedID before saving.
	learn := makeEthernetFrame(channelPeerAddr, vethLinkAddr2, netProto, nil)
	ch.InjectInbound(netProto, learn)
	learn.DecRef()

	unpreservedLearn := makeEthernetFrame(unpreservedPeerAddr, vethLinkAddr2, netProto, nil)
	unpreservedCh.InjectInbound(netProto, unpreservedLearn)
	unpreservedLearn.DecRef()

	if got := bridgeEndpoint.FindFDBEntry(channelPeerAddr).PortLinkAddress(); got != channelLinkAddr {
		t.Fatalf("bridgeEndpoint.FindFDBEntry(%s) = %s, want %s", channelPeerAddr, got, channelLinkAddr)
	}
	if got := bridgeEndpoint.FindFDBEntry(unpreservedPeerAddr).PortLinkAddress(); got != unpreservedLinkAddr {
		t.Fatalf("bridgeEndpoint.FindFDBEntry(%s) = %s, want %s", unpreservedPeerAddr, got, unpreservedLinkAddr)
	}

	s.SetRemoveConf(false)
	s.Pause()
	secondStack.Pause()
	saved := [2]*stack.Stack{s, secondStack}
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, &saved); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}

	// Saving with removeConf=false must leave the live bridge intact.
	if got := bridgeEndpoint.FindFDBEntry(unpreservedPeerAddr).PortLinkAddress(); got != unpreservedLinkAddr {
		t.Fatalf("live bridgeEndpoint.FindFDBEntry(%s) after save = %s, want %s", unpreservedPeerAddr, got, unpreservedLinkAddr)
	}

	drainChannels(ch, unpreservedCh)
	s.Destroy()
	secondStack.Destroy()

	var loaded [2]*stack.Stack
	if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load failed: %v", err)
	}
	restoredRoot, restoredChild := loaded[0], loaded[1]
	restoredRoot.ResetConfig()
	restoreStacks(restoredRoot, restoredChild)
	defer func() {
		restoredRoot.Destroy()
		restoredChild.Destroy()
	}()

	if restoredRoot.HasNIC(unpreservedID) {
		t.Fatalf("restoredRoot.HasNIC(%d) = true, want false for unpreserved bridge port", unpreservedID)
	}

	restoredBridge, ok := restoredRoot.GetLinkEndpointByName("br0").(*stack.BridgeEndpoint)
	if !ok || restoredBridge == nil {
		t.Fatalf("restoredRoot.GetLinkEndpointByName(\"br0\") = %T, want *stack.BridgeEndpoint", restoredRoot.GetLinkEndpointByName("br0"))
	}
	if got := restoredBridge.FindFDBEntry(vethLinkAddr2).PortLinkAddress(); got != vethLinkAddr1 {
		t.Fatalf("restoredBridge.FindFDBEntry(%s) = %s, want %s", vethLinkAddr2, got, vethLinkAddr1)
	}
	if got := restoredBridge.FindFDBEntry(channelPeerAddr).PortLinkAddress(); got != channelLinkAddr {
		t.Fatalf("restoredBridge.FindFDBEntry(%s) = %s, want %s", channelPeerAddr, got, channelLinkAddr)
	}
	if got := restoredBridge.FindFDBEntry(unpreservedPeerAddr).PortLinkAddress(); got != "" {
		t.Fatalf("restoredBridge.FindFDBEntry(%s) = %s, want empty for unpreserved bridge port", unpreservedPeerAddr, got)
	}

	restoredChEth, ok := restoredRoot.GetLinkEndpointByName("ch0").(*ethernet.Endpoint)
	if !ok {
		t.Fatalf("restoredRoot.GetLinkEndpointByName(\"ch0\") = %T, want *ethernet.Endpoint", restoredRoot.GetLinkEndpointByName("ch0"))
	}
	restoredCh, ok := restoredChEth.Child().(*channel.Endpoint)
	if !ok {
		t.Fatalf("restoredChEth.Child() = %T, want *channel.Endpoint", restoredChEth.Child())
	}

	n2 := &testNotification{ch: make(chan bool, 1)}
	notifyHandle2 := restoredCh.AddNotify(n2)
	if err := restoredChild.WritePacketToRemote(vethID2, channelPeerAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("restoredChild.WritePacketToRemote(%d, %s, _): %s", vethID2, channelPeerAddr, err)
	}
	select {
	case <-n2.ch:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for packet across restored veth and bridge")
	}
	restoredCh.RemoveNotify(notifyHandle2)
	restoredPkt := restoredCh.Read()
	if restoredPkt == nil {
		t.Fatal("restoredCh.Read() = nil after restore, want non-nil")
	}
	restoredPkt.DecRef()

	// Verify localAddrs across restore: a frame addressed to preserved port ch0's
	// own MAC (channelLinkAddr) is local and not forwarded, whereas a frame
	// addressed to the omitted unpreserved port's MAC (unpreservedLinkAddr) is no
	// longer local and is flooded out restoredCh. Because both frames traverse
	// the same veth FIFO in order, receiving the unpreservedLinkAddr frame first
	// proves the channelLinkAddr frame was not forwarded.
	n3 := &testNotification{ch: make(chan bool, 1)}
	notifyHandle3 := restoredCh.AddNotify(n3)
	if err := restoredChild.WritePacketToRemote(vethID2, channelLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("restoredChild.WritePacketToRemote(%d, %s, _): %s", vethID2, channelLinkAddr, err)
	}
	if err := restoredChild.WritePacketToRemote(vethID2, unpreservedLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("restoredChild.WritePacketToRemote(%d, %s, _): %s", vethID2, unpreservedLinkAddr, err)
	}
	select {
	case <-n3.ch:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for flooded packet to omitted port MAC after restore")
	}
	restoredCh.RemoveNotify(notifyHandle3)
	floodedPkt := restoredCh.Read()
	if floodedPkt == nil {
		t.Fatal("restoredCh.Read() = nil for omitted port MAC after restore, want flooded packet")
	}
	if _, ok := floodedPkt.LinkHeader().Consume(header.EthernetMinimumSize); !ok {
		floodedPkt.DecRef()
		t.Fatal("floodedPkt.LinkHeader().Consume(header.EthernetMinimumSize) = false, want true")
	}
	floodedEth := header.Ethernet(floodedPkt.LinkHeader().Slice())
	if got := floodedEth.DestinationAddress(); got != unpreservedLinkAddr {
		t.Errorf("floodedPkt DestinationAddress() = %s, want %s", got, unpreservedLinkAddr)
	}
	floodedPkt.DecRef()
	if extra := restoredCh.Read(); extra != nil {
		extra.DecRef()
		t.Fatal("unexpected extra packet forwarded to restoredCh")
	}
}

type dadEvent struct {
	nicID tcpip.NICID
	addr  tcpip.Address
	res   stack.DADResult
}

type testNDPDispatcherContextKey struct{}

type testNDPDispatcher struct {
	ipv6.NDPDispatcher
	dadCh chan dadEvent
}

func (*testNDPDispatcher) StateTypeName() string {
	return "gvisor.dev/gvisor/pkg/tcpip/stack/bridge_test.testNDPDispatcher"
}

func (*testNDPDispatcher) StateFields() []string { return nil }

func (*testNDPDispatcher) StateSave(state.Sink) {}

func (d *testNDPDispatcher) StateLoad(ctx context.Context, _ state.Source) {
	*d = *ctx.Value(testNDPDispatcherContextKey{}).(*testNDPDispatcher)
}

func (d *testNDPDispatcher) OnDuplicateAddressDetectionResult(nicID tcpip.NICID, addr tcpip.Address, res stack.DADResult) {
	if d.dadCh != nil {
		d.dadCh <- dadEvent{nicID: nicID, addr: addr, res: res}
	}
}

func init() {
	state.Register((*testNDPDispatcher)(nil))
}

type dstCaptureDispatcher struct {
	ch chan tcpip.Address
}

func (d *dstCaptureDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	view := pkt.ToView()
	defer view.Release()
	raw := view.AsSlice()
	if linkLen := len(pkt.LinkHeader().Slice()); len(raw) >= linkLen {
		raw = raw[linkLen:]
	}
	switch protocol {
	case header.IPv4ProtocolNumber:
		if len(raw) >= header.IPv4MinimumSize {
			d.ch <- header.IPv4(raw).DestinationAddress()
		}
	case header.IPv6ProtocolNumber:
		if len(raw) >= header.IPv6MinimumSize {
			d.ch <- header.IPv6(raw).DestinationAddress()
		}
	}
}

func (*dstCaptureDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func makeIPv4EthernetFrame(srcMAC, dstMAC tcpip.LinkAddress, srcIP, dstIP tcpip.Address) *stack.PacketBuffer {
	raw := make([]byte, header.EthernetMinimumSize+header.IPv4MinimumSize)
	header.Ethernet(raw[:header.EthernetMinimumSize]).Encode(&header.EthernetFields{
		SrcAddr: srcMAC,
		DstAddr: dstMAC,
		Type:    header.IPv4ProtocolNumber,
	})
	ip := header.IPv4(raw[header.EthernetMinimumSize:])
	ip.Encode(&header.IPv4Fields{
		TotalLength: header.IPv4MinimumSize,
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     srcIP,
		DstAddr:     dstIP,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
}

func makeIPv6EthernetFrame(srcMAC, dstMAC tcpip.LinkAddress, srcIP, dstIP tcpip.Address) *stack.PacketBuffer {
	raw := make([]byte, header.EthernetMinimumSize+header.IPv6MinimumSize)
	header.Ethernet(raw[:header.EthernetMinimumSize]).Encode(&header.EthernetFields{
		SrcAddr: srcMAC,
		DstAddr: dstMAC,
		Type:    header.IPv6ProtocolNumber,
	})
	ip6 := header.IPv6(raw[header.EthernetMinimumSize:])
	ip6.Encode(&header.IPv6Fields{
		PayloadLength:     0,
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           srcIP,
		DstAddr:           dstIP,
	})
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
}

func TestSaveRestorePreservedNICsWithHostNICs(t *testing.T) {
	const (
		eth0MAC     = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x01")
		eth1MAC     = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x02")
		eth0PeerMAC = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x11")
		ext0MAC     = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x21")
		ext0PeerMAC = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x22")
		ext1MAC     = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x23")
	)

	eth0V4 := tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 0, 0, 1}), PrefixLen: 24}
	eth0PeerV4 := tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	eth0V6 := tcpip.AddressWithPrefix{Address: tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), PrefixLen: 64}
	eth0PeerV6 := tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})

	ext0V4 := tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{192, 168, 1, 1}), PrefixLen: 24}
	ext0PeerV4 := tcpip.AddrFrom4([4]byte{192, 168, 1, 2})
	ext0V6 := tcpip.AddressWithPrefix{Address: tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), PrefixLen: 64}
	ext0PeerV6 := tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})

	dadConfigs := stack.DADConfigurations{
		DupAddrDetectTransmits: 1,
		RetransmitTimer:        time.Second,
	}
	dadDisp := &testNDPDispatcher{dadCh: make(chan dadEvent, 16)}
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			arp.NewProtocol,
			ipv4.NewProtocol,
			ipv6.NewProtocolWithOptions(ipv6.Options{
				DADConfigs: dadConfigs,
				NDPDisp:    dadDisp,
			}),
		},
		Clock: clock,
	})
	if err := s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("s.SetForwardingDefaultAndAllNICs(ipv4): %s", err)
	}
	if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
		t.Fatalf("s.SetForwardingDefaultAndAllNICs(ipv6): %s", err)
	}

	// Create preserved NICs at IDs 1 and 2 using NICOptions.Preserve.
	ch1 := channel.New(16, 1500, eth0MAC)
	ch2 := channel.New(16, 1500, eth1MAC)
	for i, ch := range []*channel.Endpoint{ch1, ch2} {
		id := s.NextNICID()
		if want := tcpip.NICID(i + 1); id != want {
			t.Fatalf("NextNICID() = %d, want %d", id, want)
		}
		if err := s.CreateNICWithOptions(id, ethernet.New(ch), stack.NICOptions{
			Name:     "eth" + string(rune('0'+i)),
			Preserve: true,
		}); err != nil {
			t.Fatalf("CreateNICWithOptions(%d): %s", id, err)
		}
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: eth0V4,
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("s.AddProtocolAddress(1, ipv4): %s", err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: eth0V6,
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("s.AddProtocolAddress(1, ipv6): %s", err)
	}
	clock.Advance(time.Second)
	drainChannels(ch1, ch2)
	for len(dadDisp.dadCh) > 0 {
		<-dadDisp.dadCh
	}
	if err := s.AddStaticNeighbor(1, ipv4.ProtocolNumber, eth0PeerV4, eth0PeerMAC); err != nil {
		t.Fatalf("s.AddStaticNeighbor(1, ipv4): %s", err)
	}
	if err := s.AddStaticNeighbor(1, ipv6.ProtocolNumber, eth0PeerV6, eth0PeerMAC); err != nil {
		t.Fatalf("s.AddStaticNeighbor(1, ipv6): %s", err)
	}

	eth0SubnetV4 := eth0V4.Subnet()
	eth0SubnetV6 := eth0V6.Subnet()
	s.SetRouteTable([]tcpip.Route{
		{Destination: eth0SubnetV4, NIC: 1},
		{Destination: eth0SubnetV6, NIC: 1},
	})

	s.Pause()
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, s); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}
	s.Destroy()

	var restored stack.Stack
	loadCtx := context.WithValue(t.Context(), testNDPDispatcherContextKey{}, dadDisp)
	if _, err := state.Load(loadCtx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load failed: %v", err)
	}
	defer restored.Destroy()

	// Follow Kernel.LoadFrom: reset the restored stack, create the host NICs
	// of the new configuration on it, and then restore it in two phases.
	restored.ResetConfig()

	// NextNICID skips the IDs of preserved NICs 1 and 2.
	ext0ID := restored.NextNICID()
	if ext0ID != 3 {
		t.Fatalf("NextNICID() after ResetConfig = %d, want 3", ext0ID)
	}

	// A host NIC whose name collides with a preserved NIC fails.
	collideEP := channel.New(16, 1500, ext0MAC)
	defer collideEP.Close()
	if err := restored.CreateNICWithOptions(ext0ID, ethernet.New(collideEP), stack.NICOptions{Name: "eth0"}); err == nil {
		t.Fatalf("CreateNICWithOptions(%d, name=eth0) succeeded, want ErrDuplicateNICID", ext0ID)
	} else if _, ok := err.(*tcpip.ErrDuplicateNICID); !ok {
		t.Fatalf("CreateNICWithOptions(%d, name=eth0) = %s, want ErrDuplicateNICID", ext0ID, err)
	}

	ext0EP, ext0Peer := veth.NewPair(1500, veth.DefaultBacklogSize)
	defer ext0Peer.Close()
	ext0EP.SetLinkAddress(ext0MAC)
	ext0Peer.SetLinkAddress(ext0PeerMAC)
	if err := restored.CreateNICWithOptions(ext0ID, ethernet.New(ext0EP), stack.NICOptions{Name: "ext0"}); err != nil {
		t.Fatalf("restored.CreateNICWithOptions(%d): %s", ext0ID, err)
	}
	if err := restored.AddProtocolAddress(ext0ID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: ext0V4,
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("restored.AddProtocolAddress(%d, ipv4): %s", ext0ID, err)
	}
	if err := restored.AddProtocolAddress(ext0ID, tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: ext0V6,
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("restored.AddProtocolAddress(%d, ipv6): %s", ext0ID, err)
	}
	if err := restored.AddStaticNeighbor(ext0ID, ipv4.ProtocolNumber, ext0PeerV4, ext0PeerMAC); err != nil {
		t.Fatalf("restored.AddStaticNeighbor(%d, ipv4): %s", ext0ID, err)
	}
	if err := restored.AddStaticNeighbor(ext0ID, ipv6.ProtocolNumber, ext0PeerV6, ext0PeerMAC); err != nil {
		t.Fatalf("restored.AddStaticNeighbor(%d, ipv6): %s", ext0ID, err)
	}

	ext1ID := restored.NextNICID()
	if ext1ID != 4 {
		t.Fatalf("NextNICID() = %d, want 4", ext1ID)
	}
	ext1EP, ext1Peer := veth.NewPair(1500, veth.DefaultBacklogSize)
	defer ext1Peer.Close()
	ext1EP.SetLinkAddress(ext1MAC)
	if err := restored.CreateNICWithOptions(ext1ID, ethernet.New(ext1EP), stack.NICOptions{Name: "ext1"}); err != nil {
		t.Fatalf("restored.CreateNICWithOptions(%d): %s", ext1ID, err)
	}

	ext0SubnetV4 := ext0V4.Subnet()
	ext0SubnetV6 := ext0V6.Subnet()
	ext1SubnetV4 := tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{192, 168, 4, 0}), PrefixLen: 24}.Subnet()
	restored.SetRouteTable([]tcpip.Route{
		{Destination: ext0SubnetV4, NIC: ext0ID},
		{Destination: ext0SubnetV6, NIC: ext0ID},
		{Destination: ext1SubnetV4, NIC: ext1ID},
	})
	restoreStacks(&restored)

	// Advance restored's clock so IPv6 DAD finishes on ext0 and verify that DAD
	// reports ext0's NIC ID on the restored NDPDispatcher.
	restoredClock := restored.Clock().(*faketime.ManualClock)
	restoredClock.Advance(time.Second)
	foundExt0DAD := false
	for len(dadDisp.dadCh) > 0 {
		ev := <-dadDisp.dadCh
		if ev.addr == ext0V6.Address {
			foundExt0DAD = true
			if ev.nicID != ext0ID {
				t.Errorf("DAD event for %s reported NICID %d, want %d", ext0V6.Address, ev.nicID, ext0ID)
			}
			if _, ok := ev.res.(*stack.DADSucceeded); !ok {
				t.Errorf("DAD event for %s result = %T, want *stack.DADSucceeded", ext0V6.Address, ev.res)
			}
		}
	}
	if !foundExt0DAD {
		t.Errorf("did not observe IPv6 DAD completion for %s on NIC %d", ext0V6.Address, ext0ID)
	}

	// Preserved NICs 1 ("eth0") and 2 ("eth1") keep their IDs, and the host NICs
	// get the next free IDs.
	for _, want := range []struct {
		id   tcpip.NICID
		name string
	}{
		{id: 1, name: "eth0"},
		{id: 2, name: "eth1"},
		{id: 3, name: "ext0"},
		{id: 4, name: "ext1"},
	} {
		info, ok := restored.SingleNICInfo(want.id)
		if !ok || info.Name != want.name {
			t.Errorf("SingleNICInfo(%d) = (%+v, %v), want %q", want.id, info, ok, want.name)
		}
	}

	gotRoutes := make(map[tcpip.Subnet]tcpip.NICID)
	for _, r := range restored.GetRouteTable() {
		gotRoutes[r.Destination] = r.NIC
	}
	for subnet, wantNIC := range map[tcpip.Subnet]tcpip.NICID{
		eth0SubnetV4: 1,
		eth0SubnetV6: 1,
		ext1SubnetV4: 4,
		ext0SubnetV4: 3,
		ext0SubnetV6: 3,
	} {
		if got := gotRoutes[subnet]; got != wantNIC {
			t.Errorf("route for %s has NIC %d, want %d (routes=%+v)", subnet, got, wantNIC, restored.GetRouteTable())
		}
	}
	if next := restored.NextNICID(); next != 5 {
		t.Fatalf("NextNICID() after restore = %d, want 5", next)
	}

	// Verify IPv4 and IPv6 packet forwarding in both directions between
	// preserved NIC 1 ("eth0") and host NIC 3 ("ext0").
	ext0Sink := &dstCaptureDispatcher{ch: make(chan tcpip.Address, 16)}
	ext0PeerEth := ethernet.New(ext0Peer)
	ext0PeerEth.Attach(ext0Sink)

	restoredCh1 := restored.GetLinkEndpointByName("eth0").(*ethernet.Endpoint).Child().(*channel.Endpoint)
	drainChannels(restoredCh1)

	v4ToExt0 := makeIPv4EthernetFrame(eth0PeerMAC, eth0MAC, eth0PeerV4, ext0PeerV4)
	restoredCh1.InjectInbound(header.IPv4ProtocolNumber, v4ToExt0)
	v4ToExt0.DecRef()

	v6ToExt0 := makeIPv6EthernetFrame(eth0PeerMAC, eth0MAC, eth0PeerV6, ext0PeerV6)
	restoredCh1.InjectInbound(header.IPv6ProtocolNumber, v6ToExt0)
	v6ToExt0.DecRef()

	for _, wantDst := range []tcpip.Address{ext0PeerV4, ext0PeerV6} {
		deadline := time.After(5 * time.Second)
		matched := false
		for !matched {
			select {
			case gotDst := <-ext0Sink.ch:
				if gotDst == wantDst {
					matched = true
				}
			case <-deadline:
				t.Fatalf("timed out waiting for packet forwarded to %s via NIC 3", wantDst)
			}
		}
	}

	var inboundToExt0 stack.PacketBufferList
	inboundToExt0.PushBack(makeIPv4EthernetFrame(ext0PeerMAC, ext0MAC, ext0PeerV4, eth0PeerV4))
	inboundToExt0.PushBack(makeIPv6EthernetFrame(ext0PeerMAC, ext0MAC, ext0PeerV6, eth0PeerV6))
	if _, err := ext0Peer.WritePackets(inboundToExt0); err != nil {
		inboundToExt0.DecRef()
		t.Fatalf("ext0Peer.WritePackets failed: %s", err)
	}
	inboundToExt0.DecRef()

	readCtx, readCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer readCancel()
	for _, wantProto := range []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber} {
		var fwdPkt *stack.PacketBuffer
		for {
			p := restoredCh1.ReadContext(readCtx)
			if p == nil {
				t.Fatalf("timed out waiting for proto %d packet forwarded from NIC 3 to preserved NIC 1", wantProto)
			}
			eth := header.Ethernet(p.LinkHeader().Slice())
			if eth.Type() == wantProto && eth.DestinationAddress() == eth0PeerMAC {
				fwdPkt = p
				break
			}
			p.DecRef()
		}
		fwdPkt.DecRef()
	}

	// Closing ext1's and ext0's endpoints removes NICs 4 and 3.
	ext1EP.Close()
	if restored.HasNIC(4) {
		t.Errorf("HasNIC(4) = true after closing ext1 endpoint, want false")
	}
	ext0EP.Close()
	if restored.HasNIC(3) {
		t.Errorf("HasNIC(3) = true after closing ext0 endpoint, want false")
	}
}

func TestSaveRestoreDropsMovedUnpreservedNIC(t *testing.T) {
	rootStack := stack.New(stack.Options{})
	defer rootStack.Destroy()
	childStack := stack.New(stack.Options{})

	loCh := channel.New(1, header.EthernetMinimumSize, "")
	loCh.LinkEPCapabilities = stack.CapabilityLoopback
	loID := childStack.NextNICID()
	if err := childStack.CreateNICWithOptions(loID, loCh, stack.NICOptions{Name: "lo", Preserve: true}); err != nil {
		t.Fatalf("childStack.CreateNICWithOptions(%d): %s", loID, err)
	}

	if childStack.HasUnpreservedNICOtherThanLoopback() {
		t.Fatal("childStack.HasUnpreservedNICOtherThanLoopback() = true with only the loopback NIC, want false")
	}

	// Simulate moving an unpreserved host-FD-backed NIC from the root stack
	// into a child network namespace via RTM_SETLINK(IFLA_NET_NS_FD).
	ethCh := channel.New(1, header.EthernetMinimumSize, "\x02\x02\x03\x04\x05\x0c")
	if err := rootStack.CreateNICWithOptions(rootStack.NextNICID(), ethernet.New(ethCh), stack.NICOptions{Name: "eth0"}); err != nil {
		t.Fatalf("rootStack.CreateNICWithOptions: %s", err)
	}
	movedID, err := rootStack.SetNICStack(1, childStack, "")
	if err != nil {
		t.Fatalf("rootStack.SetNICStack(1, childStack): %s", err)
	}
	if info, ok := childStack.SingleNICInfo(movedID); !ok || info.Flags.Up {
		t.Fatalf("moved NIC SingleNICInfo(%d) = (%+v, %v), want administratively down (Flags.Up=false)", movedID, info, ok)
	}
	if !childStack.IsNICPreserved(loID) {
		t.Fatalf("childStack.IsNICPreserved(%d) = false, want true for loopback NIC", loID)
	}
	if childStack.IsNICPreserved(movedID) {
		t.Fatalf("childStack.IsNICPreserved(%d) = true, want false for non-loopback NIC", movedID)
	}
	// netstack.Stack.CheckRestorable refuses this save. Save without the
	// check still drops the moved NIC.
	if !childStack.HasUnpreservedNICOtherThanLoopback() {
		t.Fatal("childStack.HasUnpreservedNICOtherThanLoopback() = false with a moved unpreserved NIC, want true")
	}

	childStack.SetRemoveConf(true)
	childStack.Pause()
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, childStack); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}
	childStack.Destroy()

	var restoredChild stack.Stack
	if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &restoredChild); err != nil {
		t.Fatalf("state.Load failed: %v", err)
	}
	restoreStacks(&restoredChild)
	defer restoredChild.Destroy()

	if !restoredChild.HasNIC(loID) {
		t.Fatalf("restoredChild.HasNIC(%d) = false, want true for preserved loopback NIC", loID)
	}
	if !restoredChild.IsNICPreserved(loID) {
		t.Fatalf("restoredChild.IsNICPreserved(%d) = false, want true so that the next save also preserves the loopback NIC", loID)
	}
	if restoredChild.HasNIC(movedID) {
		t.Fatalf("restoredChild.HasNIC(%d) = true, want false for unpreserved NIC moved into child stack", movedID)
	}
}

func TestSaveRestoreResetsNFTablesConfigured(t *testing.T) {
	s := stack.New(stack.Options{})
	s.SetNFTablesConfigured(true)
	s.SetRemoveConf(true)
	s.Pause()
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, s); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}
	s.Destroy()

	var restored stack.Stack
	if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load failed: %v", err)
	}
	restoreStacks(&restored)
	defer restored.Destroy()
	if restored.IsNFTablesConfigured() {
		t.Fatal("restored.IsNFTablesConfigured() = true, want false after load")
	}
}

func TestSetNICStackNameCollision(t *testing.T) {
	src := stack.New(stack.Options{})
	defer src.Destroy()
	dst := stack.New(stack.Options{})
	defer dst.Destroy()

	srcCh := channel.New(1, 1500, "\x02\x02\x03\x04\x05\x21")
	dstCh := channel.New(1, 1500, "\x02\x02\x03\x04\x05\x22")
	if err := src.CreateNICWithOptions(1, ethernet.New(srcCh), stack.NICOptions{Name: "veth0", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("src.CreateNICWithOptions: %s", err)
	}
	if err := dst.CreateNICWithOptions(1, ethernet.New(dstCh), stack.NICOptions{Name: "veth0", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("dst.CreateNICWithOptions: %s", err)
	}
	if _, err := src.SetNICStack(1, dst, ""); err == nil {
		t.Fatal("src.SetNICStack(1, dst) with colliding name = nil, want *tcpip.ErrDuplicateNICID")
	} else if _, ok := err.(*tcpip.ErrDuplicateNICID); !ok {
		t.Fatalf("src.SetNICStack(1, dst) = %T (%v), want *tcpip.ErrDuplicateNICID", err, err)
	}
	if !src.HasNIC(1) {
		t.Fatal("src.HasNIC(1) = false after colliding SetNICStack, want NIC preserved in src")
	}
	movedID, err := src.SetNICStack(1, dst, "eth0")
	if err != nil {
		t.Fatalf("src.SetNICStack(1, dst, \"eth0\"): %s", err)
	}
	if info, ok := dst.SingleNICInfo(movedID); !ok || info.Name != "eth0" || info.Flags.Up {
		t.Fatalf("dst.SingleNICInfo(%d) = (%+v, %v), want Name=\"eth0\" and Flags.Up=false", movedID, info, ok)
	}
	if !dst.IsNICPreserved(movedID) {
		t.Errorf("dst.IsNICPreserved(%d) = false, want true for a moved preserved NIC", movedID)
	}
}

func TestSetNICStackRejectsLoopback(t *testing.T) {
	src := stack.New(stack.Options{})
	defer src.Destroy()
	dst := stack.New(stack.Options{})
	defer dst.Destroy()
	if err := src.CreateNICWithOptions(1, loopback.New(), stack.NICOptions{Name: "lo"}); err != nil {
		t.Fatalf("src.CreateNICWithOptions(lo): %s", err)
	}
	if _, err := src.SetNICStack(1, dst, "lo1"); err == nil {
		t.Fatal("src.SetNICStack(lo) = nil, want *tcpip.ErrNotSupported")
	} else if _, ok := err.(*tcpip.ErrNotSupported); !ok {
		t.Fatalf("src.SetNICStack(lo) = %T (%v), want *tcpip.ErrNotSupported", err, err)
	}
	if !src.HasNIC(1) {
		t.Error("src.HasNIC(1) = false after rejected move, want true")
	}
}

func TestSetNICStackRejectsBridge(t *testing.T) {
	src := stack.New(stack.Options{})
	defer src.Destroy()
	dst := stack.New(stack.Options{})
	defer dst.Destroy()
	if err := src.CreateNICWithOptions(1, stack.NewBridgeEndpoint(1500), stack.NICOptions{Name: "br0", Kind: stack.NICKindBridge, Preserve: true}); err != nil {
		t.Fatalf("src.CreateNICWithOptions(br0): %s", err)
	}
	if _, err := src.SetNICStack(1, dst, ""); err == nil {
		t.Fatal("src.SetNICStack(br0) = nil, want *tcpip.ErrNotSupported")
	} else if _, ok := err.(*tcpip.ErrNotSupported); !ok {
		t.Fatalf("src.SetNICStack(br0) = %T (%v), want *tcpip.ErrNotSupported", err, err)
	}
	if !src.HasNIC(1) {
		t.Error("src.HasNIC(1) = false after rejected move, want true")
	}
}

// raceLinkEndpoint calls onDetach once when its NIC detaches it.
type raceLinkEndpoint struct {
	stack.LinkEndpoint
	onDetach func()
}

// Attach implements stack.LinkEndpoint.Attach.
func (e *raceLinkEndpoint) Attach(d stack.NetworkDispatcher) {
	if d == nil && e.onDetach != nil {
		f := e.onDetach
		e.onDetach = nil
		f()
	}
	e.LinkEndpoint.Attach(d)
}

// TestSetNICStackRollback checks that SetNICStack puts the device back in the
// source stack when a device with the same name appears in the destination
// stack after the name check.
func TestSetNICStackRollback(t *testing.T) {
	for _, adminDown := range []bool{false, true} {
		t.Run(fmt.Sprintf("adminDown=%t", adminDown), func(t *testing.T) {
			src := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
			defer src.Destroy()
			dst := stack.New(stack.Options{})
			defer dst.Destroy()

			ep := &raceLinkEndpoint{LinkEndpoint: ethernet.New(channel.New(1, 1500, "\x02\x02\x03\x04\x05\x31"))}
			if err := src.CreateNICWithOptions(1, ep, stack.NICOptions{Name: "veth0", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
				t.Fatalf("src.CreateNICWithOptions: %s", err)
			}
			if err := src.AddProtocolAddress(1, tcpip.ProtocolAddress{
				Protocol:          ipv4.ProtocolNumber,
				AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 98, 0, 1}), PrefixLen: 24},
			}, stack.AddressProperties{}); err != nil {
				t.Fatalf("src.AddProtocolAddress: %s", err)
			}
			if adminDown {
				if err := src.DisableNIC(1); err != nil {
					t.Fatalf("src.DisableNIC: %s", err)
				}
			}
			ep.onDetach = func() {
				if err := dst.CreateNICWithOptions(1, channel.New(1, 1500, ""), stack.NICOptions{Name: "eth0"}); err != nil {
					t.Errorf("dst.CreateNICWithOptions(eth0): %s", err)
				}
			}
			if _, err := src.SetNICStack(1, dst, "eth0"); err == nil {
				t.Fatal("src.SetNICStack(1, dst, \"eth0\") = nil, want *tcpip.ErrDuplicateNICID")
			} else if _, ok := err.(*tcpip.ErrDuplicateNICID); !ok {
				t.Fatalf("src.SetNICStack(1, dst, \"eth0\") = %T (%v), want *tcpip.ErrDuplicateNICID", err, err)
			}
			info, ok := src.SingleNICInfo(1)
			if !ok {
				t.Fatal("src.SingleNICInfo(1) missing after failed move, want the device back in src")
			}
			if info.Name != "veth0" {
				t.Errorf("src NIC 1 name = %q, want %q", info.Name, "veth0")
			}
			if info.Flags.Up == adminDown {
				t.Errorf("src NIC 1 Flags.Up after rollback = %t, want %t", info.Flags.Up, !adminDown)
			}
			if !src.IsNICPreserved(1) {
				t.Error("src.IsNICPreserved(1) = false after rollback, want true")
			}
			if len(info.ProtocolAddresses) != 0 {
				t.Errorf("src NIC 1 addresses after rollback = %v, want none", info.ProtocolAddresses)
			}
		})
	}
}

func TestHasPreservedBridgeWithUnpreservedPort(t *testing.T) {
	for _, tc := range []struct {
		name         string
		portPreserve bool
		want         bool
	}{
		{name: "preserved port", portPreserve: true},
		{name: "unpreserved port", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := stack.New(stack.Options{})
			defer s.Destroy()
			if err := s.CreateNICWithOptions(1, ethernet.New(channel.New(1, 1500, "\x02\x02\x03\x04\x05\x51")), stack.NICOptions{Name: "dev0", Preserve: tc.portPreserve}); err != nil {
				t.Fatalf("CreateNICWithOptions(dev0): %s", err)
			}
			if err := s.CreateNICWithOptions(2, stack.NewBridgeEndpoint(1500), stack.NICOptions{Name: "br0", Kind: stack.NICKindBridge, Preserve: true}); err != nil {
				t.Fatalf("CreateNICWithOptions(br0): %s", err)
			}
			if s.HasPreservedBridgeWithUnpreservedPort() {
				t.Fatal("HasPreservedBridgeWithUnpreservedPort() = true for a bridge without ports, want false")
			}
			if err := s.SetNICCoordinator(1, 2); err != nil {
				t.Fatalf("SetNICCoordinator: %s", err)
			}
			if got := s.HasPreservedBridgeWithUnpreservedPort(); got != tc.want {
				t.Errorf("HasPreservedBridgeWithUnpreservedPort() = %t, want %t", got, tc.want)
			}
		})
	}
}

// countingPacketEndpoint counts the packets that it gets.
type countingPacketEndpoint struct {
	n atomicbitops.Int32
}

// HandlePacket implements stack.PacketEndpoint.HandlePacket.
func (e *countingPacketEndpoint) HandlePacket(tcpip.NICID, tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	e.n.Add(1)
}

// TestSetNICStackKeepsNICOptions checks that a moved device keeps the options
// it was created with.
func TestSetNICStackKeepsNICOptions(t *testing.T) {
	src := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	defer src.Destroy()
	dst := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	defer dst.Destroy()

	const (
		devMAC    = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x41")
		remoteMAC = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x42")
		nicCtx    = "veth0-context"
	)
	ch := channel.New(4, 1500, devMAC)
	if err := src.CreateNICWithOptions(1, ethernet.New(ch), stack.NICOptions{
		Name:                             "veth0",
		Context:                          nicCtx,
		DeliverLinkPackets:               true,
		EnableExperimentIPOption:         true,
		AllowExternalIPv4LoopbackTraffic: true,
	}); err != nil {
		t.Fatalf("src.CreateNICWithOptions: %s", err)
	}
	id, err := src.SetNICStack(1, dst, "")
	if err != nil {
		t.Fatalf("src.SetNICStack: %s", err)
	}
	info, ok := dst.SingleNICInfo(id)
	if !ok {
		t.Fatalf("dst.SingleNICInfo(%d) missing", id)
	}
	if info.Context != nicCtx {
		t.Errorf("moved NIC Context = %v, want %q", info.Context, nicCtx)
	}
	nic, terr := dst.GetNICByID(id)
	if terr != nil {
		t.Fatalf("dst.GetNICByID(%d): %s", id, terr)
	}
	if !nic.GetExperimentIPOptionEnabled() {
		t.Error("moved NIC GetExperimentIPOptionEnabled() = false, want true")
	}
	if !nic.AllowExternalIPv4LoopbackTraffic() {
		t.Error("moved NIC AllowExternalIPv4LoopbackTraffic() = false, want true")
	}

	// A NIC with DeliverLinkPackets delivers inbound packets to packet
	// endpoints.
	if err := dst.EnableNIC(id); err != nil {
		t.Fatalf("dst.EnableNIC(%d): %s", id, err)
	}
	var pep countingPacketEndpoint
	if err := dst.RegisterPacketEndpoint(id, header.IPv4ProtocolNumber, &pep); err != nil {
		t.Fatalf("dst.RegisterPacketEndpoint: %s", err)
	}
	defer dst.UnregisterPacketEndpoint(id, header.IPv4ProtocolNumber, &pep)
	frame := makeIPv4EthernetFrame(remoteMAC, devMAC, tcpip.AddrFrom4([4]byte{10, 97, 0, 2}), tcpip.AddrFrom4([4]byte{10, 97, 0, 1}))
	ch.InjectInbound(header.IPv4ProtocolNumber, frame)
	frame.DecRef()
	if got := pep.n.Load(); got != 1 {
		t.Errorf("packets delivered to a packet endpoint on the moved NIC = %d, want 1", got)
	}
}

func TestRemoveBridgeReattachesPorts(t *testing.T) {
	brStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	defer brStack.Destroy()
	const (
		portMAC   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x23")
		remoteMAC = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x24")
	)
	portAddr := tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 99, 0, 1}), PrefixLen: 24}
	remoteAddr := tcpip.AddrFrom4([4]byte{10, 99, 0, 2})
	portCh := channel.New(4, 1500, portMAC)
	if err := brStack.CreateNICWithOptions(1, ethernet.New(portCh), stack.NICOptions{Name: "veth0", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("brStack.CreateNICWithOptions(veth0): %s", err)
	}
	if err := brStack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: portAddr,
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("brStack.AddProtocolAddress: %s", err)
	}
	brEP := stack.NewBridgeEndpoint(1500)
	if err := brStack.CreateNICWithOptions(2, brEP, stack.NICOptions{Name: "br0", Kind: stack.NICKindBridge, Preserve: true}); err != nil {
		t.Fatalf("brStack.CreateNICWithOptions(br0): %s", err)
	}
	if err := brStack.SetNICCoordinator(1, 2); err != nil {
		t.Fatalf("brStack.SetNICCoordinator: %s", err)
	}
	if err := brStack.RemoveNIC(2); err != nil {
		t.Fatalf("brStack.RemoveNIC(br0): %s", err)
	}
	beforeRx := brStack.Stats().IP.PacketsReceived.Value()
	inbound := makeIPv4EthernetFrame(remoteMAC, portMAC, remoteAddr, portAddr.Address)
	portCh.InjectInbound(header.IPv4ProtocolNumber, inbound)
	inbound.DecRef()
	if got := brStack.Stats().IP.PacketsReceived.Value(); got != beforeRx+1 {
		t.Fatalf("IP.PacketsReceived after bridge deletion = %d, want %d", got, beforeRx+1)
	}
}

// TestSaveRestoreMulticastMembershipOnPreservedNIC checks that restoring a UDP
// socket with IP_ADD_MEMBERSHIP on a preserved NIC does not join the group a
// second time.
func TestSaveRestoreMulticastMembershipOnPreservedNIC(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	portCh := channel.New(4, 1500, "\x02\x02\x03\x04\x05\x23")
	if err := s.CreateNICWithOptions(1, ethernet.New(portCh), stack.NICOptions{Name: "veth0", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("CreateNICWithOptions(veth0): %s", err)
	}
	mcastAddr := tcpip.AddrFrom4([4]byte{224, 0, 0, 251})
	var wq waiter.Queue
	udpEP, tcpipErr := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if tcpipErr != nil {
		t.Fatalf("NewEndpoint(udp): %s", tcpipErr)
	}
	if err := udpEP.SetSockOpt(&tcpip.AddMembershipOption{
		NIC:           1,
		MulticastAddr: mcastAddr,
	}); err != nil {
		udpEP.Close()
		t.Fatalf("SetSockOpt(AddMembershipOption): %s", err)
	}
	if inGroup, err := s.IsInGroup(1, mcastAddr); err != nil || !inGroup {
		udpEP.Close()
		t.Fatalf("IsInGroup before save = (%v, %v), want (true, nil)", inGroup, err)
	}

	s.SetRemoveConf(true)
	s.Pause()
	saved := []any{s, udpEP, &wq}
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, &saved); err != nil {
		udpEP.Close()
		t.Fatalf("state.Save(multicast): %v", err)
	}
	udpEP.Close()
	s.Destroy()

	var loaded []any
	if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load(multicast): %v", err)
	}
	restored := loaded[0].(*stack.Stack)
	restoredUDP := loaded[1].(tcpip.Endpoint)
	restoreStacks(restored)
	defer restored.Destroy()

	if inGroup, err := restored.IsInGroup(1, mcastAddr); err != nil || !inGroup {
		restoredUDP.Close()
		t.Fatalf("IsInGroup after restore = (%v, %v), want (true, nil)", inGroup, err)
	}
	restoredUDP.Close()
	if inGroup, err := restored.IsInGroup(1, mcastAddr); err != nil || inGroup {
		t.Fatalf("IsInGroup after socket Close = (%v, %v), want (false, nil)", inGroup, err)
	}
}

func TestSaveRestorePausedExternalNetworking(t *testing.T) {
	newStack := func() *stack.Stack {
		return stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				arp.NewProtocol,
				ipv4.NewProtocol,
				ipv6.NewProtocol,
			},
			Clock: faketime.NewManualClock(),
		})
	}
	checkNIC := func(t *testing.T, s *stack.Stack, id tcpip.NICID, wantUp, wantRunning bool) {
		t.Helper()
		info, ok := s.SingleNICInfo(id)
		if !ok {
			t.Fatalf("SingleNICInfo(%d) missing", id)
		}
		if info.Flags.Up != wantUp || info.Flags.Running != wantRunning {
			t.Errorf("NIC %d (%q) flags = (Up:%v, Running:%v), want (Up:%v, Running:%v)", id, info.Name, info.Flags.Up, info.Flags.Running, wantUp, wantRunning)
		}
		if got := s.CheckNIC(id); got != wantRunning {
			t.Errorf("CheckNIC(%d) = %v, want %v", id, got, wantRunning)
		}
	}

	// configure follows Kernel.LoadFrom on a loaded stack: ResetConfig, host
	// NIC creation, the optional external networking pause from the restore
	// configuration, and the two restore phases.
	configure := func(t *testing.T, s *stack.Stack, pause bool, eth0MAC tcpip.LinkAddress) {
		t.Helper()
		s.ResetConfig()
		if err := s.CreateNICWithOptions(1, loopback.New(), stack.NICOptions{Name: "lo"}); err != nil {
			t.Fatalf("CreateNICWithOptions(lo): %s", err)
		}
		if err := s.CreateNICWithOptions(3, ethernet.New(channel.New(4, 1500, eth0MAC)), stack.NICOptions{
			Name: "eth0",
		}); err != nil {
			t.Fatalf("CreateNICWithOptions(eth0): %s", err)
		}
		if pause {
			s.DisableAllNonLoopbackNICs()
		}
		restoreStacks(s)
	}

	// Build a stack with loopback (1), preserved veth0 (2), and external eth0
	// (3), and pause external networking before Save.
	orig := newStack()
	if err := orig.CreateNICWithOptions(1, loopback.New(), stack.NICOptions{Name: "lo"}); err != nil {
		t.Fatalf("orig.CreateNICWithOptions(lo): %s", err)
	}
	vethA, vethB := veth.NewPair(1500, veth.DefaultBacklogSize)
	if err := orig.CreateNICWithOptions(2, ethernet.New(vethA), stack.NICOptions{
		Name:     "veth0",
		Kind:     stack.NICKindVeth,
		Preserve: true,
	}); err != nil {
		t.Fatalf("orig.CreateNICWithOptions(veth0): %s", err)
	}
	if err := orig.CreateNICWithOptions(3, ethernet.New(channel.New(4, 1500, "\x02\x00\x00\x00\x01\x03")), stack.NICOptions{
		Name: "eth0",
	}); err != nil {
		t.Fatalf("orig.CreateNICWithOptions(eth0): %s", err)
	}
	orig.DisableAllNonLoopbackNICs()
	checkNIC(t, orig, 1, true, true)
	checkNIC(t, orig, 2, true, false)
	checkNIC(t, orig, 3, true, false)

	// A NIC created while external networking is paused is not enabled.
	vethC, vethD := veth.NewPair(1500, veth.DefaultBacklogSize)
	if err := orig.CreateNICWithOptions(5, ethernet.New(vethC), stack.NICOptions{
		Name:     "veth2",
		Kind:     stack.NICKindVeth,
		Preserve: true,
	}); err != nil {
		t.Fatalf("orig.CreateNICWithOptions(veth2): %s", err)
	}
	checkNIC(t, orig, 5, true, false)

	orig.SetRemoveConf(true)
	orig.Pause()
	savedPaused := []any{orig, vethB, vethD}
	var pausedBuf bytes.Buffer
	if _, err := state.Save(t.Context(), &pausedBuf, &savedPaused); err != nil {
		t.Fatalf("state.Save(paused): %v", err)
	}
	vethB.Close()
	vethD.Close()
	orig.Destroy()

	loadPaused := func(t *testing.T) *stack.Stack {
		t.Helper()
		var loaded []any
		if _, err := state.Load(t.Context(), bytes.NewReader(pausedBuf.Bytes()), &loaded); err != nil {
			t.Fatalf("state.Load: %v", err)
		}
		s := loaded[0].(*stack.Stack)
		peerB := loaded[1].(*veth.Endpoint)
		peerD := loaded[2].(*veth.Endpoint)
		t.Cleanup(func() {
			peerB.Close()
			peerD.Close()
			s.Destroy()
		})
		return s
	}

	// 1. Saved paused, restored without a pause: the restore configuration
	// decides, so all NICs come up.
	restored1 := loadPaused(t)
	configure(t, restored1, false /* pause */, "\x02\x00\x00\x00\x02\x03")
	checkNIC(t, restored1, 1, true, true)
	checkNIC(t, restored1, 2, true, true)
	checkNIC(t, restored1, 3, true, true)
	checkNIC(t, restored1, 5, true, true)

	// 2. Saved paused, restored with a pause: non-loopback NICs stay disabled
	// until EnableAllNonLoopbackNICs.
	restored2 := loadPaused(t)
	configure(t, restored2, true /* pause */, "\x02\x00\x00\x00\x03\x03")
	checkNIC(t, restored2, 1, true, true)
	checkNIC(t, restored2, 2, true, false)
	checkNIC(t, restored2, 3, true, false)
	checkNIC(t, restored2, 5, true, false)

	restored2.EnableAllNonLoopbackNICs()
	checkNIC(t, restored2, 1, true, true)
	checkNIC(t, restored2, 2, true, true)
	checkNIC(t, restored2, 3, true, true)
	checkNIC(t, restored2, 5, true, true)

	// 3. Saved unpaused, restored with a pause: preserved non-loopback NICs are
	// disabled, and an administratively down NIC stays down after resume.
	unpausedOrig := newStack()
	uVethA, uVethB := veth.NewPair(1500, veth.DefaultBacklogSize)
	downVethA, downVethB := veth.NewPair(1500, veth.DefaultBacklogSize)
	if err := unpausedOrig.CreateNICWithOptions(2, ethernet.New(uVethA), stack.NICOptions{
		Name:     "veth0",
		Kind:     stack.NICKindVeth,
		Preserve: true,
	}); err != nil {
		t.Fatalf("unpausedOrig.CreateNICWithOptions(veth0): %s", err)
	}
	if err := unpausedOrig.CreateNICWithOptions(4, ethernet.New(downVethA), stack.NICOptions{
		Name:     "veth1",
		Kind:     stack.NICKindVeth,
		Disabled: true,
		Preserve: true,
	}); err != nil {
		t.Fatalf("unpausedOrig.CreateNICWithOptions(veth1): %s", err)
	}
	unpausedOrig.SetRemoveConf(true)
	unpausedOrig.Pause()
	savedUnpaused := []any{unpausedOrig, uVethB, downVethB}
	var unpausedBuf bytes.Buffer
	if _, err := state.Save(t.Context(), &unpausedBuf, &savedUnpaused); err != nil {
		t.Fatalf("state.Save(unpaused): %v", err)
	}
	uVethB.Close()
	downVethB.Close()
	unpausedOrig.Destroy()

	var loaded3 []any
	if _, err := state.Load(t.Context(), bytes.NewReader(unpausedBuf.Bytes()), &loaded3); err != nil {
		t.Fatalf("state.Load(loaded3): %v", err)
	}
	restored3 := loaded3[0].(*stack.Stack)
	restored3PeerA := loaded3[1].(*veth.Endpoint)
	restored3PeerB := loaded3[2].(*veth.Endpoint)
	defer restored3PeerA.Close()
	defer restored3PeerB.Close()
	defer restored3.Destroy()

	configure(t, restored3, true /* pause */, "\x02\x00\x00\x00\x04\x03")
	checkNIC(t, restored3, 1, true, true)
	checkNIC(t, restored3, 2, true, false)
	checkNIC(t, restored3, 3, true, false)
	checkNIC(t, restored3, 4, false, false)

	restored3.EnableAllNonLoopbackNICs()
	checkNIC(t, restored3, 1, true, true)
	checkNIC(t, restored3, 2, true, true)
	checkNIC(t, restored3, 3, true, true)
	checkNIC(t, restored3, 4, false, false)
}

// restoreStacks restores loaded stacks in two phases, as
// inet.Namespace.RestoreStacks does.
func restoreStacks(stacks ...*stack.Stack) {
	for _, s := range stacks {
		s.RestoreNICsAndEndpoints()
	}
	tcpip.AsyncLoading.Wait()
	for _, s := range stacks {
		s.RestoreBackgroundWorkers()
	}
}

func TestHasModifiedFilterRules(t *testing.T) {
	for _, tc := range []struct {
		name     string
		iptables bool
		nftables bool
		want     bool
	}{
		{name: "no rules"},
		{name: "iptables", iptables: true, want: true},
		{name: "nftables", nftables: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
			defer s.Destroy()
			if tc.iptables {
				tables := s.IPTables()
				tables.ForceReplaceTable(stack.FilterID, tables.GetTable(stack.FilterID, false /* ipv6 */), false /* ipv6 */)
			}
			if tc.nftables {
				s.SetNFTablesConfigured(true)
			}
			if got := s.HasModifiedFilterRules(); got != tc.want {
				t.Errorf("HasModifiedFilterRules() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestHasPreservedNICOtherThanLoopbackOrTun(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kind     string
		preserve bool
		loopback bool
		want     bool
	}{
		{name: "preserved veth", kind: stack.NICKindVeth, preserve: true, want: true},
		{name: "preserved bridge", kind: stack.NICKindBridge, preserve: true, want: true},
		{name: "tun", kind: stack.NICKindTun},
		{name: "preserved loopback", loopback: true, preserve: true},
		{name: "unpreserved NIC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
			defer s.Destroy()
			var ep stack.LinkEndpoint
			if tc.loopback {
				ep = loopback.New()
			} else {
				ep = channel.New(1, 1500, "\x02\x00\x00\x00\x00\x01")
			}
			if err := s.CreateNICWithOptions(1, ep, stack.NICOptions{Kind: tc.kind, Preserve: tc.preserve}); err != nil {
				t.Fatalf("CreateNICWithOptions: %s", err)
			}
			if got := s.HasPreservedNICOtherThanLoopbackOrTun(); got != tc.want {
				t.Errorf("HasPreservedNICOtherThanLoopbackOrTun() = %t, want %t", got, tc.want)
			}
		})
	}
}

// TestRestoreNICIDsAfterPreservedNICs checks that a restored stack that does not
// get ResetConfig, as in a non-root network namespace, gives new NICs IDs above
// all preserved NIC IDs.
func TestRestoreNICIDsAfterPreservedNICs(t *testing.T) {
	s := stack.New(stack.Options{})
	for _, id := range []tcpip.NICID{1, 5} {
		if err := s.CreateNICWithOptions(id, channel.New(1, 1500, ""), stack.NICOptions{Preserve: true}); err != nil {
			t.Fatalf("CreateNICWithOptions(%d): %s", id, err)
		}
	}
	s.SetRemoveConf(true)
	s.Pause()
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, s); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	s.Destroy()

	var restored stack.Stack
	if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restoreStacks(&restored)
	defer restored.Destroy()
	if got := restored.NextNICID(); got <= 5 {
		t.Errorf("NextNICID() after restore = %d, want > 5", got)
	}
}

// TestSaveRestoreAddressRefsOnPreservedNIC checks that an address on a
// preserved NIC can be removed after restore when a connected endpoint used it
// at save time.
func TestSaveRestoreAddressRefsOnPreservedNIC(t *testing.T) {
	for _, tc := range []struct {
		name     string
		proto    tcpip.NetworkProtocolNumber
		factory  stack.NetworkProtocolFactory
		addr     tcpip.AddressWithPrefix
		remote   tcpip.Address
		newPfLen int
	}{
		{
			name:     "IPv4",
			proto:    ipv4.ProtocolNumber,
			factory:  ipv4.NewProtocol,
			addr:     tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 0, 0, 1}), PrefixLen: 24},
			remote:   tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
			newPfLen: 16,
		},
		{
			name:     "IPv6",
			proto:    ipv6.ProtocolNumber,
			factory:  ipv6.NewProtocol,
			addr:     tcpip.AddressWithPrefix{Address: tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}), PrefixLen: 64},
			remote:   tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 2}),
			newPfLen: 48,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{tc.factory},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			})
			if err := s.CreateNICWithOptions(1, channel.New(4, 1500, ""), stack.NICOptions{Name: "eth0", Preserve: true}); err != nil {
				t.Fatalf("CreateNICWithOptions: %s", err)
			}
			if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: tc.proto, AddressWithPrefix: tc.addr}, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress: %s", err)
			}
			s.SetRouteTable([]tcpip.Route{{Destination: tc.addr.Subnet(), NIC: 1}})

			var wq waiter.Queue
			ep, err := s.NewEndpoint(udp.ProtocolNumber, tc.proto, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint: %s", err)
			}
			if err := ep.Connect(tcpip.FullAddress{Addr: tc.remote, Port: 1234}); err != nil {
				t.Fatalf("Connect: %s", err)
			}

			s.SetRemoveConf(true)
			s.Pause()
			saved := []any{s, ep, &wq}
			var buf bytes.Buffer
			if _, err := state.Save(t.Context(), &buf, &saved); err != nil {
				t.Fatalf("state.Save: %v", err)
			}
			ep.Close()
			s.Destroy()

			var loaded []any
			if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
				t.Fatalf("state.Load: %v", err)
			}
			restored := loaded[0].(*stack.Stack)
			restoredEP := loaded[1].(tcpip.Endpoint)
			restoreStacks(restored)
			defer restored.Destroy()
			restoredEP.Close()

			if err := restored.RemoveAddress(1, tc.addr.Address); err != nil {
				t.Fatalf("RemoveAddress: %s", err)
			}
			// If the address were still referenced, adding it again would reuse
			// the old address with its old prefix.
			newAddr := tcpip.AddressWithPrefix{Address: tc.addr.Address, PrefixLen: tc.newPfLen}
			if err := restored.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: tc.proto, AddressWithPrefix: newAddr}, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress after RemoveAddress: %s", err)
			}
			got, err := restored.GetMainNICAddress(1, tc.proto)
			if err != nil {
				t.Fatalf("GetMainNICAddress: %s", err)
			}
			if got != newAddr {
				t.Errorf("GetMainNICAddress() = %s, want %s", got, newAddr)
			}
		})
	}
}

func TestSetNICNameRejectsDuplicate(t *testing.T) {
	s := stack.New(stack.Options{})
	defer s.Destroy()
	for i, name := range []string{"eth0", "eth1"} {
		id := tcpip.NICID(i + 1)
		if err := s.CreateNICWithOptions(id, channel.New(1, 1500, ""), stack.NICOptions{Name: name}); err != nil {
			t.Fatalf("CreateNICWithOptions(%d, %q): %s", id, name, err)
		}
	}
	if err := s.SetNICName(1, "eth1"); err == nil {
		t.Fatal("SetNICName(1, eth1) = nil, want ErrDuplicateNICID")
	} else if _, ok := err.(*tcpip.ErrDuplicateNICID); !ok {
		t.Fatalf("SetNICName(1, eth1) = %s, want ErrDuplicateNICID", err)
	}
	if got := s.FindNICNameFromID(1); got != "eth0" {
		t.Errorf("FindNICNameFromID(1) = %q, want eth0", got)
	}
	// Renaming a NIC to its own name succeeds.
	if err := s.SetNICName(1, "eth0"); err != nil {
		t.Errorf("SetNICName(1, eth0) = %s, want nil", err)
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}

// TestCreateNICWhileExternalNetworkingPaused checks that a loopback NIC
// created while external networking is paused is enabled, and that a
// non-loopback NIC is not.
func TestCreateNICWhileExternalNetworkingPaused(t *testing.T) {
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	defer s.Destroy()
	s.DisableAllNonLoopbackNICs()
	if err := s.CreateNICWithOptions(1, loopback.New(), stack.NICOptions{Name: "lo"}); err != nil {
		t.Fatalf("CreateNICWithOptions(lo): %s", err)
	}
	if err := s.CreateNICWithOptions(2, channel.New(1, 1500, "\x02\x00\x00\x00\x00\x01"), stack.NICOptions{Name: "eth0"}); err != nil {
		t.Fatalf("CreateNICWithOptions(eth0): %s", err)
	}
	if !s.CheckNIC(1) {
		t.Error("loopback NIC is not enabled while external networking is paused")
	}
	if s.CheckNIC(2) {
		t.Error("non-loopback NIC is enabled while external networking is paused")
	}
}
