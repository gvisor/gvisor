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

package veth_test

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/veth"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestSetLinkAddress(t *testing.T) {
	addrs := []tcpip.LinkAddress{"abc", "def"}
	e, e2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	defer e.Close()
	defer e2.Close()
	for _, addr := range addrs {
		e.SetLinkAddress(addr)

		if want, v := addr, e.LinkAddress(); want != v {
			t.Errorf("LinkAddress() = %v, want %v", v, want)
		}
	}
}

type testNetworkDispatcher struct {
	ch chan *stack.PacketBuffer
	wg *sync.WaitGroup
}

func (d *testNetworkDispatcher) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	d.ch <- pkt.Clone()
	d.wg.Wait()
}

func (*testNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	panic("not implemented")
}

func TestWritePacket(t *testing.T) {
	const (
		localLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		remoteLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")

		netProto = 55
		nicID    = 5
	)

	veth1, veth2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	veth1.SetLinkAddress(localLinkAddr)
	veth2.SetLinkAddress(remoteLinkAddr)

	s := stack.New(stack.Options{})
	if err := s.CreateNIC(nicID, ethernet.New(veth1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}

	var wg sync.WaitGroup
	sink := &testNetworkDispatcher{ch: make(chan *stack.PacketBuffer, 1), wg: &wg}
	veth2Ethernet := ethernet.New(veth2)
	veth2Ethernet.Attach(sink)

	if err := s.WritePacketToRemote(nicID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", nicID, remoteLinkAddr, err)
	}
	pkt := <-sink.ch
	if pkt == nil {
		t.Fatal("expected to read a packet")
	}

	eth := header.Ethernet(pkt.LinkHeader().Slice())
	pkt.DecRef()
	if got := eth.SourceAddress(); got != localLinkAddr {
		t.Errorf("got eth.SourceAddress() = %s, want = %s", got, localLinkAddr)
	}
	if got := eth.DestinationAddress(); got != remoteLinkAddr {
		t.Errorf("got eth.DestinationAddress() = %s, want = %s", got, remoteLinkAddr)
	}
	if got := eth.Type(); got != netProto {
		t.Errorf("got eth.Type() = %d, want = %d", got, netProto)
	}
}

func TestVethOverflows(t *testing.T) {
	const (
		localLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		remoteLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")

		netProto = 55
		nicID    = 5
	)

	backlogSize := uint32(1)
	veth1, veth2 := veth.NewPair(1500, backlogSize)
	veth1.SetLinkAddress(localLinkAddr)
	veth2.SetLinkAddress(remoteLinkAddr)

	s := stack.New(stack.Options{})
	if err := s.CreateNIC(nicID, ethernet.New(veth1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	// Use a unbuffered channel in the dispatcher so that the received packet won't be processed.
	sink := &testNetworkDispatcher{ch: make(chan *stack.PacketBuffer), wg: &wg}
	veth2Ethernet := ethernet.New(veth2)
	veth2Ethernet.Attach(sink)

	// Send 3 packets, the first packet will be blocked at the sink's channel, the
	// second packet will be waiting at the veth device's backlog queue, the third
	// packet will be rejected since it overflows the backlog queue.
	if err := s.WritePacketToRemote(nicID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", nicID, remoteLinkAddr, err)
	}
	firstPkt := <-sink.ch
	defer firstPkt.DecRef()
	if err := s.WritePacketToRemote(nicID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", nicID, remoteLinkAddr, err)
	}
	if err := s.WritePacketToRemote(nicID, remoteLinkAddr, netProto, buffer.Buffer{}); err == nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _) got: %v, want: %v", nicID, remoteLinkAddr, err, &tcpip.ErrNoBufferSpace{})
	}
	wg.Done()
	pkt := <-sink.ch
	if pkt == nil {
		t.Fatal("expected to read a packet")
	}
	pkt.DecRef()
}

func TestDestroyDevices(t *testing.T) {
	const (
		vethFirstID  = 5
		vethSecondID = 6
	)

	veth1, veth2 := veth.NewPair(1500, veth.DefaultBacklogSize)

	s1 := stack.New(stack.Options{})
	if err := s1.CreateNIC(vethFirstID, ethernet.New(veth1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethFirstID, err)
	}

	s2 := stack.New(stack.Options{})
	if err := s2.CreateNIC(vethSecondID, ethernet.New(veth2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethSecondID, err)
	}

	s1.RemoveNIC(vethFirstID)
	timeout := time.Millisecond
	for s2.HasNIC(vethSecondID) && timeout < 5*time.Second {
		time.Sleep(timeout)
		timeout += timeout
	}
	if s2.HasNIC(vethSecondID) {
		t.Fatalf("veth2 hasn't been destroyed")
	}
}

func TestMTU(t *testing.T) {
	mtus := []uint32{100, 200}
	e, e2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	defer e.Close()
	defer e2.Close()
	for _, mtu := range mtus {
		e.SetMTU(mtu)

		if want, v := mtu, e.MTU(); want != v {
			t.Errorf("MTU() = %v, want %v", v, want)
		}
	}
}

func TestVethSaveRestoreBacklogAndSize(t *testing.T) {
	const (
		localLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		remoteLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
		netProto1      = 55
		netProto2      = 56
		netProto3      = 57
		netProto4      = 58
		nicID1         = 5
		nicID2         = 6
		backlogSize    = 2
	)

	veth1, veth2 := veth.NewPair(1500, backlogSize)
	veth1.SetLinkAddress(localLinkAddr)
	veth2.SetLinkAddress(remoteLinkAddr)

	s1 := stack.New(stack.Options{})
	if err := s1.CreateNICWithOptions(nicID1, ethernet.New(veth1), stack.NICOptions{Name: "veth1", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("s1.CreateNICWithOptions(%d, _): %s", nicID1, err)
	}
	s2 := stack.New(stack.Options{})
	if err := s2.CreateNICWithOptions(nicID2, ethernet.New(veth2), stack.NICOptions{Name: "veth2", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("s2.CreateNICWithOptions(%d, _): %s", nicID2, err)
	}

	// Pause s1/s2 before queueing two packets so they remain in the backlog
	// across save/restore.
	s1.Pause()
	s2.Pause()

	if err := s1.WritePacketToRemote(nicID1, remoteLinkAddr, netProto1, buffer.MakeWithData([]byte{1})); err != nil {
		t.Fatalf("first WritePacketToRemote failed: %s", err)
	}
	if err := s1.WritePacketToRemote(nicID1, remoteLinkAddr, netProto2, buffer.MakeWithData([]byte{2})); err != nil {
		t.Fatalf("second WritePacketToRemote failed: %s", err)
	}
	// The backlog holds backlogSize (2) packets, so a third write while the
	// stacks are paused fails with ErrNoBufferSpace.
	if err := s1.WritePacketToRemote(nicID1, remoteLinkAddr, netProto3, buffer.MakeWithData([]byte{3})); err == nil {
		t.Fatalf("third WritePacketToRemote = nil, want %T", &tcpip.ErrNoBufferSpace{})
	} else if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok {
		t.Fatalf("third WritePacketToRemote = %T (%v), want *tcpip.ErrNoBufferSpace", err, err)
	}

	saved := [2]*stack.Stack{s1, s2}
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, &saved); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}

	// Destroying the original stacks while packets remain in backlogQueue must
	// not leak PacketBuffers.
	s1.Destroy()
	s2.Destroy()

	var loaded [2]*stack.Stack
	if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load failed: %v", err)
	}
	restored1, restored2 := loaded[0], loaded[1]
	defer func() {
		restored1.Destroy()
		restored2.Destroy()
	}()

	restored1.RestoreNICsAndEndpoints()
	restored2.RestoreNICsAndEndpoints()

	// The restored backlog is full (2/2) before RestoreBackgroundWorkers
	// resumes the veth worker, so another write fails with ErrNoBufferSpace.
	if err := restored1.WritePacketToRemote(nicID1, remoteLinkAddr, netProto3, buffer.MakeWithData([]byte{3})); err == nil {
		t.Fatalf("WritePacketToRemote on full restored backlogQueue = nil, want %T", &tcpip.ErrNoBufferSpace{})
	} else if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok {
		t.Fatalf("WritePacketToRemote on full restored backlogQueue = %T (%v), want *tcpip.ErrNoBufferSpace", err, err)
	}

	var wg sync.WaitGroup
	sink := &testNetworkDispatcher{ch: make(chan *stack.PacketBuffer, 3), wg: &wg}
	restoredVeth2 := restored2.GetLinkEndpointByName("veth2")
	if restoredVeth2 == nil {
		t.Fatal("restored2.GetLinkEndpointByName(\"veth2\") = nil, want non-nil")
	}
	restoredVeth2.Attach(sink)

	restored1.RestoreBackgroundWorkers()
	restored2.RestoreBackgroundWorkers()

	for i, wantProto := range []tcpip.NetworkProtocolNumber{netProto1, netProto2} {
		select {
		case pkt := <-sink.ch:
			eth := header.Ethernet(pkt.LinkHeader().Slice())
			gotProto := eth.Type()
			pkt.DecRef()
			if gotProto != wantProto {
				t.Errorf("restored packet %d protocol = %d, want %d", i, gotProto, wantProto)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for restored packet %d", i)
		}
	}

	// Send a sentinel packet after draining to verify normal post-restore delivery.
	if err := restored1.WritePacketToRemote(nicID1, remoteLinkAddr, netProto4, buffer.MakeWithData([]byte{4})); err != nil {
		t.Fatalf("WritePacketToRemote(netProto4) failed: %s", err)
	}
	select {
	case pkt := <-sink.ch:
		eth := header.Ethernet(pkt.LinkHeader().Slice())
		gotProto := eth.Type()
		pkt.DecRef()
		if gotProto != netProto4 {
			t.Errorf("sentinel packet protocol = %d, want %d", gotProto, netProto4)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for sentinel packet")
	}
}

func TestVethPauseResumeAndConcurrentClose(t *testing.T) {
	const (
		localLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		remoteLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
		netProto1      = 55
		netProto2      = 56
		netProto3      = 57
		nicID1         = 5
		backlogSize    = 2
	)

	veth1, veth2 := veth.NewPair(1500, backlogSize)
	veth1.SetLinkAddress(localLinkAddr)
	veth2.SetLinkAddress(remoteLinkAddr)

	s := stack.New(stack.Options{})
	defer s.Destroy()
	if err := s.CreateNICWithOptions(nicID1, ethernet.New(veth1), stack.NICOptions{Name: "veth1", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("s.CreateNICWithOptions(%d, _): %s", nicID1, err)
	}

	var wg sync.WaitGroup
	sink := &testNetworkDispatcher{ch: make(chan *stack.PacketBuffer, 3), wg: &wg}
	veth2Ethernet := ethernet.New(veth2)
	veth2Ethernet.Attach(sink)

	s.Pause()
	if err := s.WritePacketToRemote(nicID1, remoteLinkAddr, netProto1, buffer.MakeWithData([]byte{1})); err != nil {
		t.Fatalf("WritePacketToRemote(netProto1) failed: %s", err)
	}
	if err := s.WritePacketToRemote(nicID1, remoteLinkAddr, netProto2, buffer.MakeWithData([]byte{2})); err != nil {
		t.Fatalf("WritePacketToRemote(netProto2) failed: %s", err)
	}
	if err := s.WritePacketToRemote(nicID1, remoteLinkAddr, netProto3, buffer.MakeWithData([]byte{3})); err == nil {
		t.Fatalf("WritePacketToRemote(netProto3) while full = nil, want *tcpip.ErrNoBufferSpace")
	} else if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok {
		t.Fatalf("WritePacketToRemote(netProto3) = %T (%v), want *tcpip.ErrNoBufferSpace", err, err)
	}

	s.Resume()

	for i, wantProto := range []tcpip.NetworkProtocolNumber{netProto1, netProto2} {
		select {
		case pkt := <-sink.ch:
			eth := header.Ethernet(pkt.LinkHeader().Slice())
			gotProto := eth.Type()
			pkt.DecRef()
			if gotProto != wantProto {
				t.Errorf("resumed packet %d protocol = %d, want %d", i, gotProto, wantProto)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for resumed packet %d", i)
		}
	}

	// Verify concurrent Close() on both ends waits for the worker and drains
	// queued PacketBuffers cleanly without racing or leaking.
	for range 16 {
		epA, epB := veth.NewPair(1500, 8)
		var pkts stack.PacketBufferList
		for range 4 {
			pkts.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData([]byte{1, 2, 3, 4}),
			}))
		}
		_, _ = epA.WritePackets(pkts)
		pkts.DecRef()

		var closeWG sync.WaitGroup
		closeWG.Add(2)
		go func() {
			defer closeWG.Done()
			epA.Close()
		}()
		go func() {
			defer closeWG.Done()
			epB.Close()
		}()
		closeWG.Wait()
	}
}

func TestVethSaveRestoreZeroBacklog(t *testing.T) {
	const (
		localLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")
		remoteLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x09")
		netProto       = 55
		nicID1         = 5
		nicID2         = 6
	)

	veth1, veth2 := veth.NewPair(1500, 0)
	veth1.SetLinkAddress(localLinkAddr)
	veth2.SetLinkAddress(remoteLinkAddr)

	s1 := stack.New(stack.Options{})
	if err := s1.CreateNICWithOptions(nicID1, ethernet.New(veth1), stack.NICOptions{Name: "veth1", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("s1.CreateNICWithOptions(%d, _): %s", nicID1, err)
	}
	s2 := stack.New(stack.Options{})
	if err := s2.CreateNICWithOptions(nicID2, ethernet.New(veth2), stack.NICOptions{Name: "veth2", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("s2.CreateNICWithOptions(%d, _): %s", nicID2, err)
	}

	s1.Pause()
	s2.Pause()

	saved := [2]*stack.Stack{s1, s2}
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, &saved); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}
	s1.Destroy()
	s2.Destroy()

	var loaded [2]*stack.Stack
	if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load failed: %v", err)
	}
	restored1, restored2 := loaded[0], loaded[1]
	restored1.RestoreNICsAndEndpoints()
	restored2.RestoreNICsAndEndpoints()
	defer func() {
		restored1.Destroy()
		restored2.Destroy()
	}()

	// A restored backlog with capacity 0 rejects writes with ErrNoBufferSpace
	// before RestoreBackgroundWorkers starts the veth worker.
	if err := restored1.WritePacketToRemote(nicID1, remoteLinkAddr, netProto, buffer.MakeWithData([]byte{1})); err == nil {
		t.Fatalf("WritePacketToRemote on paused zero-backlog veth = nil, want %T", &tcpip.ErrNoBufferSpace{})
	} else if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok {
		t.Fatalf("WritePacketToRemote on paused zero-backlog veth = %T (%v), want *tcpip.ErrNoBufferSpace", err, err)
	}

	var wg sync.WaitGroup
	sink := &testNetworkDispatcher{ch: make(chan *stack.PacketBuffer, 1), wg: &wg}
	restoredVeth2 := restored2.GetLinkEndpointByName("veth2")
	if restoredVeth2 == nil {
		t.Fatal("restored2.GetLinkEndpointByName(\"veth2\") = nil, want non-nil")
	}
	restoredVeth2.Attach(sink)

	restored1.RestoreBackgroundWorkers()
	restored2.RestoreBackgroundWorkers()

	// Wait briefly until the unbuffered worker goroutine blocks on <-ch, then
	// verify live packet delivery succeeds on the restored zero-backlog veth.
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := restored1.WritePacketToRemote(nicID1, remoteLinkAddr, netProto, buffer.MakeWithData([]byte{1}))
		if err == nil {
			break
		}
		if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok || !time.Now().Before(deadline) {
			t.Fatalf("WritePacketToRemote after RestoreBackgroundWorkers failed: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case pkt := <-sink.ch:
		pkt.DecRef()
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for packet on restored zero-backlog veth")
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}

func TestVethRepeatedPauseAndCloseBeforeResume(t *testing.T) {
	const (
		nicID1 = 1
		nicID2 = 2
	)
	veth1, veth2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	s1 := stack.New(stack.Options{})
	if err := s1.CreateNICWithOptions(nicID1, ethernet.New(veth1), stack.NICOptions{Name: "veth1", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("s1.CreateNICWithOptions(%d, _): %s", nicID1, err)
	}
	s2 := stack.New(stack.Options{})
	if err := s2.CreateNICWithOptions(nicID2, ethernet.New(veth2), stack.NICOptions{Name: "veth2", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("s2.CreateNICWithOptions(%d, _): %s", nicID2, err)
	}

	// Pause is idempotent, and a pause after a resume stops the new worker.
	s1.Pause()
	s1.Pause()
	s2.Pause()
	s1.Resume()
	s2.Resume()
	s1.Pause()
	s2.Pause()

	saved := [2]*stack.Stack{s1, s2}
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, &saved); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}
	s1.Destroy()
	s2.Destroy()

	var loaded [2]*stack.Stack
	if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load failed: %v", err)
	}
	restored1, restored2 := loaded[0], loaded[1]
	restored1.RestoreNICsAndEndpoints()
	restored2.RestoreNICsAndEndpoints()

	// Destroy the stacks before RestoreBackgroundWorkers starts a veth worker.
	done := make(chan struct{})
	go func() {
		restored1.Destroy()
		restored2.Destroy()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Destroy before RestoreBackgroundWorkers did not return")
	}
}

// TestVethPauseResumeAfterClose checks that Pause and Resume after Close do
// not start a worker and do not block.
func TestVethPauseResumeAfterClose(t *testing.T) {
	veth1, veth2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	veth1.Close()
	done := make(chan struct{})
	go func() {
		veth1.Pause()
		veth2.Resume()
		veth2.Pause()
		veth1.Resume()
		veth1.Wait()
		veth2.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pause, Resume, or Wait after Close did not return")
	}
}

// TestVethBacklogAboveMaxSaveRestore checks that NewPair clamps a backlog
// size above MaxBacklogSize, so that a full backlog saves and restores.
func TestVethBacklogAboveMaxSaveRestore(t *testing.T) {
	const (
		localLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x0a")
		remoteLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x0b")
		netProto       = 55
		nicID1         = 5
		nicID2         = 6
	)

	veth1, veth2 := veth.NewPair(1500, veth.MaxBacklogSize+10)
	veth1.SetLinkAddress(localLinkAddr)
	veth2.SetLinkAddress(remoteLinkAddr)

	s1 := stack.New(stack.Options{})
	if err := s1.CreateNICWithOptions(nicID1, ethernet.New(veth1), stack.NICOptions{Name: "veth1", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("s1.CreateNICWithOptions(%d, _): %s", nicID1, err)
	}
	s2 := stack.New(stack.Options{})
	if err := s2.CreateNICWithOptions(nicID2, ethernet.New(veth2), stack.NICOptions{Name: "veth2", Kind: stack.NICKindVeth, Preserve: true}); err != nil {
		t.Fatalf("s2.CreateNICWithOptions(%d, _): %s", nicID2, err)
	}
	s1.Pause()
	s2.Pause()

	// Fill the backlog. The write after MaxBacklogSize packets fails.
	for i := 0; i < veth.MaxBacklogSize; i++ {
		if err := s1.WritePacketToRemote(nicID1, remoteLinkAddr, netProto, buffer.MakeWithData([]byte{1})); err != nil {
			t.Fatalf("WritePacketToRemote #%d failed: %s", i, err)
		}
	}
	if err := s1.WritePacketToRemote(nicID1, remoteLinkAddr, netProto, buffer.MakeWithData([]byte{1})); err == nil {
		t.Fatalf("WritePacketToRemote on a full backlog = nil, want %T", &tcpip.ErrNoBufferSpace{})
	}

	saved := [2]*stack.Stack{s1, s2}
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, &saved); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}
	s1.Destroy()
	s2.Destroy()

	var loaded [2]*stack.Stack
	if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load failed: %v", err)
	}
	restored1, restored2 := loaded[0], loaded[1]
	restored1.RestoreNICsAndEndpoints()
	restored2.RestoreNICsAndEndpoints()
	restored1.RestoreBackgroundWorkers()
	restored2.RestoreBackgroundWorkers()
	restored1.Destroy()
	restored2.Destroy()
}

// gatedDispatcher records the payload byte of each delivered packet. Delivery
// of the first packet blocks until openGate is called.
type gatedDispatcher struct {
	entered  chan struct{}
	gate     chan struct{}
	gateOnce sync.Once

	mu  sync.Mutex
	got []byte
}

func newGatedDispatcher() *gatedDispatcher {
	return &gatedDispatcher{
		entered: make(chan struct{}),
		gate:    make(chan struct{}),
	}
}

func (d *gatedDispatcher) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	b := pkt.Data().AsRange().ToSlice()
	d.mu.Lock()
	d.got = append(d.got, b[0])
	first := len(d.got) == 1
	d.mu.Unlock()
	if first {
		close(d.entered)
		<-d.gate
	}
}

func (*gatedDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// openGate lets the delivery of the first packet finish. Tests also defer it,
// so that a failed test does not leave the worker blocked.
func (d *gatedDispatcher) openGate() {
	d.gateOnce.Do(func() { close(d.gate) })
}

func (d *gatedDispatcher) delivered() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]byte(nil), d.got...)
}

// writeByte writes one packet with payload b to ep.
func writeByte(ep *veth.Endpoint, b byte) tcpip.Error {
	var pkts stack.PacketBufferList
	pkts.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte{b}),
	}))
	defer pkts.DecRef()
	_, err := ep.WritePackets(pkts)
	return err
}

// fillWithBlockedWorker writes packets 1 to backlogSize+1 to ep. The worker
// blocks while it delivers packet 1, so packets 2 to backlogSize+1 fill the
// queue. It then checks that one more write fails because the queue is full.
func fillWithBlockedWorker(t *testing.T, ep *veth.Endpoint, d *gatedDispatcher, backlogSize int) {
	t.Helper()
	// With a zero backlog, a write succeeds only while the worker waits to
	// receive.
	deadline := time.Now().Add(5 * time.Second)
	for writeByte(ep, 1) != nil {
		if !time.Now().Before(deadline) {
			t.Fatal("writeByte(1) did not succeed")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-d.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the first delivery")
	}
	for i := 2; i <= backlogSize+1; i++ {
		if err := writeByte(ep, byte(i)); err != nil {
			t.Fatalf("writeByte(%d) = %v", i, err)
		}
	}
	if err := writeByte(ep, 0xff); err == nil {
		t.Fatal("writeByte on a full queue = nil, want ErrNoBufferSpace")
	}
}

// waitForGoroutine waits until the stack trace of one goroutine contains all
// of frames. The public API does not show when Pause or Close blocks, so the
// tests match the names of unexported veth functions in goroutine stack
// traces. If those functions are renamed, the tests time out here.
func waitForGoroutine(t *testing.T, what string, frames ...string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			found := true
			for _, f := range frames {
				if !strings.Contains(g, f) {
					found = false
					break
				}
			}
			if found {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// waitForBlockedStop waits until a goroutine blocks in a channel send to stop
// a veth worker.
func waitForBlockedStop(t *testing.T) {
	t.Helper()
	waitForGoroutine(t, "Pause to block on the full queue", "[chan send", "veth.(*veth).stopWorker")
}

func waitDone(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not return", what)
	}
}

// TestVethPauseDeliversQueuedPackets checks that the worker delivers the
// packets that were queued before Pause, and then stops.
func TestVethPauseDeliversQueuedPackets(t *testing.T) {
	const backlogSize = 4
	a, b := veth.NewPair(1500, backlogSize)
	defer a.Close()
	d := newGatedDispatcher()
	defer d.openGate()
	b.Attach(d)
	if err := writeByte(a, 1); err != nil {
		t.Fatalf("writeByte(1) = %v", err)
	}
	select {
	case <-d.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the first delivery")
	}
	for i := byte(2); i <= 3; i++ {
		if err := writeByte(a, i); err != nil {
			t.Fatalf("writeByte(%d) = %v", i, err)
		}
	}

	pauseDone := make(chan struct{})
	go func() {
		a.Pause()
		close(pauseDone)
	}()
	waitForGoroutine(t, "Pause to wait for the worker", "veth.(*veth).pause(", "sync.(*WaitGroup).Wait")
	d.openGate()
	waitDone(t, pauseDone, "Pause")
	if got, want := d.delivered(), []byte{1, 2, 3}; !bytes.Equal(got, want) {
		t.Fatalf("delivered before Pause returned = %v, want %v", got, want)
	}
}

// TestVethPauseFullQueueConcurrentWriters checks that Pause returns when the
// queue is full and writers keep writing. The packets that were queued when
// Pause started are delivered before Pause returns. The packets that writers
// queue after that are kept across save/restore and delivered in order after
// Resume.
func TestVethPauseFullQueueConcurrentWriters(t *testing.T) {
	const backlogSize = 4
	a, b := veth.NewPair(1500, backlogSize)
	d := newGatedDispatcher()
	defer d.openGate()
	b.Attach(d)
	fillWithBlockedWorker(t, a, d, backlogSize)

	pauseDone := make(chan struct{})
	go func() {
		a.Pause()
		close(pauseDone)
	}()

	// Writers try to fill every free slot until Pause returns.
	var (
		writersMu sync.Mutex
		accepted  []byte
		next      = byte(backlogSize + 2)
		stop      = make(chan struct{})
		stopOnce  sync.Once
		writersWG sync.WaitGroup
	)
	for range 4 {
		writersWG.Add(1)
		go func() {
			defer writersWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Hold writersMu across the write so that accepted
				// keeps the queue order.
				writersMu.Lock()
				if next == 0xff {
					writersMu.Unlock()
					return
				}
				if err := writeByte(a, next); err == nil {
					accepted = append(accepted, next)
					next++
				}
				writersMu.Unlock()
			}
		}()
	}

	stopWriters := func() { stopOnce.Do(func() { close(stop) }) }
	defer func() {
		stopWriters()
		writersWG.Wait()
	}()

	// Wait until Pause blocks on the full queue, then let the worker run.
	waitForBlockedStop(t)
	d.openGate()
	waitDone(t, pauseDone, "Pause with a full queue and active writers")
	stopWriters()
	writersWG.Wait()

	want := []byte{1, 2, 3, 4, 5}
	if got := d.delivered(); !bytes.Equal(got, want) {
		t.Fatalf("delivered before Pause returned = %v, want %v", got, want)
	}
	if len(accepted) > backlogSize {
		t.Fatalf("accepted %d packets while paused, want at most %d", len(accepted), backlogSize)
	}
	// Make sure that at least one packet is queued for save/restore.
	if len(accepted) < backlogSize {
		if err := writeByte(a, next); err != nil {
			t.Fatalf("writeByte(%d) while paused = %v", next, err)
		}
		accepted = append(accepted, next)
	}

	// Save and restore the paused pair, then resume it. Detach the dispatcher
	// first, because the test dispatcher is not savable.
	b.Attach(nil)
	saved := [2]*veth.Endpoint{a, b}
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, &saved); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}
	a.Close()
	var loaded [2]*veth.Endpoint
	if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load failed: %v", err)
	}
	ra, rb := loaded[0], loaded[1]
	defer ra.Close()
	rd := newGatedDispatcher()
	rd.openGate()
	rb.Attach(rd)
	ra.Resume()

	deadline := time.Now().Add(5 * time.Second)
	for len(rd.delivered()) < len(accepted) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := rd.delivered(); !bytes.Equal(got, accepted) {
		t.Fatalf("delivered after restore and Resume = %v, want %v", got, accepted)
	}
}

// TestVethPauseSaveRestoreCycles checks that repeated Pause, save, restore and
// Resume cycles deliver exactly the written packets, in order. Pause delivers
// the packets queued before it, and the packets queued while paused are
// delivered after restore and Resume.
func TestVethPauseSaveRestoreCycles(t *testing.T) {
	for _, backlogSize := range []uint32{0, 1, 3} {
		t.Run(fmt.Sprintf("backlog%d", backlogSize), func(t *testing.T) {
			a, b := veth.NewPair(1500, backlogSize)
			d := newGatedDispatcher()
			d.openGate()
			var want []byte
			next := byte(1)
			// writeLive writes one packet while the worker runs. With a zero
			// backlog, a write succeeds only while the worker waits to
			// receive.
			writeLive := func() {
				t.Helper()
				deadline := time.Now().Add(5 * time.Second)
				for writeByte(a, next) != nil {
					if !time.Now().Before(deadline) {
						t.Fatalf("writeByte(%d) did not succeed", next)
					}
					time.Sleep(time.Millisecond)
				}
				want = append(want, next)
				next++
			}
			for cycle := range 3 {
				b.Attach(d)
				if cycle > 0 {
					a.Resume()
				}
				for range 4 {
					writeLive()
				}
				a.Pause()
				if got := d.delivered(); !bytes.Equal(got, want) {
					t.Fatalf("cycle %d: delivered after Pause = %v, want %v", cycle, got, want)
				}
				// Queue packets while paused, up to the backlog size.
				for range backlogSize {
					if err := writeByte(a, next); err != nil {
						t.Fatalf("cycle %d: writeByte(%d) while paused = %v", cycle, next, err)
					}
					want = append(want, next)
					next++
				}
				b.Attach(nil)
				saved := [2]*veth.Endpoint{a, b}
				var buf bytes.Buffer
				if _, err := state.Save(t.Context(), &buf, &saved); err != nil {
					t.Fatalf("cycle %d: state.Save failed: %v", cycle, err)
				}
				a.Close()
				var loaded [2]*veth.Endpoint
				if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
					t.Fatalf("cycle %d: state.Load failed: %v", cycle, err)
				}
				a, b = loaded[0], loaded[1]
			}
			b.Attach(d)
			a.Resume()
			defer a.Close()
			writeLive()
			deadline := time.Now().Add(5 * time.Second)
			for len(d.delivered()) < len(want) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := d.delivered(); !bytes.Equal(got, want) {
				t.Fatalf("delivered = %v, want %v", got, want)
			}
		})
	}
}

// TestVethCloseDuringPause checks that Close returns, and discards all queued
// packets without delivering them, when it runs while a Pause waits for space
// in a full queue.
func TestVethCloseDuringPause(t *testing.T) {
	for _, backlogSize := range []int{0, 1, 4} {
		t.Run(fmt.Sprintf("backlog%d", backlogSize), func(t *testing.T) {
			a, b := veth.NewPair(1500, uint32(backlogSize))
			d := newGatedDispatcher()
			defer d.openGate()
			b.Attach(d)
			fillWithBlockedWorker(t, a, d, backlogSize)

			pauseDone := make(chan struct{})
			go func() {
				a.Pause()
				close(pauseDone)
			}()
			waitForBlockedStop(t)
			closeDone := make(chan struct{})
			go func() {
				b.Close()
				close(closeDone)
			}()
			// Close removes the stop packet of Pause and sends a new one. With a
			// zero backlog, that send blocks until the worker receives it.
			if backlogSize == 0 {
				waitForGoroutine(t, "Close to send a stop packet", "[chan send", "veth.(*veth).close(")
			} else {
				waitForGoroutine(t, "Close to wait for the worker", "veth.(*veth).close(", "sync.(*WaitGroup).Wait")
			}
			d.openGate()
			waitDone(t, pauseDone, "Pause")
			waitDone(t, closeDone, "Close")
			if got, want := d.delivered(), []byte{1}; !bytes.Equal(got, want) {
				t.Fatalf("delivered = %v, want %v", got, want)
			}
			if err := writeByte(a, 0xfe); err != nil {
				t.Fatalf("writeByte after Close = %v, want nil", err)
			}
			a.Close()
		})
	}
}
