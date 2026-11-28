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

package tcp

import (
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestSendBufferStateSnapshot(t *testing.T) {
	var ep Endpoint
	var snapshot TCPSndBufState
	// Neither the initial nor updated endpoint state contains this value.
	snapshot.AutoTuneSndBufDisabled.Store(2)

	// The socket option callback does not take sndQueueMu. Join only after
	// both accesses so that the wait group cannot serialize them.
	var wg sync.WaitGroup
	wg.Go(func() {
		_ = ep.OnSetSendBufferSize(4096)
	})
	wg.Go(func() {
		ep.sndQueueInfo.sndQueueMu.Lock()
		ep.sndQueueInfo.CloneState(&snapshot)
		ep.sndQueueInfo.sndQueueMu.Unlock()
	})
	wg.Wait()

	ep.sndQueueInfo.sndQueueMu.Lock()
	sourceDisabled := ep.sndQueueInfo.AutoTuneSndBufDisabled.Load()
	ep.sndQueueInfo.sndQueueMu.Unlock()
	if sourceDisabled != 1 {
		t.Errorf("source AutoTuneSndBufDisabled = %d, want 1", sourceDisabled)
	}
	if got := snapshot.AutoTuneSndBufDisabled.Load(); got > 1 {
		t.Errorf("snapshot AutoTuneSndBufDisabled = %d, want 0 or 1", got)
	}
}

func queueListenerRSTs(t *testing.T, st *stack.Stack, p *processor, packets int, consumed func()) *Endpoint {
	t.Helper()
	ep := &Endpoint{stack: st}
	ep.segmentQueue.ep = ep
	ep.state.Store(uint32(StateListen))
	for range packets {
		s := newSegment()
		s.flags = header.TCPFlagRst
		s.pkt = stack.NewPacketBuffer(stack.PacketBufferOptions{OnRelease: consumed})
		queued := ep.enqueueSegment(s)
		s.DecRef()
		if !queued {
			t.Fatal("listener rejected an empty RST segment")
		}
	}
	p.epQ.enqueue(ep)
	return ep
}

func TestProcessorYieldsAfterReadyEndpoints(t *testing.T) {
	st := stack.New(stack.Options{})
	defer st.Destroy()
	var p processor
	var blockedPackets, readyPackets int
	blocked := queueListenerRSTs(t, st, &p, 1, func() { blockedPackets++ })
	queueListenerRSTs(t, st, &p, maxSegmentsPerWake+1, func() { readyPackets++ })

	func() {
		blocked.StopWork()
		defer blocked.ResumeWork()
		if !p.drainQueue() {
			t.Error("processor drained the queue while the first listener was locked")
		}
		if blockedPackets != 0 || readyPackets != maxSegmentsPerWake {
			t.Errorf("before yielding: processed %d blocked and %d ready packets, want 0 and %d", blockedPackets, readyPackets, maxSegmentsPerWake)
		}
	}()

	if p.drainQueue() || blockedPackets != 1 || readyPackets != maxSegmentsPerWake+1 {
		t.Errorf("after unlocking: processed %d blocked and %d ready packets, want 1 and %d with the queue drained", blockedPackets, readyPackets, maxSegmentsPerWake+1)
	}
}

func TestProcessorRetriesUnlockedEndpoint(t *testing.T) {
	st := stack.New(stack.Options{})
	defer st.Destroy()
	var p processor
	var processed int
	blocked := queueListenerRSTs(t, st, &p, 1, func() { processed++ })
	peerReady := make(chan struct{})
	resume := make(chan struct{})
	queueListenerRSTs(t, st, &p, 1, func() {
		close(peerReady)
		<-resume
	})

	done := make(chan bool, 1)
	func() {
		blocked.StopWork()
		defer blocked.ResumeWork()
		go func() { done <- p.drainQueue() }()
		select {
		case <-peerReady:
		case <-done:
			t.Fatal("processor returned before serving the ready peer")
		}
	}()
	close(resume)
	if yielded := <-done; yielded || processed != 1 {
		t.Errorf("after listener unlocked: yielded=%t, processed=%d, want false, 1", yielded, processed)
	}
}

func TestCoalesceChunkSizing(t *testing.T) {
	ep := &Endpoint{
		amss:        65476,
		waiterQueue: &waiter.Queue{},
	}
	newSeg := func(payload []byte) *segment {
		s := newSegment()
		s.pkt = stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(payload),
		})
		s.dataMemSize = SegOverheadSize + len(payload)
		return s
	}
	deliver := func(payload []byte) {
		s := newSeg(payload)
		defer s.DecRef()
		ep.mu.Lock()
		defer ep.mu.Unlock()
		ep.readyToRead(s)
	}
	tailViewCap := func() int {
		ep.mu.Lock()
		defer ep.mu.Unlock()
		ep.rcvQueueMu.Lock()
		defer ep.rcvQueueMu.Unlock()
		vl, _ := ep.rcvQueue.Back().pkt.AsViewList()
		return vl.Back().Capacity()
	}
	defer func() {
		ep.mu.Lock()
		defer ep.mu.Unlock()
		ep.rcvQueueMu.Lock()
		defer ep.rcvQueueMu.Unlock()
		for !ep.rcvQueue.Empty() {
			s := ep.rcvQueue.Front()
			ep.rcvQueue.Remove(s)
			s.DecRef()
		}
	}()

	// Seed a front segment (never coalesced into) and a full 1 KiB record tail.
	deliver([]byte("front"))
	record := make([]byte, 1024)
	deliver(record)

	// A small trailing delimiter after a full 1 KiB record should allocate a
	// small chunk rather than rounding up to SegOverheadSize (~1 KiB).
	deliver([]byte("\r\n"))

	if got := tailViewCap(); got >= SegOverheadSize {
		t.Errorf("first small spill allocated %d-byte chunk, want < %d", got, SegOverheadSize)
	}
	ep.rcvQueueMu.Lock()
	nextCap := ep.rcvCoalesceChunkCap
	ep.rcvQueueMu.Unlock()
	if nextCap == 0 || nextCap >= SegOverheadSize {
		t.Errorf("rcvCoalesceChunkCap after first spill = %d, want in (0, %d)", nextCap, SegOverheadSize)
	}

	// Another 1 KiB record starts a new tail and resets the chunk cap.
	deliver(record)
	ep.rcvQueueMu.Lock()
	resetCap := ep.rcvCoalesceChunkCap
	ep.rcvQueueMu.Unlock()
	if resetCap != 0 {
		t.Errorf("rcvCoalesceChunkCap after new tail = %d, want 0", resetCap)
	}

	// A sustained run of small segments grows the chunk cap and allocated chunk
	// size up to at least SegOverheadSize.
	small := make([]byte, 32)
	for range 64 {
		deliver(small)
	}
	if got := tailViewCap(); got < SegOverheadSize {
		t.Errorf("tail chunk capacity after run of small segments = %d, want >= %d", got, SegOverheadSize)
	}
	ep.rcvQueueMu.Lock()
	grownCap := ep.rcvCoalesceChunkCap
	ep.rcvQueueMu.Unlock()
	if grownCap != SegOverheadSize {
		t.Errorf("rcvCoalesceChunkCap after run of small segments = %d, want %d", grownCap, SegOverheadSize)
	}
}
