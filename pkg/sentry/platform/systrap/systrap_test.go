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

package systrap

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/testutil"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/usermem"
)

const childEnv = "SYSTRAP_TEST_CHILD"

func TestMain(m *testing.M) {
	switch mode := os.Getenv(childEnv); mode {
	case "":
		cpuid.Initialize()
		os.Exit(m.Run())
	case "stuck":
		for {
			unix.Pause()
		}
	case "hoststall":
		if err := hostStallChild(); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown %s: %q\n", childEnv, mode)
		os.Exit(1)
	}
}

// testMemoryManager implements the parts of platform.MemoryManager that
// platformContext.Switch touches on the syscall path. Syscall patching is
// disabled in the tests, so MMap and friends are never reached.
type testMemoryManager struct {
	usermem.IO // Never used.
	as         platform.AddressSpace
}

func (*testMemoryManager) MMap(pkgcontext.Context, memmap.MMapOpts) (hostarch.Addr, error) {
	panic("unexpected MMap call")
}

func (mm *testMemoryManager) AddressSpace() platform.AddressSpace { return mm.as }

func (*testMemoryManager) FindVMAByName(hostarch.AddrRange, string) (hostarch.Addr, uint64, error) {
	panic("unexpected FindVMAByName call")
}

const userCodeAddr = hostarch.Addr(0x100000)

// newSystrapTest creates a real Systrap instance, maps userCode into a new
// address space, and returns a context ready to Switch into it.
func newSystrapTest(t *testing.T) (*Systrap, platform.AddressSpace, *platformContext, *arch.Context64) {
	t.Helper()

	s, err := New(platform.Options{
		DisableSyscallPatching: true,
		// Only slow-path for now in order to not have to use a real
		// memory manager.
		DisableFastPath: true,
	})
	if err != nil {
		t.Fatalf("failed to create Systrap platform: %v", err)
	}

	as, err := s.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatalf("failed to create address space: %v", err)
	}
	t.Cleanup(as.Release)

	fr, err := s.memoryFile.Allocate(uint64(hostarch.PageSize), pgalloc.AllocOpts{Kind: usage.System})
	if err != nil {
		t.Fatalf("failed to allocate user code page: %v", err)
	}
	bs, err := s.memoryFile.MapInternal(fr, hostarch.Write)
	if err != nil {
		t.Fatalf("failed to map user code page: %v", err)
	}
	if _, err := safemem.CopySeq(bs, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(testutil.UserCode))); err != nil {
		t.Fatalf("failed to write user code: %v", err)
	}
	if err := as.MapFile(userCodeAddr, s.memoryFile, fr, hostarch.AccessType{Read: true, Execute: true}, false); err != nil {
		t.Fatalf("failed to map user code into the stub address space: %v", err)
	}

	pctx := s.NewContext(pkgcontext.Background()).(*platformContext)
	t.Cleanup(pctx.Release)

	ac := arch.New(arch.Host)
	ac.SetIP(uintptr(userCodeAddr))
	return s, as, pctx, ac
}

// TestSwitchThreadIDVisibility runs a real Systrap instance and verifies
// that there is no window during which the ContextState indicates it's being
// worked on AND there is no thread currently working on it.
func TestSwitchThreadIDVisibility(t *testing.T) {
	_, as, pctx, ac := newSystrapTest(t)
	mm := &testMemoryManager{as: as}
	ctx := pkgcontext.Background()
	violations := atomic.Uint64{}
	stop := atomic.Bool{}
	samplerDone := make(chan struct{})
	startSampler := func(shared *sysmsg.ThreadContext) {
		go func() {
			defer close(samplerDone)
			for !stop.Load() {
				a1 := atomic.LoadUint64(&shared.AckedTime)

				// The stub ThreadID must always be set first,
				// and cleared last.
				tid := atomic.LoadUint32(&shared.ThreadID)
				state := shared.State.Get()

				a2 := atomic.LoadUint64(&shared.AckedTime)
				if a1 != 0 && a1 == a2 && state == sysmsg.ContextStateNone && tid == invalidThreadID {
					violations.Add(1)
				}
			}
		}()
	}

	for i := 0; i < 4000; i++ {
		si, _, err := pctx.Switch(ctx, mm, ac, 0)
		if err != nil {
			t.Fatalf("Switch failed at iteration %d: %v (si: %v)", i, err, si)
		}
		if sysno := ac.SyscallNo(); sysno != unix.SYS_GETPID {
			t.Fatalf("unexpected syscall %d at iteration %d", sysno, i)
		}
		ac.SetReturn(0) // Emulate the syscall return value.

		if i == 0 {
			startSampler(pctx.sharedContext.Load().shared)
		}
	}

	stop.Store(true)
	<-samplerDone
	if n := violations.Load(); n != 0 {
		t.Errorf("sampler observed %d acked contexts with an invalid ThreadID; "+
			"the stub published acked_time before ThreadID or cleared ThreadID "+
			"before publishing the context state", n)
	}
}

func TestSpinningQueueLayout(t *testing.T) {
	newSystrapTest(t)
	queueStart := stubContextQueueRegion + stubContextQueueRegionLen
	if stubSpinningThreadQueueAddr < queueStart || stubSpinningThreadQueueAddr+sysmsg.SpinningQueueMemSize > stubContextRegion {
		t.Errorf("spinning queue %#x not in [%#x, %#x)", stubSpinningThreadQueueAddr, queueStart, stubContextRegion)
	}
}

func TestSubprocessPoolSanitizesAndPrunesThreads(t *testing.T) {
	s, err := New(platform.Options{
		DisableSyscallPatching: true,
		DisableFastPath:        true,
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	t.Cleanup(func() {
		for sp := globalPool.fetchAvailable(s.memoryFile); sp != nil; sp = globalPool.fetchAvailable(s.memoryFile) {
			sp.destroyResources()
		}
		s.memoryFile.Destroy()
	})
	ctx := pkgcontext.Background()

	as1, err := s.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatalf("NewAddressSpace(1) failed: %v", err)
	}
	sp1 := as1.(*subprocess)

	fr, err := s.memoryFile.Allocate(uint64(hostarch.PageSize), pgalloc.AllocOpts{Kind: usage.System})
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}
	defer s.memoryFile.DecRef(fr)
	bs, err := s.memoryFile.MapInternal(fr, hostarch.Write)
	if err != nil {
		t.Fatalf("MapInternal failed: %v", err)
	}
	if _, err := safemem.CopySeq(bs, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(testutil.UserCode))); err != nil {
		t.Fatalf("CopySeq failed: %v", err)
	}
	if err := as1.MapFile(userCodeAddr, s.memoryFile, fr, hostarch.AccessType{Read: true, Execute: true}, false); err != nil {
		t.Fatalf("MapFile(1) failed: %v", err)
	}

	// Add extra sysmsg threads (up to maxSysmsgThreads) to simulate a
	// multi-threaded process, then poison shared sysmsg, contextQueue, and
	// ThreadContext fields before Release.
	extraThreads := max(0, min(2, maxSysmsgThreads-1))
	for range extraThreads {
		atomic.AddUint32(&sp1.contextQueue.numThreadsToWakeup, 1)
		if err := sp1.createSysmsgThread(); err != nil {
			t.Fatalf("createSysmsgThread failed: %v", err)
		}
		sp1.kickSysmsgMu.Lock()
		sp1.numSysmsgThreads++
		sp1.kickSysmsgMu.Unlock()
	}

	pctx1 := s.NewContext(ctx).(*platformContext)
	ac := arch.New(arch.Host)
	ac.SetIP(uintptr(userCodeAddr))
	if si, _, err := pctx1.Switch(ctx, &testMemoryManager{as: as1}, ac, 0); err != nil {
		t.Fatalf("Switch(1) failed: %v (si: %v)", err, si)
	}

	sc1 := pctx1.sharedContext.Load()
	sc1.shared.GsUsedByApp = 1
	sc1.shared.Debug = 0xdeadbeef
	atomic.StoreUint32(&sp1.contextQueue.usedFastPath, 99)

	sp1.sysmsgThreadsMu.RLock()
	if got, want := len(sp1.sysmsgThreads), 1+extraThreads; got != want {
		sp1.sysmsgThreadsMu.RUnlock()
		t.Fatalf("len(sysmsgThreads) = %d, want %d", got, want)
	}
	for _, st := range sp1.sysmsgThreads {
		st.msg.Syshandler = 0x41414141
		st.msg.SyshandlerStack = 0x42424242
		st.msg.RetAddr = 0x43434343
		st.msg.FaultJump = 77
		_ = unix.Tgkill(int(st.thread.tgid), int(st.thread.tid), unix.SIGCHLD)
	}
	sp1.sysmsgThreadsMu.RUnlock()

	pctx1.Release()
	as1.Release()

	as2, err := s.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatalf("NewAddressSpace(2) failed: %v", err)
	}
	defer as2.Release()
	sp2 := as2.(*subprocess)
	if sp2 != sp1 {
		t.Fatalf("expected recycled subprocess %p, got %p", sp1, sp2)
	}

	sp2.sysmsgThreadsMu.RLock()
	numThreads := len(sp2.sysmsgThreads)
	var kept *sysmsgThread
	for _, st := range sp2.sysmsgThreads {
		kept = st
	}
	sp2.sysmsgThreadsMu.RUnlock()
	if numThreads != 1 || kept == nil {
		t.Fatalf("recycled len(sysmsgThreads) = %d, want 1", numThreads)
	}
	wantSyshandler := uint64(stubSysmsgStart + uintptr(sysmsg.Sighandler_blob_offset____export_syshandler))
	if kept.msg.Syshandler != wantSyshandler {
		t.Errorf("Syshandler = %#x, want %#x", kept.msg.Syshandler, wantSyshandler)
	}
	if kept.msg.RetAddr != 0 || kept.msg.FaultJump != 0 {
		t.Errorf("RetAddr=%#x FaultJump=%d, want 0", kept.msg.RetAddr, kept.msg.FaultJump)
	}
	if got := atomic.LoadUint32(&sp2.contextQueue.usedFastPath); got != 0 {
		t.Errorf("usedFastPath = %d, want 0", got)
	}

	if err := as2.MapFile(userCodeAddr, s.memoryFile, fr, hostarch.AccessType{Read: true, Execute: true}, false); err != nil {
		t.Fatalf("MapFile(2) failed: %v", err)
	}
	pctx2 := s.NewContext(ctx).(*platformContext)
	defer pctx2.Release()
	ac2 := arch.New(arch.Host)
	ac2.SetIP(uintptr(userCodeAddr))
	if si, _, err := pctx2.Switch(ctx, &testMemoryManager{as: as2}, ac2, 0); err != nil {
		t.Fatalf("Switch(2) on recycled subprocess failed: %v (si: %v)", err, si)
	}
	if sc2 := pctx2.sharedContext.Load(); sc2.shared.Debug != 0 {
		t.Errorf("recycled ThreadContext.Debug = %#x, want 0", sc2.shared.Debug)
	}
}

func TestSubprocessKillCleansUpMemoryFile(t *testing.T) {
	s, err := New(platform.Options{
		DisableSyscallPatching: true,
		DisableFastPath:        true,
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer s.memoryFile.Destroy()

	beforeUsage, err := s.memoryFile.TotalUsage()
	if err != nil {
		t.Fatalf("TotalUsage(before) failed: %v", err)
	}

	as, err := s.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatalf("NewAddressSpace failed: %v", err)
	}
	sp := as.(*subprocess)
	sp.kill()
	as.Release()

	// pgalloc.MemoryFile reclaims DecRef'd pages asynchronously on releaserMain.
	deadline := time.Now().Add(5 * time.Second)
	var afterUsage uint64
	for {
		afterUsage, err = s.memoryFile.TotalUsage()
		if err != nil {
			t.Fatalf("TotalUsage(after) failed: %v", err)
		}
		if afterUsage == beforeUsage || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if afterUsage != beforeUsage {
		t.Errorf("memoryFile usage after killed subprocess Release = %d, want %d (leaked %d bytes)", afterUsage, beforeUsage, afterUsage-beforeUsage)
	}
}

func BenchmarkAddressSpaceChurn(b *testing.B) {
	prevDisable := disableSubprocessPool
	disableSubprocessPool = os.Getenv("SYSTRAP_BENCH_DISABLE_POOL") == "1"
	b.Cleanup(func() { disableSubprocessPool = prevDisable })

	s, err := New(platform.Options{
		DisableSyscallPatching: true,
		DisableFastPath:        true,
	})
	if err != nil {
		b.Fatalf("New failed: %v", err)
	}
	b.Cleanup(func() {
		for sp := globalPool.fetchAvailable(s.memoryFile); sp != nil; sp = globalPool.fetchAvailable(s.memoryFile) {
			sp.destroyResources()
		}
		s.memoryFile.Destroy()
	})
	ctx := pkgcontext.Background()

	fr, err := s.memoryFile.Allocate(uint64(hostarch.PageSize), pgalloc.AllocOpts{Kind: usage.System})
	if err != nil {
		b.Fatalf("Allocate failed: %v", err)
	}
	b.Cleanup(func() { s.memoryFile.DecRef(fr) })
	bs, err := s.memoryFile.MapInternal(fr, hostarch.Write)
	if err != nil {
		b.Fatalf("MapInternal failed: %v", err)
	}
	if _, err := safemem.CopySeq(bs, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(testutil.UserCode))); err != nil {
		b.Fatalf("CopySeq failed: %v", err)
	}

	threadCounts := []int{1}
	if multi := min(4, maxSysmsgThreads); multi > 1 {
		threadCounts = append(threadCounts, multi)
	}
	for _, numThreads := range threadCounts {
		name := fmt.Sprintf("Threads_%d", numThreads)
		b.Run(name, func(b *testing.B) {
			for sp := globalPool.fetchAvailable(s.memoryFile); sp != nil; sp = globalPool.fetchAvailable(s.memoryFile) {
				sp.destroyResources()
			}
			b.ResetTimer()
			for range b.N {
				as, err := s.NewAddressSpace(platform.AddressSpaceOptions{})
				if err != nil {
					b.Fatalf("NewAddressSpace failed: %v", err)
				}
				sp := as.(*subprocess)
				for range numThreads - 1 {
					atomic.AddUint32(&sp.contextQueue.numThreadsToWakeup, 1)
					if err := sp.createSysmsgThread(); err != nil {
						b.Fatalf("createSysmsgThread failed: %v", err)
					}
					sp.kickSysmsgMu.Lock()
					sp.numSysmsgThreads++
					sp.kickSysmsgMu.Unlock()
				}
				if err := as.MapFile(userCodeAddr, s.memoryFile, fr, hostarch.AccessType{Read: true, Execute: true}, false); err != nil {
					b.Fatalf("MapFile failed: %v", err)
				}
				pctx := s.NewContext(ctx).(*platformContext)
				ac := arch.New(arch.Host)
				ac.SetIP(uintptr(userCodeAddr))
				if _, _, err := pctx.Switch(ctx, &testMemoryManager{as: as}, ac, 0); err != nil {
					b.Fatalf("Switch failed: %v", err)
				}
				pctx.Release()
				as.Release()
			}
		})
	}
}
