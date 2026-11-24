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

package mm

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/usermem"
)

func TestTranslationFaultEntryPoints(t *testing.T) {
	operations := []struct {
		translationFaultOperation
		waits     int
		syncFills int
	}{
		// Each user fault is a separate operation, so each may wait.
		{translationFaultOperation{"user fault", func(f *translationFaultTest) error {
			if err := f.mm.HandleUserFault(f.ctx, f.mapped.Start, hostarch.Execute, 0); err != nil {
				return err
			}
			return f.mm.HandleUserFault(f.ctx, f.mapped.Start+pageSizeAddr, hostarch.Read, 0)
		}, 0, true}, 2, 0},
		// Other operations wait for the first cold page, then translate
		// the second synchronously.
		{translationFaultOperation{"address space IO", func(f *translationFaultTest) error {
			return f.mm.handleASIOFault(f.ctx, f.mapped.Start, f.mapped, hostarch.Read)
		}, 0, false}, 1, 1},
		{translationFaultOperation{"scalar IO", (*translationFaultTest).scalarCopy, 1, false}, 1, 1},
		{translationFaultOperation{"vector IO", (*translationFaultTest).vectorCopy, 1, false}, 1, 1},
		{translationFaultOperation{"pin", (*translationFaultTest).pin, 0, false}, 1, 1},
		{translationFaultOperation{"mlock", func(f *translationFaultTest) error {
			return f.mm.MLock(f.ctx, f.mapped.Start, uint64(f.mapped.Length()), memmap.MLockEager)
		}, 0, false}, 1, 1},
		{translationFaultOperation{"mlockall", func(f *translationFaultTest) error {
			return f.mm.MLockAll(f.ctx, MLockAllOpts{Current: true, Mode: memmap.MLockEager})
		}, 0, false}, 1, 1},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			f := newTranslationFaultTest(t)
			f.wantInterruptible = operation.interruptible
			f.mapFile(memmap.MMapOpts{Length: 2 * pageSize, Perms: hostarch.ReadExecute})
			if err := operation.run(f); err != nil {
				t.Fatal(err)
			}
			// Both pages started cold. Copies must run once, after both
			// are available.
			f.check(operation.waits, operation.syncFills, operation.wantCopies)
		})
	}
}

func TestTranslationFaultMMapPopulate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required bool
	}{{"populate", false}, {"required populate", true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTranslationFaultTest(t)
			f.mapFile(memmap.MMapOpts{
				Length:                2 * pageSize,
				Perms:                 hostarch.ReadExecute,
				PlatformEffect:        memmap.PlatformEffectCommit,
				RequirePlatformEffect: tc.required,
			})
			// Eager mmap itself must obtain both cold pages.
			f.check(1, 1, 0)
		})
	}
}

func TestTranslationFaultMRemap(t *testing.T) {
	f := newTranslationFaultTest(t)
	f.backing.availableEnd = pageSize
	f.mapFile(memmap.MMapOpts{Length: pageSize, Perms: hostarch.ReadExecute})
	if err := f.mm.MLock(f.ctx, f.mapped.Start, pageSize, memmap.MLockEager); err != nil {
		t.Fatal(err)
	}
	// Growing a locked mapping populates its new, cold page.
	if _, err := f.mm.MRemap(f.ctx, f.mapped.Start, pageSize, 2*pageSize, MRemapOpts{Move: MRemapMayMove}); err != nil {
		t.Fatal(err)
	}
	f.check(1, 0, 0)
}

// TestTranslationFaultWaitsOnce checks that an operation terminates when Wait
// succeeds but the backing is unavailable again on the retry.
func TestTranslationFaultWaitsOnce(t *testing.T) {
	for _, operation := range translationFaultRevalidationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			f := newTranslationFaultTest(t)
			f.wantInterruptible = operation.interruptible
			f.backing.stall = true
			f.mapFile(memmap.MMapOpts{Length: pageSize, Perms: hostarch.Read})
			if err := operation.run(f); err != nil {
				t.Fatal(err)
			}
			f.check(1, 1, operation.wantCopies)
		})
	}
}

func TestTranslationFaultRevalidates(t *testing.T) {
	changes := []struct {
		name  string
		apply func(*translationFaultTest) error
	}{
		{"unmap", func(f *translationFaultTest) error {
			return f.mm.MUnmap(f.ctx, f.mapped.Start, pageSize)
		}},
		{"protect", func(f *translationFaultTest) error {
			return f.mm.MProtect(f.mapped.Start, pageSize, hostarch.NoAccess, false)
		}},
	}
	for _, operation := range translationFaultRevalidationOperations() {
		for _, change := range changes {
			t.Run(operation.name+"/"+change.name, func(t *testing.T) {
				f := newTranslationFaultTest(t)
				f.wantInterruptible = operation.interruptible
				f.mapFile(memmap.MMapOpts{Length: pageSize, Perms: hostarch.Read})
				f.duringWait = func() error { return change.apply(f) }
				if err := operation.run(f); err == nil {
					t.Fatal("retry accepted an unmapped or inaccessible page")
				}
				f.check(1, 0, 0)
			})
		}
	}
}

func TestTranslationFaultMappingReplacement(t *testing.T) {
	for _, operation := range translationFaultRevalidationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			f := newTranslationFaultTest(t)
			f.wantInterruptible = operation.interruptible
			f.mapFile(memmap.MMapOpts{Length: pageSize, Perms: hostarch.Read})
			f.duringWait = func() error {
				_, err := f.mm.MMap(f.ctx, memmap.MMapOpts{
					Addr:     f.mapped.Start,
					Fixed:    true,
					Unmap:    true,
					Length:   pageSize,
					Private:  true,
					Perms:    hostarch.Read,
					MaxPerms: hostarch.AnyAccess,
				})
				return err
			}
			if err := operation.run(f); err != nil {
				t.Fatal(err)
			}
			f.check(1, 0, operation.wantCopies)
			// MAP_FIXED replaced the nonzero file backing with zeroed anonymous memory.
			buf := make([]byte, pageSizeInt)
			if n, err := f.mm.CopyIn(f.ctx, f.mapped.Start, buf, usermem.IOOpts{}); n != len(buf) || err != nil {
				t.Fatalf("replacement read = %d, %v", n, err)
			}
			if !bytes.Equal(buf, make([]byte, len(buf))) {
				t.Fatal("retry used stale file backing")
			}
		})
	}
}

func TestTranslationFaultWaitErrors(t *testing.T) {
	for _, operation := range translationFaultRevalidationOperations() {
		for _, failure := range []struct {
			name string
			err  error
		}{
			{"interrupt", linuxerr.ErrInterrupted},
			{"error", &memmap.BusError{Err: linuxerr.EIO}},
		} {
			t.Run(operation.name+"/"+failure.name, func(t *testing.T) {
				f := newTranslationFaultTest(t)
				f.wantInterruptible = operation.interruptible
				f.mapFile(memmap.MMapOpts{Length: pageSize, Perms: hostarch.Read})
				f.duringWait = func() error { return failure.err }
				want := failure.err
				wantCopies := 0
				if failure.err == linuxerr.ErrInterrupted && !operation.interruptible {
					want = nil
					wantCopies = operation.wantCopies
				} else if operation.wantCopies != 0 {
					want = linuxerr.EFAULT
				}
				if err := operation.run(f); err != want {
					t.Fatalf("wait error = %v, want %v", err, want)
				}
				f.check(1, 0, wantCopies)
			})
		}
	}
}

// stagedMappable simulates a file whose contents load one page at a time.
// Translate returns a fault at the first unavailable page, unless the caller
// disallows faults, in which case it makes the required range available
// itself. Each successful Wait makes one more page available, unless stall is
// set, after running any action supplied by the test.
type stagedMappable struct {
	*SpecialMappable
	availableEnd uint64
	stall        bool
	waits        int
	syncFills    int
	onWait       func(bool) error
}

func (m *stagedMappable) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	if required.End > m.availableEnd && !memmap.TranslationFaultsAllowed(ctx) {
		m.syncFills++
		m.availableEnd = required.End
	}
	var translations []memmap.Translation
	if optional.Start < m.availableEnd {
		available := optional.Intersect(memmap.MappableRange{End: m.availableEnd})
		translations, _ = m.SpecialMappable.Translate(ctx, required, available, at)
	}
	if required.End > m.availableEnd {
		return translations, m
	}
	return translations, nil
}

func (*stagedMappable) Error() string { return "backing unavailable" }

func (m *stagedMappable) Wait(_ context.Context, interruptible bool) error {
	m.waits++
	if err := m.onWait(interruptible); err != nil {
		return err
	}
	if !m.stall {
		m.availableEnd += pageSize
	}
	return nil
}

// translationFaultTest owns a two-page backing file and a memory manager. The
// file contains nonzero bytes so a stale translation is visible after replacement
// with anonymous memory. All waits check that MM has released both of its locks
// and has not yet invoked the copy callback.
type translationFaultTest struct {
	t                 *testing.T
	ctx               context.Context
	mm                *MemoryManager
	backing           *stagedMappable
	mapped            hostarch.AddrRange
	copies            int
	wantInterruptible bool
	duringWait        func() error
}

func newTranslationFaultTest(t *testing.T) *translationFaultTest {
	t.Helper()
	ctx := contexttest.Context(t)
	mm := testMemoryManager(ctx, t)
	t.Cleanup(func() { mm.DecUsers(ctx) })
	mf := pgalloc.MemoryFileFromContext(ctx)
	fr, err := mf.Allocate(2*pageSize, pgalloc.AllocOpts{})
	if err != nil {
		t.Fatal(err)
	}
	backing := &stagedMappable{SpecialMappable: NewSpecialMappable("cold", mf, fr)}
	t.Cleanup(func() { backing.DecRef(ctx) })
	blocks, err := mf.MapInternal(fr, hostarch.Write)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{0x5a}, int(fr.Length()))
	if _, err := safemem.CopySeq(blocks, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(data))); err != nil {
		t.Fatal(err)
	}
	f := &translationFaultTest{t: t, ctx: ctx, mm: mm, backing: backing}
	backing.onWait = f.wait
	return f
}

func (f *translationFaultTest) wait(interruptible bool) error {
	if interruptible != f.wantInterruptible {
		f.t.Errorf("interruptible wait = %t, want %t", interruptible, f.wantInterruptible)
	}
	// Taking these locks would deadlock if the caller still held either one.
	f.mm.mappingMu.Lock()
	f.mm.activeMu.Lock()
	if f.mm.pmas.Span() > 2*pageSizeAddr {
		f.t.Error("unexpected backing outside the tested mapping")
	}
	f.mm.activeMu.Unlock()
	f.mm.mappingMu.Unlock()
	if f.copies != 0 {
		f.t.Error("copy callback ran before all content waits finished")
	}
	if f.duringWait != nil {
		err := f.duringWait()
		if err == linuxerr.ErrInterrupted && !interruptible {
			return nil
		}
		return err
	}
	return nil
}

func (f *translationFaultTest) mapFile(opts memmap.MMapOpts) {
	f.t.Helper()
	opts.Mappable = f.backing
	opts.MappingIdentity = f.backing.SpecialMappable
	opts.Private = true
	opts.MaxPerms = hostarch.AnyAccess
	addr, err := f.mm.MMap(f.ctx, opts)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mapped = hostarch.AddrRange{Start: addr, End: addr + hostarch.Addr(opts.Length)}
}

func (f *translationFaultTest) copy(blocks safemem.BlockSeq) (uint64, error) {
	f.copies++
	if got, want := blocks.NumBytes(), uint64(f.mapped.Length()); got != want {
		f.t.Errorf("copy length = %d, want %d", got, want)
	}
	return blocks.NumBytes(), nil
}

func (f *translationFaultTest) check(waits, syncFills, copies int) {
	f.t.Helper()
	if f.backing.waits != waits {
		f.t.Errorf("waits = %d, want %d", f.backing.waits, waits)
	}
	if f.backing.syncFills != syncFills {
		f.t.Errorf("synchronous fills = %d, want %d", f.backing.syncFills, syncFills)
	}
	if f.copies != copies {
		f.t.Errorf("copy callbacks = %d, want %d", f.copies, copies)
	}
}

func (f *translationFaultTest) scalarCopy() error {
	_, err := f.mm.withInternalMappings(f.ctx, f.mapped, hostarch.Read, false, f.copy)
	return err
}

func (f *translationFaultTest) vectorCopy() error {
	// Separate pages exercise progress across vector elements as well as spans.
	var ranges []hostarch.AddrRange
	for addr := f.mapped.Start; addr < f.mapped.End; addr += pageSizeAddr {
		ranges = append(ranges, hostarch.AddrRange{Start: addr, End: addr + pageSizeAddr})
	}
	_, err := f.mm.withVecInternalMappings(f.ctx, hostarch.AddrRangeSeqFromSlice(ranges), hostarch.Read, false, f.copy)
	return err
}

func (f *translationFaultTest) pin() error {
	ranges, err := f.mm.Pin(f.ctx, f.mapped, hostarch.Read, false)
	Unpin(ranges)
	return err
}

type translationFaultOperation struct {
	name          string
	run           func(*translationFaultTest) error
	wantCopies    int
	interruptible bool
}

// These operations all retry after waiting. User faults, pinning, and population
// expose backing errors directly; guest-copy operations convert them to EFAULT.
func translationFaultRevalidationOperations() []translationFaultOperation {
	return []translationFaultOperation{
		{"user", func(f *translationFaultTest) error {
			return f.mm.HandleUserFault(f.ctx, f.mapped.Start, hostarch.Read, 0)
		}, 0, true},
		{"scalar", (*translationFaultTest).scalarCopy, 1, false},
		{"vector", (*translationFaultTest).vectorCopy, 1, false},
		{"pin", (*translationFaultTest).pin, 0, false},
		{"populate", func(f *translationFaultTest) error {
			return f.mm.populateRange(f.ctx, f.mapped, memmap.PlatformEffectCommit)
		}, 0, false},
	}
}
