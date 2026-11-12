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

package pgalloc

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

func createAdoptTestFD(t *testing.T) int {
	t.Helper()
	fd, err := memutil.CreateMemFD("pgalloc-adopt-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	return fd
}

func newAdoptTestMemoryFile(t *testing.T, fd int, keep bool) *MemoryFile {
	t.Helper()
	file := os.NewFile(uintptr(fd), "pgalloc-adopt-test")
	f, err := NewMemoryFile(file, MemoryFileOpts{
		DelayedEviction:         DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
		KeepFileContents:        keep,
	})
	if err != nil {
		file.Close()
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(f.Destroy)
	return f
}

func fillRange(t *testing.T, f *MemoryFile, fr memmap.FileRange, b byte) {
	t.Helper()
	f.forEachMappingSlice(fr, func(bs []byte) {
		for i := range bs {
			bs[i] = b
		}
	})
}

func checkRange(t *testing.T, f *MemoryFile, fr memmap.FileRange, b byte) {
	t.Helper()
	f.forEachMappingSlice(fr, func(bs []byte) {
		for i, got := range bs {
			if got != b {
				t.Fatalf("byte %d of %v: got %#x, want %#x", i, fr, got, b)
			}
		}
	})
}

func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s did not panic", name)
		}
	}()
	fn()
}

func TestAdoptExisting(t *testing.T) {
	fd := createAdoptTestFD(t)
	fd2, err := unix.Dup(fd)
	if err != nil {
		unix.Close(fd)
		t.Fatalf("Dup: %v", err)
	}

	// Allocate four ranges in the first MemoryFile and fill them.
	f1 := newAdoptTestMemoryFile(t, fd, false /* keep */)
	pg := uint64(hostarch.PageSize)
	var frs [4]memmap.FileRange
	for i, n := range []uint64{4, 3, 5, 2} {
		fr, err := f1.Allocate(n*pg, AllocOpts{Kind: usage.Tmpfs})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		fillRange(t, f1, fr, byte(i+1))
		frs[i] = fr
	}

	// Adopt the first and third ranges. The others are not adopted, so they
	// must be zeroed.
	used := []memmap.FileRange{frs[0], frs[2]}
	f2 := newAdoptTestMemoryFile(t, fd2, true /* keep */)
	if err := f2.AdoptExisting(used, usage.Tmpfs); err != nil {
		t.Fatalf("AdoptExisting: %v", err)
	}
	checkRange(t, f2, frs[0], 1)
	checkRange(t, f2, frs[2], 3)
	checkRange(t, f2, frs[1], 0)
	checkRange(t, f2, frs[3], 0)
	if !f2.HasUniqueRef(frs[0]) || !f2.HasUniqueRef(frs[2]) {
		t.Errorf("adopted ranges do not have exactly one reference")
	}

	// New allocations must not overlap adopted ranges and must read as zeros.
	for i := 0; i < 8; i++ {
		fr, err := f2.Allocate(2*pg, AllocOpts{Kind: usage.Tmpfs})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		for _, u := range used {
			if fr.Overlaps(u) {
				t.Fatalf("new allocation %v overlaps adopted range %v", fr, u)
			}
		}
		checkRange(t, f2, fr, 0)
		fillRange(t, f2, fr, 0xff)
	}
	checkRange(t, f2, frs[0], 1)
	checkRange(t, f2, frs[2], 3)

	// Freeing an adopted range returns it to the allocator.
	f2.DecRef(frs[0])
}

func TestAdoptExistingEmpty(t *testing.T) {
	fd := createAdoptTestFD(t)
	// Leave garbage in the file, then adopt nothing.
	if err := unix.Ftruncate(fd, 3*int64(hostarch.PageSize)); err != nil {
		unix.Close(fd)
		t.Fatalf("Ftruncate: %v", err)
	}
	if _, err := unix.Pwrite(fd, []byte{1, 2, 3}, 0); err != nil {
		unix.Close(fd)
		t.Fatalf("Pwrite: %v", err)
	}
	f := newAdoptTestMemoryFile(t, fd, true /* keep */)
	if err := f.AdoptExisting(nil, usage.Tmpfs); err != nil {
		t.Fatalf("AdoptExisting: %v", err)
	}
	fr, err := f.Allocate(uint64(hostarch.PageSize), AllocOpts{Kind: usage.Tmpfs})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	checkRange(t, f, fr, 0)
}

func TestAdoptExistingLifecycle(t *testing.T) {
	pg := uint64(hostarch.PageSize)

	// Allocating before AdoptExisting on a KeepFileContents MemoryFile must
	// panic rather than serve unzeroed backing file contents.
	fdUnadopted := createAdoptTestFD(t)
	if err := unix.Ftruncate(fdUnadopted, int64(pg)); err != nil {
		unix.Close(fdUnadopted)
		t.Fatalf("Ftruncate: %v", err)
	}
	fUnadopted := newAdoptTestMemoryFile(t, fdUnadopted, true /* keep */)
	mustPanic(t, "Allocate before AdoptExisting", func() {
		_, _ = fUnadopted.Allocate(pg, AllocOpts{Kind: usage.Tmpfs})
	})

	// Adopting a 0-byte backing file succeeds once, allows subsequent
	// allocations, and rejects a second AdoptExisting call.
	fZero := newAdoptTestMemoryFile(t, createAdoptTestFD(t), true /* keep */)
	if err := fZero.AdoptExisting(nil, usage.Tmpfs); err != nil {
		t.Fatalf("AdoptExisting on empty file: %v", err)
	}
	if err := fZero.AdoptExisting(nil, usage.Tmpfs); err == nil {
		t.Errorf("second AdoptExisting on empty file succeeded, want error")
	}
	fr, err := fZero.Allocate(pg, AllocOpts{Kind: usage.Tmpfs})
	if err != nil {
		t.Fatalf("Allocate after empty AdoptExisting: %v", err)
	}
	checkRange(t, fZero, fr, 0)
	fZero.DecRef(fr)

	// Calling AdoptExisting a second time on a non-empty file also fails.
	fdNonEmpty := createAdoptTestFD(t)
	if err := unix.Ftruncate(fdNonEmpty, int64(pg)); err != nil {
		unix.Close(fdNonEmpty)
		t.Fatalf("Ftruncate: %v", err)
	}
	fNonEmpty := newAdoptTestMemoryFile(t, fdNonEmpty, true /* keep */)
	if err := fNonEmpty.AdoptExisting(nil, usage.Tmpfs); err != nil {
		t.Fatalf("AdoptExisting: %v", err)
	}
	if err := fNonEmpty.AdoptExisting(nil, usage.Tmpfs); err == nil {
		t.Errorf("second AdoptExisting succeeded, want error")
	}
}

func TestAdoptExistingValidation(t *testing.T) {
	pg := uint64(hostarch.PageSize)
	for _, tc := range []struct {
		name string
		used []memmap.FileRange
	}{
		{name: "unaligned", used: []memmap.FileRange{{Start: 1, End: pg}}},
		{name: "empty", used: []memmap.FileRange{{Start: pg, End: pg}}},
		{name: "unsorted", used: []memmap.FileRange{{Start: 2 * pg, End: 3 * pg}, {Start: 0, End: pg}}},
		{name: "overlapping", used: []memmap.FileRange{{Start: 0, End: 2 * pg}, {Start: pg, End: 3 * pg}}},
		{name: "beyond_eof", used: []memmap.FileRange{{Start: 0, End: 5 * pg}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd := createAdoptTestFD(t)
			if err := unix.Ftruncate(fd, 4*int64(pg)); err != nil {
				unix.Close(fd)
				t.Fatalf("Ftruncate: %v", err)
			}
			f := newAdoptTestMemoryFile(t, fd, true /* keep */)
			if err := f.AdoptExisting(tc.used, usage.Tmpfs); err == nil {
				t.Errorf("AdoptExisting(%v) succeeded, want error", tc.used)
			}
		})
	}
}

func TestAdoptExistingRequiresKeepFileContents(t *testing.T) {
	f := newAdoptTestMemoryFile(t, createAdoptTestFD(t), false /* keep */)
	if err := f.AdoptExisting(nil, usage.Tmpfs); err == nil {
		t.Errorf("AdoptExisting succeeded without KeepFileContents")
	}
}

func TestAdoptExistingVoidSentinelAndAdvise(t *testing.T) {
	pg := uint64(hostarch.PageSize)
	fd := createAdoptTestFD(t)
	if err := unix.Ftruncate(fd, int64(2*pg)); err != nil {
		unix.Close(fd)
		t.Fatalf("Ftruncate: %v", err)
	}
	file := os.NewFile(uintptr(fd), "pgalloc-adopt-advise-test")
	f, err := NewMemoryFile(file, MemoryFileOpts{
		DelayedEviction:         DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
		KeepFileContents:        true,
		AdviseNoHugepage:        true,
	})
	if err != nil {
		file.Close()
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(f.Destroy)

	used := []memmap.FileRange{{Start: 0, End: pg}}
	if err := f.AdoptExisting(used, usage.Tmpfs); err != nil {
		t.Fatalf("AdoptExisting: %v", err)
	}
	f.mu.Lock()
	voidSeg := f.unfreeSmall.FindSegment(chunkSize)
	f.mu.Unlock()
	if !voidSeg.Ok() || voidSeg.Start() != chunkSize || voidSeg.End() != math.MaxUint64 {
		t.Fatalf("void sentinel = %v, want [%#x, %#x)", voidSeg.Range(), uint64(chunkSize), uint64(math.MaxUint64))
	}
}

func TestAdoptZeroNonZeroPagesPreservesSparsity(t *testing.T) {
	pg := uint64(hostarch.PageSize)
	const holeSize = 4 << 20 // 4 MiB interior sparse hole

	// Layout:
	//   page 0:             adopted live data (0xaa)
	//   page 1:             unadopted non-zero page (0xbb) -> must be zeroed
	//   [2*pg, +holeSize):  interior sparse hole -> must stay unallocated
	//   next page:          unadopted non-zero page (0xcc) -> must be zeroed
	//   final page:         adopted live data (0xdd)
	dirty1Off := pg
	holeStart := 2 * pg
	dirty2Off := holeStart + holeSize
	live2Off := dirty2Off + pg

	path := filepath.Join(t.TempDir(), "sparse-filestore")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	fd := int(file.Fd())
	writePage := func(off uint64, val byte) {
		t.Helper()
		p := make([]byte, pg)
		for i := range p {
			p[i] = val
		}
		if _, err := unix.Pwrite(fd, p, int64(off)); err != nil {
			t.Fatalf("Pwrite(%#x): %v", off, err)
		}
	}
	writePage(0, 0xaa)
	writePage(dirty1Off, 0xbb)
	writePage(dirty2Off, 0xcc)
	writePage(live2Off, 0xdd)

	var statBefore unix.Stat_t
	if err := unix.Fstat(fd, &statBefore); err != nil {
		file.Close()
		t.Fatalf("Fstat(before): %v", err)
	}

	f, err := NewMemoryFile(file, MemoryFileOpts{
		DelayedEviction:         DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
		DisableIMAWorkAround:    true,
		DiskBackedFile:          true,
		KeepFileContents:        true,
	})
	if err != nil {
		file.Close()
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(f.Destroy)

	// Invoke the fallback scanner directly on the gap [dirty1Off, live2Off)
	// before mapping chunks (matching AdoptExisting's order) without calling
	// decommitFile.
	clearer := adoptGapClearer{f: f}
	if err := clearer.zeroNonZeroPages(memmap.FileRange{Start: dirty1Off, End: live2Off}); err != nil {
		t.Fatalf("zeroNonZeroPages: %v", err)
	}

	var statAfter unix.Stat_t
	if err := unix.Fstat(fd, &statAfter); err != nil {
		t.Fatalf("Fstat(after): %v", err)
	}
	// The 4 MiB interior hole must not have been materialized on disk.
	// Allow a tiny tolerance for filesystem metadata/COW, well below holeSize.
	const maxAllowedGrowthBlocks = 64 // 32 KiB in 512-byte blocks
	if statAfter.Blocks > statBefore.Blocks+maxAllowedGrowthBlocks {
		t.Fatalf("zeroNonZeroPages allocated blocks for sparse hole: before=%d after=%d blocks (hole=%d bytes)",
			statBefore.Blocks, statAfter.Blocks, holeSize)
	}

	// Verify live pages are untouched and all gap pages (including both dirty
	// pages and the interior hole) read as zero via ReadAt.
	checkReadAt := func(off uint64, want byte) {
		t.Helper()
		buf := make([]byte, pg)
		if _, err := f.file.ReadAt(buf, int64(off)); err != nil {
			t.Fatalf("ReadAt(%#x): %v", off, err)
		}
		for i, got := range buf {
			if got != want {
				t.Fatalf("page at %#x byte %d: got %#x, want %#x", off, i, got, want)
			}
		}
	}
	checkReadAt(0, 0xaa)
	checkReadAt(dirty1Off, 0)
	checkReadAt(holeStart, 0)
	checkReadAt(holeStart+holeSize/2, 0)
	checkReadAt(dirty2Off, 0)
	checkReadAt(live2Off, 0xdd)
}

func TestAdoptZeroNonZeroPagesReturnsErrorWithoutPublishing(t *testing.T) {
	pg := uint64(hostarch.PageSize)
	path := filepath.Join(t.TempDir(), "ro-filestore")
	rwFile, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	// Make the file chunk-aligned with a non-zero first page so AdoptExisting
	// skips Truncate, fails decommitFile, and hits WriteAt on the first chunk.
	if err := rwFile.Truncate(chunkSize); err != nil {
		rwFile.Close()
		t.Fatalf("Truncate: %v", err)
	}
	if _, err := rwFile.WriteAt([]byte{0x55}, 0); err != nil {
		rwFile.Close()
		t.Fatalf("WriteAt: %v", err)
	}
	rwFile.Close()

	// Open read-only so decommitFile and WriteAt fail with EBADF.
	roFile, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	f, err := NewMemoryFile(roFile, MemoryFileOpts{
		DelayedEviction:         DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
		DisableIMAWorkAround:    true,
		DiskBackedFile:          true,
		KeepFileContents:        true,
	})
	if err != nil {
		roFile.Close()
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(f.Destroy)

	// WriteAt failure returns an error instead of panicking.
	clearer := adoptGapClearer{f: f}
	if err := clearer.zeroNonZeroPages(memmap.FileRange{Start: 0, End: 2 * pg}); err == nil {
		t.Fatalf("zeroNonZeroPages on read-only file succeeded, want error")
	}

	// ReadAt failure (past EOF) returns an error instead of panicking.
	if err := clearer.zeroNonZeroPages(memmap.FileRange{Start: chunkSize, End: chunkSize + pg}); err == nil {
		t.Fatalf("zeroNonZeroPages past EOF succeeded, want error")
	}

	// AdoptExisting error during gap clearing leaves allocator state unpublished.
	// Checking EBADF (from WriteAt) rather than EACCES (from writable MAP_SHARED
	// mmap) also verifies gap clearing runs before mapping.
	if err := f.AdoptExisting(nil, usage.Tmpfs); !errors.Is(err, unix.EBADF) {
		t.Fatalf("AdoptExisting on read-only file: got %v, want %v", err, unix.EBADF)
	}
	f.mu.Lock()
	unadopted := f.unadopted
	nrChunks := len(f.chunksLoad())
	voidSeg := f.unfreeSmall.FindSegment(0)
	f.mu.Unlock()
	if !unadopted || nrChunks != 0 || !voidSeg.Ok() || voidSeg.Start() != 0 || voidSeg.End() != math.MaxUint64 {
		t.Fatalf("allocator state published after failed AdoptExisting: unadopted=%t chunks=%d void=%v",
			unadopted, nrChunks, voidSeg.Range())
	}
}
