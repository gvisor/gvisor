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
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// adoptScanBufSize is the bounded read/write buffer size used by
// adoptGapClearer when the backing filesystem declines hole punching during
// AdoptExisting.
const adoptScanBufSize = 256 << 10

// AdoptExisting makes f take ownership of the existing contents of its
// backing file. After AdoptExisting returns, each page in used is allocated
// with one reference and the given memory accounting kind, and all other pages
// in the file are free. AdoptExisting decommits (or zeroes) the pages that are
// not in used, since free pages must be zeroed.
//
// used must be sorted, non-overlapping, page-aligned, and within the current
// size of the backing file.
//
// Preconditions:
//   - f was created with MemoryFileOpts.KeepFileContents.
//   - AdoptExisting has not yet been called on f, and no pages have been
//     allocated from f.
func (f *MemoryFile) AdoptExisting(used []memmap.FileRange, kind usage.MemoryKind) error {
	if !f.opts.KeepFileContents {
		return fmt.Errorf("AdoptExisting requires MemoryFileOpts.KeepFileContents")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.file.Fd()), &stat); err != nil {
		return fmt.Errorf("failed to stat backing file: %w", err)
	}
	if stat.Size < 0 {
		return fmt.Errorf("invalid backing file size %d", stat.Size)
	}
	curSize := uint64(stat.Size)
	if err := validateAdoptedRanges(used, curSize); err != nil {
		return err
	}

	fileSize := curSize
	if fileSize&chunkMask != 0 {
		fileSize = (fileSize + chunkMask) &^ chunkMask
	}
	nrChunks := fileSize / chunkSize
	if nrChunks > maxChunks {
		return fmt.Errorf("backing file size %d is too large", curSize)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.unadopted || len(f.chunksLoad()) != 0 {
		return fmt.Errorf("AdoptExisting called more than once or after allocation")
	}
	if fileSize == 0 {
		f.unadopted = false
		return nil
	}

	truncated := false
	if fileSize != curSize {
		if err := f.file.Truncate(int64(fileSize)); err != nil {
			return fmt.Errorf("failed to extend backing file to %d bytes: %w", fileSize, err)
		}
		truncated = true
	}
	ok := false
	defer func() {
		if !ok && truncated {
			_ = f.file.Truncate(int64(curSize))
		}
	}()

	// Clear unadopted gaps up to clearEnd before publishing chunks so an I/O
	// error leaves allocator state unchanged. Pages in [clearEnd, fileSize)
	// were added by Truncate above and are already uncommitted zeros.
	clearEnd := hostarch.MustPageRoundUp(curSize)
	clearer := adoptGapClearer{f: f}
	var off uint64
	for _, fr := range used {
		if off < fr.Start {
			if err := clearer.clear(memmap.FileRange{Start: off, End: fr.Start}); err != nil {
				return err
			}
		}
		off = fr.End
	}
	if off < clearEnd {
		if err := clearer.clear(memmap.FileRange{Start: off, End: clearEnd}); err != nil {
			return err
		}
	}

	// All adopted chunks are small-page-backed; unfreeHuge, unwasteSmall, and
	// unwasteHuge already cover the whole file.
	if err := f.mapAndAddChunksLocked(nil /* oldChunks */, nrChunks, false /* huge */); err != nil {
		return fmt.Errorf("failed to mmap backing file: %w", err)
	}
	ok = true
	f.unadopted = false

	for _, fr := range used {
		f.unfreeSmall.InsertRange(fr, unfreeInfo{refs: 1})
	}
	for _, fr := range used {
		f.memAcct.InsertRange(fr, memAcctInfo{
			kind:           kind,
			knownCommitted: false,
			commitSeq:      f.commitSeq,
		})
	}
	return nil
}

// adoptGapClearer zeroes unadopted gaps in a MemoryFile during AdoptExisting,
// reusing scan/zero buffers across gaps when hole punching is unavailable.
type adoptGapClearer struct {
	f                    *MemoryFile
	scanBuf              []byte
	zeroBuf              []byte
	punchHoleUnsupported bool
}

func (c *adoptGapClearer) clear(gap memmap.FileRange) error {
	if !c.punchHoleUnsupported {
		err := c.f.decommitFile(gap)
		if err == nil {
			return nil
		}
		log.Warningf("Failed to decommit %v during adoption: %v", gap, err)
		if errors.Is(err, unix.EOPNOTSUPP) {
			c.punchHoleUnsupported = true
		}
	}
	if err := c.zeroNonZeroPages(gap); err != nil {
		return fmt.Errorf("failed to zero unadopted range %v: %w", gap, err)
	}
	return nil
}

// zeroNonZeroPages scans fr in bounded chunks via ReadAt and zeroes only pages
// containing non-zero bytes via WriteAt, preserving sparsity across
// already-zero holes and returning any host I/O error to the caller.
func (c *adoptGapClearer) zeroNonZeroPages(fr memmap.FileRange) error {
	pg := uint64(hostarch.PageSize)
	wantBuf := min(fr.Length(), max(uint64(adoptScanBufSize), pg))
	if uint64(len(c.scanBuf)) < wantBuf {
		c.scanBuf = make([]byte, wantBuf)
	}
	if uint64(len(c.zeroBuf)) < wantBuf {
		c.zeroBuf = make([]byte, wantBuf)
	}
	buf := c.scanBuf
	zeros := c.zeroBuf
	zeroPage := zeros[:pg]

	for off := fr.Start; off < fr.End; {
		n := min(uint64(len(buf)), fr.End-off)
		chunk := buf[:n]
		if _, err := c.f.file.ReadAt(chunk, int64(off)); err != nil {
			return err
		}
		var dirtyStart uint64
		dirty := false
		for rel := uint64(0); rel < n; rel += pg {
			if !bytes.Equal(chunk[rel:rel+pg], zeroPage) {
				if !dirty {
					dirtyStart = off + rel
					dirty = true
				}
			} else if dirty {
				if _, err := c.f.file.WriteAt(zeros[:off+rel-dirtyStart], int64(dirtyStart)); err != nil {
					return err
				}
				dirty = false
			}
		}
		if dirty {
			if _, err := c.f.file.WriteAt(zeros[:off+n-dirtyStart], int64(dirtyStart)); err != nil {
				return err
			}
		}
		off += n
	}
	return nil
}

// validateAdoptedRanges returns an error if ranges is not sorted,
// non-overlapping, page-aligned, and within [0, size).
func validateAdoptedRanges(ranges []memmap.FileRange, size uint64) error {
	var prevEnd uint64
	for i, fr := range ranges {
		if !fr.WellFormed() || fr.Length() == 0 {
			return fmt.Errorf("adopted range %d %v is empty or malformed", i, fr)
		}
		if !hostarch.IsPageAligned(fr.Start) || !hostarch.IsPageAligned(fr.End) {
			return fmt.Errorf("adopted range %d %v is not page-aligned", i, fr)
		}
		if fr.Start < prevEnd {
			return fmt.Errorf("adopted range %d %v is not sorted or overlaps the previous range", i, fr)
		}
		if fr.End > size {
			return fmt.Errorf("adopted range %d %v exceeds the backing file size %#x", i, fr, size)
		}
		prevEnd = fr.End
	}
	return nil
}
