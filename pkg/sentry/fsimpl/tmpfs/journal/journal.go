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

// Package journal implements a metadata journal for a tmpfs whose file data
// is stored in a host-backed pgalloc.MemoryFile (the filestore). The journal
// lives in its own host file, next to the filestore. It records which
// filestore pages hold each file's data, letting a new sentry rebuild the
// tmpfs after the previous sentry crashed or stopped without copying file
// data.
//
// Offset 0 of the journal file holds a 4 KiB header, and two regions later in
// the file hold the journal records. The header holds the offset and size of
// each region, so that a region can move and grow when a snapshot does not
// fit. One region is active at a time. It holds a snapshot of the full tmpfs state, followed
// by records for later changes. The writer appends records through a shared
// mapping of the active region, so an append is a memory copy with no system
// calls. A sentry crash cannot lose appended records, since the host page
// cache keeps them. Host crashes are out of scope; the journal never calls
// fsync.
//
// Compaction writes a new snapshot to the inactive region, then makes it
// active with one atomic store to the header. Until that store, the old
// region stays valid, so a crash during compaction is safe. Before it writes
// the snapshot, compaction moves the inactive region to a larger range of the
// journal file if the snapshot may not fit. The inactive region is empty at
// that point, so nothing is copied.
//
// Replay treats the journal as untrusted: it stops at the first torn record
// and validates the resulting state strictly.
package journal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sync"
)

// Header layout. All integers are little-endian.
//
//	0:    magic      [8]byte
//	8:    version    u32
//	12:   unused     u32
//	16:   regionSize u64
//	24:   active     u64 (generation | flag bits; updated atomically)
//	32:   buildID    u16 length + [maxIDLen]byte
//	32+2+maxIDLen: imageID u16 length + [maxIDLen]byte
//	headerSize-48: region 0 offset u64, size u64
//	headerSize-32: region 1 offset u64, size u64
//	headerSize-16: filestoreEnd u64 (updated atomically)
//	headerSize-4: crc32c u32 over the immutable fields: bytes [0, 24) and
//	              [32, headerSize-48)
//
// regionSize is the minimum size of a region. A region descriptor changes
// only while its region is inactive, so a torn descriptor is never used.
//
// filestoreEnd is a high-water mark in the filestore: it is at least the end
// of every extent in an EXTENT_SET record in the active region. Open refuses
// extents beyond it. The host can shrink the filestore to it before the
// sandbox starts; see FilestoreEnd.
const (
	headerSize      = 4096
	headerAreaSize  = (headerSize + hostarch.PageSize - 1) &^ (hostarch.PageSize - 1)
	formatVersion   = 4
	maxIDLen        = 1024
	activeOff       = 24
	buildIDOff      = 32
	imageIDOff      = buildIDOff + 2 + maxIDLen
	regionDescOff   = headerSize - 48
	filestoreEndOff = headerSize - 16
	headerCRCOff    = headerSize - 4

	// The active generation selects the active region: slot = gen & 1.
	// brokenBit is set when a record could not be appended because the
	// active region was full; the next successful compaction clears it.
	brokenBit = uint64(1) << 63

	// incompleteBit is set in a new journal for a filestore that a restore
	// or tar archive populates. The first Commit clears it.
	incompleteBit = uint64(1) << 62

	activeFlags = brokenBit | incompleteBit
)

var headerMagic = [8]byte{'g', 'V', 't', 'm', 'p', 'J', 'n', 'l'}

// Region header layout:
//
//	0:  magic    u32
//	4:  unused   u32
//	8:  gen      u64
//	16: startSeq u64
//	24: crc32c   u32 over bytes [0, 24)
const (
	regionMagic      = 0x4e474552 // "REGN"
	regionHeaderSize = 64
)

const (
	// DefaultRegionSize is the default minimum size of a journal region.
	DefaultRegionSize = 64 << 20

	minRegionSize = 4 * hostarch.PageSize
	maxRegionSize = 1 << 32

	// snapshotSlack is added to the space for a snapshot.
	snapshotSlack = hostarch.PageSize
)

// Options configures Create, CreateIncomplete, and Open.
type Options struct {
	// BuildID identifies the binary that writes the journal. Open refuses a
	// journal written by a different binary.
	BuildID string

	// ImageID optionally identifies the lower layer of the overlay. Recorded on
	// Create/CreateIncomplete; if non-empty on Open, Open refuses a journal
	// created with a different ImageID.
	ImageID string

	// RegionSize is the minimum size of each region. It is only used when
	// a new journal is created. If it is 0, DefaultRegionSize is used.
	RegionSize uint64

	// FilestoreSize bounds replayed extents if non-zero. Open also bounds
	// them by the current size of the MemoryFile's backing file.
	FilestoreSize uint64
}

// Journal is an open journal backed by a host file.
type Journal struct {
	// file is the journal file. file is immutable until Close (which holds
	// compactMu and mu).
	file *os.File

	// regionSize is the minimum size of a region. regionSize is immutable.
	regionSize uint64

	// needCompaction is called, without mu held, when the active region is
	// half full or full. needCompaction is immutable after
	// SetCompactionRequester.
	needCompaction func()

	// compactMu serializes region preparation (disk I/O on the inactive slot)
	// and Close so file and inactive region mappings cannot be closed or
	// relocated concurrently while mu is dropped.
	//
	// Lock order: compactMu -> mu.
	compactMu sync.Mutex

	mu sync.Mutex

	// header is a shared mapping of [0, headerAreaSize) in file.
	//
	// +checklocks:mu
	header []byte

	// gen is the generation of the active region.
	//
	// +checklocks:mu
	gen uint64

	// incomplete is true until the first snapshot commits on a journal
	// created with CreateIncomplete.
	//
	// +checklocks:mu
	incomplete bool

	// broken is true if a record was dropped because the active region was
	// full or hit a host I/O fault.
	//
	// +checklocks:mu
	broken bool

	// active is the writer for the active region.
	//
	// +checklocks:mu
	active regionWriter

	// next is the writer for the inactive region during compaction, and nil
	// otherwise.
	//
	// +checklocks:mu
	next *regionWriter

	// filestoreEnd is the value of the filestoreEnd header field.
	//
	// +checklocks:mu
	filestoreEnd uint64

	// nextEnd is the filestore high-water mark for the inactive region
	// during compaction (at least the end of every EXTENT_SET record written
	// to it).
	//
	// +checklocks:mu
	nextEnd uint64

	// regions holds the region descriptors, as in the header. An unallocated
	// inactive slot has size == 0.
	//
	// +checklocks:mu
	regions [2]region

	// regionMaps holds the shared mapping for each allocated region slot.
	//
	// +checklocks:mu
	regionMaps [2][]byte

	// scratch is a reusable buffer for encoding records before copying them
	// into a MAP_SHARED region via safecopy.
	//
	// +checklocks:mu
	scratch []byte

	// requested is true if needCompaction was called and compaction has
	// not finished since.
	//
	// +checklocks:mu
	requested bool

	// closed is true after Close. Appends are dropped after Close.
	//
	// +checklocks:mu
	closed bool
}

// region describes a region of the journal in the backing file.
type region struct {
	off  uint64
	size uint64
}

func (r region) end() uint64 {
	return r.off + r.size
}

func (r region) overlaps(o region) bool {
	return r.off < o.end() && o.off < r.end()
}

// valid returns true if r is a well-formed region in a file of size
// fileSize.
func (r region) valid(fileSize uint64) bool {
	return r.off >= headerAreaSize && hostarch.IsPageAligned(r.off) &&
		r.size >= minRegionSize && r.size <= maxRegionSize && hostarch.IsPageAligned(r.size) &&
		r.off <= fileSize && r.size <= fileSize-r.off
}

// regionWriter appends records to one region.
type regionWriter struct {
	// mapping is the shared mapping of the region, of length size.
	mapping []byte
	// size is the size of the region.
	size uint64
	// tail is the offset of the next record within mapping.
	tail uint64
	// nextSeq is the sequence number of the next record.
	nextSeq uint64
	// full is true if an append did not fit or failed with an I/O fault.
	full bool
	// ioErr records the first safecopy fault encountered while writing.
	ioErr error
}

// Create initializes a new journal in file, replacing any existing contents.
// On success, the returned Journal takes ownership of file.
func Create(file *os.File, opts Options) (*Journal, error) {
	return create(file, opts, false /* incomplete */)
}

// CreateIncomplete is like Create, but marks the journal as incomplete. Until
// the returned Journal commits its first snapshot, Open refuses the journal
// with ErrIncomplete.
func CreateIncomplete(file *os.File, opts Options) (*Journal, error) {
	return create(file, opts, true /* incomplete */)
}

// Open replays the journal in file and adopts the filestore pages that it
// references into mf, which must have been created with KeepFileContents.
//
// If keepJournal is true, Open also returns an open Journal that continues
// journaling into file, and that takes ownership of file. If keepJournal is
// false, Open returns a nil *Journal, and the caller keeps ownership of file.
//
// Open refuses an empty or uninitialized file (ErrIncomplete), a journal marked
// incomplete (ErrIncomplete) or broken, a journal with a mismatched format
// version or build ID, a journal whose image ID differs from a non-empty
// opts.ImageID, or one whose contents are invalid.
func Open(mf *pgalloc.MemoryFile, file *os.File, opts Options, keepJournal bool) (*Journal, *State, error) {
	if len(opts.BuildID) > maxIDLen || len(opts.ImageID) > maxIDLen {
		return nil, nil, fmt.Errorf("build ID or image ID longer than %d bytes", maxIDLen)
	}
	fd := int(file.Fd())
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, nil, fmt.Errorf("failed to stat journal: %w", err)
	}
	if stat.Size == 0 {
		return nil, nil, ErrIncomplete
	}
	if stat.Size < headerSize {
		return nil, nil, fmt.Errorf("journal size %d is smaller than its header", stat.Size)
	}
	journalSize := uint64(stat.Size)
	var dataStat unix.Stat_t
	if err := unix.Fstat(mf.FD(), &dataStat); err != nil {
		return nil, nil, fmt.Errorf("failed to stat filestore: %w", err)
	}
	if stat.Dev == dataStat.Dev && stat.Ino == dataStat.Ino {
		return nil, nil, fmt.Errorf("journal and filestore refer to the same file")
	}
	var hdr [headerSize]byte
	n, err := preadFull(fd, hdr[:], 0)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read journal header: %w", err)
	}
	if n < headerSize {
		return nil, nil, fmt.Errorf("short read of journal header: got %d bytes, want %d", n, headerSize)
	}
	// Initialization writes the magic last. A header without a magic was
	// never completely written.
	var zeroMagic [len(headerMagic)]byte
	if bytes.Equal(hdr[:len(headerMagic)], zeroMagic[:]) {
		return nil, nil, ErrIncomplete
	}

	regionSize, err := checkHeader(hdr[:], opts)
	if err != nil {
		return nil, nil, err
	}
	active := binary.LittleEndian.Uint64(hdr[activeOff:])
	if active&brokenBit != 0 {
		return nil, nil, fmt.Errorf("journal overflowed before the previous sandbox stopped; its state is incomplete")
	}
	if active >= incompleteBit-1 {
		return nil, nil, fmt.Errorf("journal generation %#x is out of range", active)
	}

	filestoreLimit := uint64(dataStat.Size)
	if opts.FilestoreSize != 0 && opts.FilestoreSize < filestoreLimit {
		filestoreLimit = opts.FilestoreSize
	}
	filestoreEnd := binary.LittleEndian.Uint64(hdr[filestoreEndOff:])
	limit := min(filestoreLimit, filestoreEnd)

	gen := active
	activeSlot := int(gen & 1)
	regions := [2]region{loadRegionFromHeader(hdr[:], 0), loadRegionFromHeader(hdr[:], 1)}
	r := regions[activeSlot]
	if !r.valid(journalSize) {
		return nil, nil, fmt.Errorf("active journal region [%#x, +%#x) is not valid in a %#x-byte file", r.off, r.size, journalSize)
	}

	activeMap, err := mmapRange(fd, r.off, r.size)
	if err != nil {
		return nil, nil, err
	}
	startSeq, err := checkRegionHeader(activeMap, gen)
	if err != nil {
		unmapRange(activeMap)
		return nil, nil, err
	}
	st, tail, nextSeq, err := replayRegion(activeMap, startSeq, limit)
	if err != nil {
		unmapRange(activeMap)
		if filestoreEnd < filestoreLimit {
			return nil, nil, fmt.Errorf("failed to replay journal with filestore end mark %#x: %w", filestoreEnd, err)
		}
		return nil, nil, fmt.Errorf("failed to replay journal: %w", err)
	}

	if err := mf.AdoptExisting(st.UsedRanges(), usage.Tmpfs); err != nil {
		unmapRange(activeMap)
		return nil, nil, fmt.Errorf("failed to adopt filestore pages: %w", err)
	}

	if !keepJournal {
		unmapRange(activeMap)
		return nil, st, nil
	}

	headerMap, err := mmapRange(fd, 0, headerAreaSize)
	if err != nil {
		unmapRange(activeMap)
		return nil, nil, err
	}
	// The inactive region is not mapped. If its descriptor is not valid, the
	// next compaction allocates a new inactive region.
	inactiveSlot := 1 - activeSlot
	if !regions[inactiveSlot].valid(journalSize) || regions[inactiveSlot].overlaps(r) {
		regions[inactiveSlot] = region{}
	}
	j := &Journal{
		file:       file,
		regionSize: regionSize,
	}
	j.mu.Lock()
	j.header = headerMap
	j.gen = gen
	j.active = regionWriter{mapping: activeMap, size: r.size, tail: tail, nextSeq: nextSeq}
	j.filestoreEnd = filestoreEnd
	j.regions = regions
	j.regionMaps[activeSlot] = activeMap
	err = j.storeRegionLocked(inactiveSlot, regions[inactiveSlot])
	j.mu.Unlock()
	if err != nil {
		unmapRange(headerMap)
		unmapRange(activeMap)
		return nil, nil, fmt.Errorf("failed to update inactive journal region descriptor: %w", err)
	}
	return j, st, nil
}

// create initializes a new journal in file.
func create(file *os.File, opts Options, incomplete bool) (*Journal, error) {
	if len(opts.BuildID) > maxIDLen || len(opts.ImageID) > maxIDLen {
		return nil, fmt.Errorf("build ID or image ID longer than %d bytes", maxIDLen)
	}
	regionSize := opts.RegionSize
	if regionSize == 0 {
		regionSize = DefaultRegionSize
	}
	if regionSize < minRegionSize || regionSize > maxRegionSize || !hostarch.IsPageAligned(regionSize) {
		return nil, fmt.Errorf("invalid region size %d", regionSize)
	}

	// Truncate first so that the file holds no stale header or records.
	regions := [2]region{
		{off: headerAreaSize, size: regionSize},
		{off: headerAreaSize + regionSize, size: regionSize},
	}
	if err := file.Truncate(0); err != nil {
		return nil, fmt.Errorf("failed to truncate journal file: %w", err)
	}
	if err := file.Truncate(int64(regions[1].end())); err != nil {
		return nil, fmt.Errorf("failed to size journal file: %w", err)
	}
	fd := int(file.Fd())
	headerMap, err := mmapRange(fd, 0, headerAreaSize)
	if err != nil {
		return nil, err
	}
	map0, err := mmapRange(fd, regions[0].off, regionSize)
	if err != nil {
		unmapRange(headerMap)
		return nil, err
	}
	map1, err := mmapRange(fd, regions[1].off, regionSize)
	if err != nil {
		unmapRange(map0)
		unmapRange(headerMap)
		return nil, err
	}

	// Build the header in Go memory (magic zeroed) and copy it into the
	// shared mapping with safecopy so ENOSPC/EDQUOT returns an error instead
	// of crashing the sentry with SIGBUS.
	const gen = 1
	active := uint64(gen)
	if incomplete {
		active |= incompleteBit
	}
	var h [headerSize]byte
	binary.LittleEndian.PutUint32(h[8:], formatVersion)
	binary.LittleEndian.PutUint64(h[16:], regionSize)
	binary.LittleEndian.PutUint64(h[activeOff:], active)
	putID(h[buildIDOff:], opts.BuildID)
	putID(h[imageIDOff:], opts.ImageID)
	for i, r := range regions {
		off := regionDescOff + 16*i
		binary.LittleEndian.PutUint64(h[off:], r.off)
		binary.LittleEndian.PutUint64(h[off+8:], r.size)
	}
	binary.LittleEndian.PutUint32(h[headerCRCOff:], headerCRC(h[:], headerMagic))

	if err := safeCopyOut(headerMap[:headerSize], h[:]); err != nil {
		unmapRange(map1)
		unmapRange(map0)
		unmapRange(headerMap)
		return nil, fmt.Errorf("failed to write journal header: %w", err)
	}
	// The first generation is 1, so region 1 is active first.
	if err := writeRegionHeader(map1, gen, 1 /* startSeq */); err != nil {
		unmapRange(map1)
		unmapRange(map0)
		unmapRange(headerMap)
		return nil, fmt.Errorf("failed to write journal region header: %w", err)
	}
	// Write the magic last: until it is written, Open treats the journal as
	// incomplete.
	if err := safeStore64(headerMap[0:8], binary.LittleEndian.Uint64(headerMagic[:])); err != nil {
		unmapRange(map1)
		unmapRange(map0)
		unmapRange(headerMap)
		return nil, fmt.Errorf("failed to seal journal header: %w", err)
	}

	j := &Journal{
		file:       file,
		regionSize: regionSize,
	}
	j.mu.Lock()
	j.header = headerMap
	j.gen = gen
	j.incomplete = incomplete
	j.active = regionWriter{mapping: map1, size: regionSize, tail: regionHeaderSize, nextSeq: 1}
	j.regions = regions
	j.regionMaps = [2][]byte{map0, map1}
	j.mu.Unlock()
	return j, nil
}

func mmapRange(fd int, off, size uint64) ([]byte, error) {
	m, err := unix.Mmap(fd, int64(off), int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap journal range [%#x, +%#x): %w", off, size, err)
	}
	return m, nil
}

func unmapRange(m []byte) {
	if m != nil {
		if err := unix.Munmap(m); err != nil {
			log.Warningf("Failed to unmap journal range: %v", err)
		}
	}
}

func preadFull(fd int, buf []byte, off int64) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := unix.Pread(fd, buf[total:], off+int64(total))
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			break
		}
		total += n
	}
	return total, nil
}

func putID(b []byte, id string) {
	binary.LittleEndian.PutUint16(b, uint16(len(id)))
	copy(b[2:2+maxIDLen], id)
}

func getID(b []byte) (string, error) {
	n := int(binary.LittleEndian.Uint16(b))
	if n > maxIDLen {
		return "", fmt.Errorf("ID length %d exceeds %d", n, maxIDLen)
	}
	return string(b[2 : 2+n]), nil
}

// headerCRC returns the checksum of the immutable fields of header h, with
// the given magic.
func headerCRC(h []byte, magic [8]byte) uint32 {
	tab := castagnoli()
	c := crc32.Update(0, tab, magic[:])
	c = crc32.Update(c, tab, h[8:activeOff])
	return crc32.Update(c, tab, h[buildIDOff:regionDescOff])
}

// checkHeader validates header h against opts and returns the region size.
func checkHeader(h []byte, opts Options) (uint64, error) {
	regionSize, err := checkHeaderFormat(h)
	if err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint64(h[activeOff:])&incompleteBit != 0 {
		return 0, ErrIncomplete
	}
	buildID, err := getID(h[buildIDOff:])
	if err != nil {
		return 0, err
	}
	if buildID != opts.BuildID {
		return 0, fmt.Errorf("journal was written by build %q, but this is build %q", buildID, opts.BuildID)
	}
	imageID, err := getID(h[imageIDOff:])
	if err != nil {
		return 0, err
	}
	if opts.ImageID != "" && imageID != opts.ImageID {
		return 0, &ImageMismatchError{Journal: imageID, Want: opts.ImageID}
	}
	return regionSize, nil
}

// checkHeaderFormat validates the magic, checksum, format version and region
// size of header h, and returns the region size.
func checkHeaderFormat(h []byte) (uint64, error) {
	var magic [8]byte
	copy(magic[:], h)
	if magic != headerMagic {
		return 0, fmt.Errorf("journal has bad magic %q", magic[:])
	}
	if got, want := binary.LittleEndian.Uint32(h[headerCRCOff:]), headerCRC(h, headerMagic); got != want {
		return 0, fmt.Errorf("journal header checksum is %#x, want %#x", got, want)
	}
	if v := binary.LittleEndian.Uint32(h[8:]); v != formatVersion {
		return 0, fmt.Errorf("journal format version is %d, want %d", v, formatVersion)
	}
	regionSize := binary.LittleEndian.Uint64(h[16:])
	if regionSize < minRegionSize || regionSize > maxRegionSize || !hostarch.IsPageAligned(regionSize) {
		return 0, fmt.Errorf("journal has invalid region size %d", regionSize)
	}
	return regionSize, nil
}

// Invalidate marks the journal header in file as broken so Open refuses to
// replay it later (for example, when a filestore is imported without runtime
// journaling and mutated in place). Invalidate does not take ownership of file.
func Invalidate(file *os.File) error {
	fd := int(file.Fd())
	var hdr [headerSize]byte
	n, err := preadFull(fd, hdr[:], 0)
	if err != nil {
		return fmt.Errorf("failed to read journal header: %w", err)
	}
	if n < headerSize {
		return nil
	}
	if _, err := checkHeaderFormat(hdr[:]); err != nil {
		return nil
	}
	active := binary.LittleEndian.Uint64(hdr[activeOff:])
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], active|brokenBit)
	for written := 0; written < len(buf); {
		w, err := unix.Pwrite(fd, buf[written:], activeOff+int64(written))
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to invalidate journal header: %w", err)
		}
		written += w
	}
	return nil
}

// ErrIncomplete is returned by Open if the journal is incomplete or was never
// initialized. See CreateIncomplete.
var ErrIncomplete = errors.New("journal is incomplete")

// Incomplete returns true if the journal in file is marked as incomplete.
func Incomplete(file *os.File) (bool, error) {
	var hdr [headerSize]byte
	n, err := preadFull(int(file.Fd()), hdr[:], 0)
	if err != nil {
		return false, fmt.Errorf("failed to read journal header: %w", err)
	}
	if n < headerSize {
		return false, nil
	}
	if _, err := checkHeaderFormat(hdr[:]); err != nil {
		return false, nil
	}
	return binary.LittleEndian.Uint64(hdr[activeOff:])&incompleteBit != 0, nil
}

// ImageMismatchError is returned by Open when the journal was created for a
// different image.
type ImageMismatchError struct {
	Journal string
	Want    string
}

// Error implements error.Error.
func (e *ImageMismatchError) Error() string {
	return fmt.Sprintf("journal was created for image %q, but the image is %q", e.Journal, e.Want)
}

// +checklocks:j.mu
func (j *Journal) storeActiveLocked() error {
	v := j.gen
	if j.broken {
		v |= brokenBit
	}
	if j.incomplete {
		v |= incompleteBit
	}
	return safeStore64(j.header[activeOff:activeOff+8], v)
}

// raiseFilestoreEndLocked raises the filestoreEnd header field to cover an
// extent that ends at end. The caller must call it before it seals the
// record.
//
// +checklocks:j.mu
func (j *Journal) raiseFilestoreEndLocked(end uint64) {
	if end > j.filestoreEnd {
		j.filestoreEnd = end
		if err := safeStore64(j.header[filestoreEndOff:filestoreEndOff+8], end); err != nil {
			log.Warningf("tmpfs journal: failed to update filestoreEnd: %v", err)
		}
	}
}

// extentEnd returns the end of the filestore range of an extent.
func extentEnd(length, mfOff uint64) uint64 {
	end := mfOff + length
	if end < mfOff {
		return math.MaxUint64
	}
	return end
}

func loadRegionFromHeader(hdr []byte, i int) region {
	off := regionDescOff + 16*i
	return region{
		off:  binary.LittleEndian.Uint64(hdr[off:]),
		size: binary.LittleEndian.Uint64(hdr[off+8:]),
	}
}

// storeRegionLocked writes the descriptor of region slot i to the header. The
// region must not be active.
//
// +checklocks:j.mu
func (j *Journal) storeRegionLocked(i int, r region) error {
	off := regionDescOff + 16*i
	if err := safeStore64(j.header[off:off+8], r.off); err != nil {
		return err
	}
	return safeStore64(j.header[off+8:off+16], r.size)
}

func snapshotNeed(size uint64) uint64 {
	need := regionHeaderSize + recordSize(16) + snapshotSlack
	if size > (maxRegionSize-need)/2 {
		return maxRegionSize + 1
	}
	return need + 2*size
}

// PrepareSnapshot ensures the inactive region is mapped and large enough for a
// snapshot of size bytes without holding j.mu across blocking host file
// operations. Callers that hold external filesystem locks during BeginSnapshot
// should call PrepareSnapshot beforehand without those locks held.
func (j *Journal) PrepareSnapshot(size uint64) error {
	return j.prepareRegion(snapshotNeed(size))
}

// prepareRegion makes the inactive region large enough for need bytes without
// holding j.mu across Munmap, Fallocate, Truncate, or Mmap.
//
// +checklocksexclude:j.compactMu
// +checklocksexclude:j.mu
func (j *Journal) prepareRegion(need uint64) error {
	j.compactMu.Lock()
	defer j.compactMu.Unlock()

	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return fmt.Errorf("journal is closed")
	}
	if j.next != nil {
		j.mu.Unlock()
		return fmt.Errorf("compaction already in progress")
	}
	if need > maxRegionSize {
		j.requested = false
		j.mu.Unlock()
		return fmt.Errorf("journal snapshot needs %d bytes, more than the maximum region size %d", need, uint64(maxRegionSize))
	}
	slot := int((j.gen + 1) & 1)
	cur := j.regions[slot]
	active := j.regions[1-slot]
	// Leave room for appends after the snapshot, so that the next
	// compaction, which starts when the region is half full, is not due at
	// once.
	want := max(j.regionSize, hostarch.MustPageRoundUp(min(2*need, maxRegionSize)))
	if cur.size != 0 && !cur.overlaps(active) && cur.size >= want && cur.size <= max(j.regionSize, 2*want) {
		if j.regionMaps[slot] != nil {
			j.mu.Unlock()
			return nil
		}
		j.mu.Unlock()
		// Holding compactMu pins j.file and slot against Close and concurrent
		// compactions while mu is released for mmap.
		m, err := mmapRange(int(j.file.Fd()), cur.off, cur.size)
		j.mu.Lock()
		if err != nil {
			j.requested = false
			j.mu.Unlock()
			return err
		}
		j.regionMaps[slot] = m
		j.mu.Unlock()
		return nil
	}

	oldMap := j.regionMaps[slot]
	j.regionMaps[slot] = nil
	if cur.size != 0 {
		if err := j.storeRegionLocked(slot, region{}); err != nil {
			j.regionMaps[slot] = oldMap
			j.requested = false
			j.mu.Unlock()
			return fmt.Errorf("failed to clear inactive journal region descriptor: %w", err)
		}
		j.regions[slot] = region{}
	}
	j.mu.Unlock()

	// Perform blocking unmap, hole-punch, truncate, and mmap on the inactive
	// slot without holding j.mu so active-region appends are not stalled.
	// compactMu pins j.file and prevents concurrent compactions or Close.
	unmapRange(oldMap)
	if cur.size != 0 {
		j.freeRange(cur)
	}
	// Place the region at the start of the file if it fits before the
	// active region, and after the active region otherwise.
	next := region{off: headerAreaSize, size: want}
	if next.overlaps(active) {
		next.off = active.end()
	}
	// Grow or shrink the file to the end of the last region.
	if err := j.file.Truncate(int64(max(next.end(), active.end()))); err != nil {
		j.mu.Lock()
		j.requested = false
		j.mu.Unlock()
		return fmt.Errorf("failed to resize journal file for a %d-byte region: %w", want, err)
	}
	m, err := mmapRange(int(j.file.Fd()), next.off, next.size)
	if err != nil {
		j.mu.Lock()
		j.requested = false
		j.mu.Unlock()
		return err
	}

	j.mu.Lock()
	if err := j.storeRegionLocked(slot, next); err != nil {
		j.requested = false
		j.mu.Unlock()
		unmapRange(m)
		return fmt.Errorf("failed to write journal region descriptor: %w", err)
	}
	j.regions[slot] = next
	j.regionMaps[slot] = m
	j.mu.Unlock()
	log.Infof("tmpfs journal: placed region %d at [%#x, +%#x) for a %d-byte snapshot", slot, next.off, next.size, need)
	return nil
}

// freeRange releases the disk space of region r of the journal file.
func (j *Journal) freeRange(r region) {
	if err := unix.Fallocate(int(j.file.Fd()), unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, int64(r.off), int64(r.size)); err != nil {
		log.Debugf("tmpfs journal: failed to punch hole over [%#x, +%#x): %v", r.off, r.size, err)
	}
}

// ReclaimInactive punches a hole over the inactive region's disk blocks without
// holding j.mu so disk space is released after compaction without stalling
// appends.
//
// +checklocksexclude:j.compactMu
// +checklocksexclude:j.mu
func (j *Journal) ReclaimInactive() {
	j.compactMu.Lock()
	defer j.compactMu.Unlock()
	j.mu.Lock()
	if j.closed || j.next != nil {
		j.mu.Unlock()
		return
	}
	inactive := j.regions[1-int(j.gen&1)]
	j.mu.Unlock()
	if inactive.size != 0 {
		j.freeRange(inactive)
	}
}

func writeRegionHeader(regionMap []byte, gen, startSeq uint64) error {
	var h [regionHeaderSize]byte
	binary.LittleEndian.PutUint32(h[0:], regionMagic)
	binary.LittleEndian.PutUint64(h[8:], gen)
	binary.LittleEndian.PutUint64(h[16:], startSeq)
	binary.LittleEndian.PutUint32(h[24:], crc32.Checksum(h[:24], castagnoli()))
	if err := safeCopyOut(regionMap[:regionHeaderSize], h[:]); err != nil {
		return err
	}
	// Clear the first record's magic word so stale records left by an earlier
	// aborted or crashed compaction cannot be replayed if the log is empty.
	return safeStore32(regionMap[regionHeaderSize:regionHeaderSize+4], 0)
}

// checkRegionHeader validates the header of regionMap and returns the sequence
// number of its first record.
func checkRegionHeader(regionMap []byte, gen uint64) (uint64, error) {
	h := regionMap[:regionHeaderSize]
	if m := binary.LittleEndian.Uint32(h[0:]); m != regionMagic {
		return 0, fmt.Errorf("active journal region has bad magic %#x", m)
	}
	if got, want := binary.LittleEndian.Uint32(h[24:]), crc32.Checksum(h[:24], castagnoli()); got != want {
		return 0, fmt.Errorf("active journal region header checksum is %#x, want %#x", got, want)
	}
	if g := binary.LittleEndian.Uint64(h[8:]); g != gen {
		return 0, fmt.Errorf("active journal region has generation %d, want %d", g, gen)
	}
	return binary.LittleEndian.Uint64(h[16:]), nil
}

// SetCompactionRequester sets the function that the Journal calls when the
// active region is half full. fn is called without any Journal lock held, and
// must not block. The Journal calls fn at most once until Snapshot.Commit or
// Snapshot.Abort.
//
// Preconditions: No other goroutine is using j.
func (j *Journal) SetCompactionRequester(fn func()) {
	j.needCompaction = fn
}

// Close stops appends, unmaps the journal's mappings, and closes the journal
// file. Records appended after Close are dropped. Close does not modify the
// journal file, so that a new sandbox can replay the journal.
func (j *Journal) Close() {
	j.compactMu.Lock()
	defer j.compactMu.Unlock()
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	j.closed = true
	j.next = nil
	j.active.mapping = nil
	for i := range j.regionMaps {
		unmapRange(j.regionMaps[i])
		j.regionMaps[i] = nil
	}
	unmapRange(j.header)
	j.header = nil
	if err := j.file.Close(); err != nil {
		log.Warningf("tmpfs journal: failed to close journal file: %v", err)
	}
}

// CompactionPending returns true if the Journal requested a compaction that
// has not finished yet.
func (j *Journal) CompactionPending() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.requested
}

// Broken returns true if a record was dropped because the active region was
// full or hit an I/O fault, and no compaction has finished since.
func (j *Journal) Broken() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.broken
}

var errRegionFull = errors.New("journal region is full")

// prepareScratchLocked sizes j.scratch for a record with payloadLen bytes,
// clears trailing alignment padding, and returns the payload slice.
//
// +checklocks:j.mu
func (j *Journal) prepareScratchLocked(payloadLen uint64) []byte {
	size := recordSize(payloadLen)
	if uint64(cap(j.scratch)) < size {
		j.scratch = make([]byte, size)
	}
	rec := j.scratch[:size]
	clear(rec[recordHeaderSize+payloadLen+recordCRCSize : size])
	return rec[recordHeaderSize : recordHeaderSize+payloadLen]
}

// writeRecordLocked finalizes the record encoded in j.scratch and writes it to
// w via safecopy. Before sealing the record's magic word, it zeroes the next
// record's magic word so stale records from a prior aborted or crashed
// compaction cannot be replayed past the new tail.
//
// +checklocks:j.mu
func (j *Journal) writeRecordLocked(w *regionWriter, typ RecordType, payloadLen uint64) error {
	if w.full {
		return errRegionFull
	}
	size := recordSize(payloadLen)
	if size > w.size-w.tail {
		w.full = true
		return errRegionFull
	}
	rec := j.scratch[:size]
	binary.LittleEndian.PutUint32(rec[4:], uint32(payloadLen))
	binary.LittleEndian.PutUint64(rec[8:], w.nextSeq)
	binary.LittleEndian.PutUint16(rec[16:], uint16(typ))
	binary.LittleEndian.PutUint16(rec[18:], 0)
	binary.LittleEndian.PutUint32(rec[20:], 0)
	crc := crc32.Checksum(rec[4:recordHeaderSize+payloadLen], castagnoli())
	binary.LittleEndian.PutUint32(rec[recordHeaderSize+payloadLen:], crc)

	// Zero the next record's magic word before sealing this record so replay
	// stops here even if the region holds valid stale records with matching
	// sequence numbers from an earlier aborted or crashed compaction.
	if nextTail := w.tail + size; nextTail+4 <= w.size {
		if err := safeStore32(w.mapping[nextTail:nextTail+4], 0); err != nil {
			w.full = true
			w.ioErr = err
			return err
		}
	}
	if err := safeCopyOut(w.mapping[w.tail+4:w.tail+size], rec[4:size]); err != nil {
		w.full = true
		w.ioErr = err
		return err
	}
	if err := safeStore32(w.mapping[w.tail:w.tail+4], recordMagic); err != nil {
		w.full = true
		w.ioErr = err
		return err
	}
	w.tail += size
	w.nextSeq++
	return nil
}

// markBrokenLocked marks the journal broken in memory and on disk.
//
// +checklocks:j.mu
func (j *Journal) markBrokenLocked(err error) {
	if j.broken {
		return
	}
	if errors.Is(err, errRegionFull) {
		log.Warningf("tmpfs journal: active region is full; the journal is unusable until compaction finishes")
	} else {
		log.Warningf("tmpfs journal: failed to write to active region (%v); the journal is unusable until compaction finishes", err)
	}
	j.broken = true
	if storeErr := j.storeActiveLocked(); storeErr != nil {
		log.Warningf("tmpfs journal: failed to set broken flag in header: %v", storeErr)
	}
}

// beginLocked returns the scratch payload buffer into which the caller must
// encode a record of length payloadLen, or nil if the record is dropped.
// The caller must then call endLocked.
//
// +checklocks:j.mu
func (j *Journal) beginLocked(payloadLen uint64) []byte {
	if j.closed {
		return nil
	}
	if j.active.full && (j.next == nil || j.next.full) {
		return nil
	}
	return j.prepareScratchLocked(payloadLen)
}

// endLocked writes the record encoded in j.scratch to the active region and,
// during compaction, also to the inactive region. It returns true if the
// caller must call j.needCompaction after it unlocks j.mu.
//
// +checklocks:j.mu
func (j *Journal) endLocked(typ RecordType, payloadLen uint64) bool {
	if j.closed {
		return false
	}
	if !j.active.full {
		if err := j.writeRecordLocked(&j.active, typ, payloadLen); err != nil {
			j.markBrokenLocked(err)
		}
	}
	if j.next != nil && !j.next.full {
		_ = j.writeRecordLocked(j.next, typ, payloadLen)
	}
	if j.requested || j.needCompaction == nil {
		return false
	}
	if j.active.full || j.active.tail > j.active.size/2 {
		j.requested = true
		return true
	}
	return false
}

// +checklocksrelease:j.mu
func (j *Journal) end(typ RecordType, payloadLen uint64) {
	request := j.endLocked(typ, payloadLen)
	j.mu.Unlock()
	if request {
		j.needCompaction()
	}
}

// Inode appends a RecordInode record.
func (j *Journal) Inode(r *InodeRecord) {
	n := r.payloadLen()
	j.mu.Lock()
	if buf := j.beginLocked(n); buf != nil {
		e := encoder{buf: buf}
		r.encode(&e)
	}
	j.end(RecordInode, n)
}

// InodeFree appends a RecordInodeFree record.
func (j *Journal) InodeFree(ino uint64) {
	const n = 8
	j.mu.Lock()
	if buf := j.beginLocked(n); buf != nil {
		binary.LittleEndian.PutUint64(buf, ino)
	}
	j.end(RecordInodeFree, n)
}

// DirentAdd appends a RecordDirentAdd record.
func (j *Journal) DirentAdd(parent uint64, name string, child uint64) {
	n := direntAddLen(name)
	j.mu.Lock()
	if buf := j.beginLocked(n); buf != nil {
		encodeDirentAdd(buf, parent, name, child)
	}
	j.end(RecordDirentAdd, n)
}

func direntAddLen(name string) uint64 {
	return 8 + 8 + 2 + uint64(len(name))
}

func encodeDirentAdd(buf []byte, parent uint64, name string, child uint64) {
	e := encoder{buf: buf}
	e.u64(parent)
	e.u64(child)
	e.str16(name)
}

// DirentDel appends a RecordDirentDel record.
func (j *Journal) DirentDel(parent uint64, name string) {
	n := 8 + 2 + uint64(len(name))
	j.mu.Lock()
	if buf := j.beginLocked(n); buf != nil {
		e := encoder{buf: buf}
		e.u64(parent)
		e.str16(name)
	}
	j.end(RecordDirentDel, n)
}

const renameExchange = 1

// Rename appends a RecordRename record. If exchange is false, the entry
// oldName in oldParent moves to newName in newParent, and replaces any entry
// with that name. If exchange is true, the two entries are exchanged.
func (j *Journal) Rename(oldParent uint64, oldName string, newParent uint64, newName string, exchange bool) {
	var flags uint32
	if exchange {
		flags = renameExchange
	}
	n := 8 + 8 + 4 + 2 + uint64(len(oldName)) + 2 + uint64(len(newName))
	j.mu.Lock()
	if buf := j.beginLocked(n); buf != nil {
		e := encoder{buf: buf}
		e.u64(oldParent)
		e.u64(newParent)
		e.u32(flags)
		e.str16(oldName)
		e.str16(newName)
	}
	j.end(RecordRename, n)
}

func encodeExtent(buf []byte, ino, off, length, mfOff uint64) {
	binary.LittleEndian.PutUint64(buf[0:], ino)
	binary.LittleEndian.PutUint64(buf[8:], off)
	binary.LittleEndian.PutUint64(buf[16:], length)
	if len(buf) > 24 {
		binary.LittleEndian.PutUint64(buf[24:], mfOff)
	}
}

// ExtentSet appends a RecordExtentSet record.
func (j *Journal) ExtentSet(ino, off, length, mfOff uint64) {
	const n = 32
	j.mu.Lock()
	if buf := j.beginLocked(n); buf != nil {
		encodeExtent(buf, ino, off, length, mfOff)
		// The record may go to both regions. Cover it in the mark before
		// it is sealed, and in nextEnd for the inactive region.
		end := extentEnd(length, mfOff)
		j.raiseFilestoreEndLocked(end)
		if j.next != nil {
			j.nextEnd = max(j.nextEnd, end)
		}
	}
	j.end(RecordExtentSet, n)
}

// ExtentClear appends a RecordExtentClear record.
func (j *Journal) ExtentClear(ino, off, length uint64) {
	const n = 24
	j.mu.Lock()
	if buf := j.beginLocked(n); buf != nil {
		encodeExtent(buf, ino, off, length, 0)
	}
	j.end(RecordExtentClear, n)
}

// Snapshot writes a new snapshot to the inactive region. Records that are
// appended to the Journal while a Snapshot is in progress are also written
// to the inactive region, in order with the snapshot records.
//
// For each inode, the snapshot records must reflect a state at least as new
// as every record for that inode that was appended before them. Callers
// ensure this by holding the locks that serialize changes to each inode while
// they write its snapshot records.
type Snapshot struct {
	j *Journal
}

// BeginSnapshot starts a compaction, and writes a RecordRoot record with the
// given root inode number and next free inode number as the first snapshot
// record. size is the expected total size of the other snapshot records; see
// SnapshotSizer. If the inactive region may be too small for them, together
// with the records that are appended during the compaction, BeginSnapshot
// first moves it to a larger range of the journal file. The caller must call
// Commit or Abort on the returned Snapshot.
func (j *Journal) BeginSnapshot(rootIno, nextIno, size uint64) (*Snapshot, error) {
	if err := j.PrepareSnapshot(size); err != nil {
		return nil, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil, fmt.Errorf("journal is closed")
	}
	if j.next != nil {
		return nil, fmt.Errorf("compaction already in progress")
	}
	if j.gen+1 >= incompleteBit {
		j.requested = false
		return nil, fmt.Errorf("journal generation %#x exhausted", j.gen)
	}
	gen := j.gen + 1
	slot := int(gen & 1)
	r := j.regions[slot]
	m := j.regionMaps[slot]
	if m == nil {
		j.requested = false
		return nil, fmt.Errorf("inactive journal region is not mapped")
	}
	startSeq := j.active.nextSeq
	if err := writeRegionHeader(m, gen, startSeq); err != nil {
		j.requested = false
		return nil, fmt.Errorf("failed to write journal region header: %w", err)
	}
	j.next = &regionWriter{mapping: m, size: r.size, tail: regionHeaderSize, nextSeq: startSeq}
	j.nextEnd = 0
	const n = 16
	buf := j.prepareScratchLocked(n)
	binary.LittleEndian.PutUint64(buf[0:], rootIno)
	binary.LittleEndian.PutUint64(buf[8:], nextIno)
	if err := j.writeRecordLocked(j.next, RecordRoot, n); err != nil {
		j.next = nil
		j.requested = false
		return nil, fmt.Errorf("failed to write root snapshot record: %w", err)
	}
	return &Snapshot{j: j}, nil
}

// snapshotBegin returns the scratch payload buffer for a snapshot record, or
// nil if the record is dropped. The caller must call j.snapshotEnd.
//
// +checklocksacquire:j.mu
func (j *Journal) snapshotBegin(payloadLen uint64) []byte {
	j.mu.Lock()
	if j.closed || j.next == nil || j.next.full {
		return nil
	}
	return j.prepareScratchLocked(payloadLen)
}

// +checklocksrelease:j.mu
func (j *Journal) snapshotEnd(typ RecordType, payloadLen uint64) {
	if !j.closed && j.next != nil && !j.next.full {
		_ = j.writeRecordLocked(j.next, typ, payloadLen)
	}
	j.mu.Unlock()
}

// Inode writes a RecordInode record. For a regular file, it also writes a
// RecordExtentClear record for the whole file, so that the snapshot replaces
// the extents set by earlier records.
func (s *Snapshot) Inode(r *InodeRecord) {
	n := r.payloadLen()
	if buf := s.j.snapshotBegin(n); buf != nil {
		e := encoder{buf: buf}
		r.encode(&e)
	}
	s.j.snapshotEnd(RecordInode, n)
	if r.Mode&linux.S_IFMT == linux.S_IFREG {
		const n = 24
		if buf := s.j.snapshotBegin(n); buf != nil {
			encodeExtent(buf, r.Ino, 0, MaxFileOffset, 0)
		}
		s.j.snapshotEnd(RecordExtentClear, n)
	}
}

// DirentAdd writes a RecordDirentAdd record.
func (s *Snapshot) DirentAdd(parent uint64, name string, child uint64) {
	n := direntAddLen(name)
	if buf := s.j.snapshotBegin(n); buf != nil {
		encodeDirentAdd(buf, parent, name, child)
	}
	s.j.snapshotEnd(RecordDirentAdd, n)
}

// ExtentSet writes a RecordExtentSet record.
func (s *Snapshot) ExtentSet(ino, off, length, mfOff uint64) {
	const n = 32
	if buf := s.j.snapshotBegin(n); buf != nil {
		encodeExtent(buf, ino, off, length, mfOff)
		// Until Commit, the mark must also cover the active region, so
		// it can only grow here.
		end := extentEnd(length, mfOff)
		s.j.raiseFilestoreEndLocked(end)
		s.j.nextEnd = max(s.j.nextEnd, end)
	}
	s.j.snapshotEnd(RecordExtentSet, n)
}

// ErrSnapshotOverflow is returned by Commit if the snapshot and the records
// that were appended during the compaction did not fit in the region. The
// caller can retry with a larger size.
var ErrSnapshotOverflow = errors.New("journal snapshot does not fit in its region")

// Commit makes the snapshot the active region. If the snapshot did not fit in
// the region, Commit returns an error that wraps ErrSnapshotOverflow, and the
// old region stays active.
func (s *Snapshot) Commit() error {
	j := s.j
	j.mu.Lock()
	defer j.mu.Unlock()
	next := j.next
	j.next = nil
	j.requested = false
	if next == nil {
		return fmt.Errorf("journal closed during compaction")
	}
	if next.ioErr != nil {
		return fmt.Errorf("journal write failed during compaction: %w", next.ioErr)
	}
	if next.full {
		return fmt.Errorf("%w: region size is %d bytes", ErrSnapshotOverflow, next.size)
	}
	// This single atomic store makes the new region active and clears
	// brokenBit and incompleteBit.
	wasBroken := j.broken
	wasIncomplete := j.incomplete
	j.gen++
	j.broken = false
	j.incomplete = false
	if err := j.storeActiveLocked(); err != nil {
		j.gen--
		j.broken = wasBroken
		j.incomplete = wasIncomplete
		return fmt.Errorf("failed to commit journal snapshot: %w", err)
	}
	j.active = *next
	// Before this point, the mark covers the extents of both regions.
	// Shrink it to the extents of the new active region. A crash between the
	// two stores leaves a mark that is too high, which is safe.
	j.filestoreEnd = j.nextEnd
	if err := safeStore64(j.header[filestoreEndOff:filestoreEndOff+8], j.nextEnd); err != nil {
		log.Warningf("tmpfs journal: failed to shrink filestoreEnd after commit: %v", err)
	}
	return nil
}

// Abort abandons the snapshot. The old region stays active.
func (s *Snapshot) Abort() {
	j := s.j
	j.mu.Lock()
	defer j.mu.Unlock()
	j.next = nil
	j.requested = false
}

// SnapshotSizer computes the size of snapshot records for BeginSnapshot. It
// has the same record methods as Snapshot.
type SnapshotSizer struct {
	size uint64
}

// Size returns the total size of the records.
func (z *SnapshotSizer) Size() uint64 {
	return z.size
}

// Inode adds the size of the records that Snapshot.Inode writes.
func (z *SnapshotSizer) Inode(r *InodeRecord) {
	z.size += recordSize(r.payloadLen())
	if r.Mode&linux.S_IFMT == linux.S_IFREG {
		z.size += recordSize(24)
	}
}

// DirentAdd adds the size of a RecordDirentAdd record.
func (z *SnapshotSizer) DirentAdd(parent uint64, name string, child uint64) {
	z.size += recordSize(direntAddLen(name))
}

// ExtentSet adds the size of a RecordExtentSet record.
func (z *SnapshotSizer) ExtentSet(ino, off, length, mfOff uint64) {
	z.size += recordSize(32)
}
