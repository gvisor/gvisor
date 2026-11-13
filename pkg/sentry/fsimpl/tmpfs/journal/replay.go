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

package journal


import (
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// MaxFileOffset is the exclusive upper bound on page-aligned regular file
// offsets, equal to hostarch.PageRoundUp(math.MaxInt64).
const MaxFileOffset = uint64(1) << 63

// Extent maps file offsets [Off, Off+Len) of a regular file to filestore
// offsets [MFOff, MFOff+Len).
type Extent struct {
	Off   uint64
	Len   uint64
	MFOff uint64
}

// Inode is the replayed state of one inode.
type Inode struct {
	InodeRecord

	// Nlink is the link count, computed from the directory entries.
	Nlink uint32

	// Children maps names to inode numbers. It is only set for
	// directories.
	Children map[string]uint64

	// Extents holds the extents of a regular file, sorted by Off.
	Extents []Extent
}

// State is the filesystem state held by a journal.
type State struct {
	// Root is the root inode number. Root is 0 if the journal is new.
	Root uint64

	// NextIno is greater than every inode number in the journal.
	NextIno uint64

	// Inodes maps inode numbers to inodes. It only holds inodes that are
	// reachable from Root.
	Inodes map[uint64]*Inode

	// used holds the filestore ranges referenced by extents, sorted and
	// merged.
	used []memmap.FileRange
}

// Empty returns true if s holds no filesystem.
func (s *State) Empty() bool {
	return s.Root == 0
}

// UsedRanges returns the filestore ranges referenced by s, sorted and merged.
func (s *State) UsedRanges() []memmap.FileRange {
	return s.used
}

