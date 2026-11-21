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

package vfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
)

// landlockAccessFSForOpen returns the filesystem rights that an open with opts
// needs on the file that it opens. isDir is true if that file is a directory.
//
// The rights follow what the resulting file can do. A readable file needs
// LANDLOCK_ACCESS_FS_READ_FILE, or LANDLOCK_ACCESS_FS_READ_DIR for a
// directory, and a writable file needs LANDLOCK_ACCESS_FS_WRITE_FILE. An exec
// open also needs LANDLOCK_ACCESS_FS_EXECUTE. Other flags need nothing more.
// For example, O_RDONLY|O_TRUNC needs only READ_FILE, and access mode 3, whose
// file can be neither read nor written, needs no right.
func landlockAccessFSForOpen(opts *OpenOptions, isDir bool) uint64 {
	var accessFS uint64
	if MayReadFileWithOpenFlags(opts.Flags) {
		if isDir {
			accessFS |= linux.LANDLOCK_ACCESS_FS_READ_DIR
		} else {
			accessFS |= linux.LANDLOCK_ACCESS_FS_READ_FILE
		}
	}
	if MayWriteFileWithOpenFlags(opts.Flags) {
		accessFS |= linux.LANDLOCK_ACCESS_FS_WRITE_FILE
	}
	if opts.FileExec {
		accessFS |= linux.LANDLOCK_ACCESS_FS_EXECUTE
	}
	return accessFS
}

// CheckLandlockOpen checks an open with opts of the existing file d against
// the Landlock domain of rp's credentials, as ResolvingPath.CheckLandlock
// does. isDir is true if d is a directory. It returns EACCES if the domain
// denies the open.
//
// The check applies to exactly the file that the open acts on, so d must be
// the dentry that the open resolved, and the open must have no effect, such
// as truncating the file, before the check passes.
//
// Preconditions: d is a dentry of rp.Mount()'s filesystem. The caller holds a
// reference on d.
func (rp *ResolvingPath) CheckLandlockOpen(ctx context.Context, d *Dentry, isDir bool, opts *OpenOptions) error {
	dom := LandlockDomainOf(rp.creds)
	if dom == nil {
		return nil
	}
	return rp.checkLandlock(ctx, dom, d, landlockAccessFSForOpen(opts, isDir))
}

// CheckLandlockCreateOpen checks an open with opts that creates a regular file
// in directory parent against the Landlock domain of rp's credentials, as
// ResolvingPath.CheckLandlock does. The open needs
// LANDLOCK_ACCESS_FS_MAKE_REG and the rights to open the new file, all on
// parent. It returns EACCES if the domain denies the open.
//
// The check must pass before the file is created, while the name is known to
// be free, so that a denied open creates nothing.
//
// Preconditions: parent is a dentry of rp.Mount()'s filesystem. The caller
// holds a reference on parent.
func (rp *ResolvingPath) CheckLandlockCreateOpen(ctx context.Context, parent *Dentry, opts *OpenOptions) error {
	dom := LandlockDomainOf(rp.creds)
	if dom == nil {
		return nil
	}
	return rp.checkLandlock(ctx, dom, parent, linux.LANDLOCK_ACCESS_FS_MAKE_REG|landlockAccessFSForOpen(opts, false /* isDir */))
}
