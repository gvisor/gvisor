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

// CheckOpenExistingFile makes the checks of an open with opts of the existing
// file d, of type ftype, that come after the permission check and before the
// open has any effect. It makes them in this order, and returns the error of
// the first that fails:
//
//  1. The file type checks of CheckOpenFileType: ELOOP and EISDIR.
//  2. For a regular file opened with O_TRUNC: EROFS if rp.Mount() is
//     read-only.
//  3. For an open with write access (O_WRONLY or O_RDWR): ETXTBSY if the file
//     is being executed. Then, for a regular file opened without O_TRUNC,
//     EROFS if rp.Mount() is read-only. If copiesUpForWrite is true, this
//     EROFS check applies to every open of a regular file without O_TRUNC
//     that needs write permission, including access mode 3.
//  4. The Landlock check of CheckLandlockOpen.
//  5. For an open that needs write permission without write access
//     (O_RDONLY|O_TRUNC, or access mode 3): ETXTBSY if the file is being
//     executed.
//
// For example, O_WRONLY|O_TRUNC of a running executable on a read-only mount
// fails with EROFS, while O_WRONLY fails with ETXTBSY. Only files whose
// DentryImpl implements WriteCounter can fail with ETXTBSY.
//
// copiesUpForWrite is true if the filesystem copies a regular file up for
// every open that needs write permission, so that such an open writes to
// rp.Mount(). For example, overlay copies a lower regular file up even for an
// ioctl-only open (access mode 3), so that open fails with EROFS on a
// read-only overlay mount, while the same open succeeds on a read-only tmpfs
// mount.
//
// The EROFS checks do not keep rp.Mount() writable after they return, so the
// open must still call Mount.CheckBeginWrite before it writes to the file,
// for example to truncate it.
//
// Preconditions: d is a dentry of rp.Mount()'s filesystem. The caller holds a
// reference on d.
func (rp *ResolvingPath) CheckOpenExistingFile(ctx context.Context, d *Dentry, ftype linux.FileMode, copiesUpForWrite bool, opts *OpenOptions) error {
	if err := CheckOpenFileType(ftype, opts); err != nil {
		return err
	}
	regular := ftype.FileType() == linux.ModeRegular
	trunc := opts.Flags&linux.O_TRUNC != 0
	writeAccess := MayWriteFileWithOpenFlags(opts.Flags)
	// writePerm includes O_TRUNC and access mode 3.
	writePerm := AccessTypesForOpenFlags(opts).MayWrite()
	if regular && trunc {
		if err := rp.mount.checkWritable(); err != nil {
			return err
		}
	}
	if writeAccess {
		if err := checkWriteCount(d); err != nil {
			return err
		}
	}
	if regular && !trunc && (writeAccess || copiesUpForWrite && writePerm) {
		if err := rp.mount.checkWritable(); err != nil {
			return err
		}
	}
	if err := rp.CheckLandlockOpen(ctx, d, ftype.FileType() == linux.ModeDirectory, opts); err != nil {
		return err
	}
	if !writeAccess && writePerm {
		return checkWriteCount(d)
	}
	return nil
}

// checkWriteCount returns ETXTBSY if the file that d represents is being
// executed. Files whose DentryImpl does not implement WriteCounter are never
// being executed.
func checkWriteCount(d *Dentry) error {
	if wc, ok := d.impl.(WriteCounter); ok {
		return wc.WriteCount().CheckWrite()
	}
	return nil
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

// CheckOpenAccessFS returns nil if d allows an open with opts of the existing
// file at vd, and EACCES otherwise. isDir is true if the file is a directory.
// The open needs the rights that ResolvingPath.CheckLandlockOpen checks, and
// CheckOpenAccessFS walks from vd as CheckAccessFS does, handing the
// references that the walk takes to deferred.
//
// For example, an open with O_RDWR of a file needs
// LANDLOCK_ACCESS_FS_READ_FILE and LANDLOCK_ACCESS_FS_WRITE_FILE, and an open
// with access mode 3 needs no right.
//
// Preconditions: The caller holds a reference on vd.
func (d *LandlockDomain) CheckOpenAccessFS(ctx context.Context, vd VirtualDentry, isDir bool, opts *OpenOptions, deferred *DeferredDecRefs) error {
	if d == nil {
		return nil
	}
	return d.CheckAccessFS(ctx, vd, landlockAccessFSForOpen(opts, isDir), deferred)
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
