// Copyright 2019 The gVisor Authors.
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

package gofer

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func (i *inode) isSymlink() bool {
	return i.fileType() == linux.S_IFLNK
}

// Precondition: d.isSymlink().
func (d *dentry) readlink(ctx context.Context, mnt *vfs.Mount) (string, error) {
	if d.inode.fs.opts.interop == InteropModeShared {
		return d.inode.readlinkImpl(ctx)
	}
	d.touchAtime(mnt)
	d.inode.dataMu.Lock()
	defer d.inode.dataMu.Unlock()
	if d.inode.haveTarget {
		return d.inode.target, nil
	}
	target, err := d.inode.readlinkImpl(ctx)
	if err == nil {
		d.inode.haveTarget = true
		d.inode.target = target
	}
	return target, err
}
