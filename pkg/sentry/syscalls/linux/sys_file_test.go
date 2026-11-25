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

package linux

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// TestHostFDGetSeals verifies that file seals are reported for imported host
// files, which is what fcntl(F_GET_SEALS) uses for host-backed files.
func TestHostFDGetSeals(t *testing.T) {
	k, err := testutil.Boot()
	if err != nil {
		t.Fatalf("Boot failed: %v", err)
	}
	ctx := k.SupervisorContext()
	hostFS, err := host.NewFilesystem(k.VFS())
	if err != nil {
		t.Fatalf("host.NewFilesystem failed: %v", err)
	}
	defer hostFS.DecRef(ctx)
	mnt := k.VFS().NewDisconnectedMount(hostFS, nil, &vfs.MountOptions{})
	k.SetHostMount(mnt)
	t.Cleanup(k.Release)

	importFD := func(hostFD int) *vfs.FileDescription {
		t.Helper()
		// host.NewFD takes ownership of hostFD, even on failure.
		file, err := host.NewFD(ctx, mnt, hostFD, &host.NewFDOptions{})
		if err != nil {
			t.Fatalf("host.NewFD failed: %v", err)
		}
		return file
	}

	t.Run("SealedMemfd", func(t *testing.T) {
		hostFD, err := unix.MemfdCreate("seals", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
		if err != nil {
			t.Skipf("memfd_create failed: %v", err)
		}
		file := importFD(hostFD)
		defer file.DecRef(ctx)

		if !host.IsHostFD(file) {
			t.Errorf("IsHostFD on imported memfd = false, want true")
		}
		// The host may set seals at creation, for example F_SEAL_EXEC with
		// vm.memfd_noexec.
		initial, err := unix.FcntlInt(uintptr(hostFD), unix.F_GET_SEALS, 0)
		if err != nil {
			t.Fatalf("F_GET_SEALS failed: %v", err)
		}
		got, err := host.GetSeals(file)
		if err != nil || got != uint32(initial) {
			t.Errorf("GetSeals on unsealed memfd = (%#x, %v), want (%#x, nil)", got, err, initial)
		}

		const added = unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW
		if _, err := unix.FcntlInt(uintptr(hostFD), unix.F_ADD_SEALS, added); err != nil {
			t.Fatalf("F_ADD_SEALS failed: %v", err)
		}
		want := uint32(initial | added)
		got, err = host.GetSeals(file)
		if err != nil || got != want {
			t.Errorf("GetSeals = (%#x, %v), want (%#x, nil)", got, err, want)
		}
	})

	t.Run("NotSealable", func(t *testing.T) {
		// A pipe does not support seals, so the host returns EINVAL.
		fds := make([]int, 2)
		if err := unix.Pipe2(fds, unix.O_CLOEXEC); err != nil {
			t.Fatalf("Pipe2 failed: %v", err)
		}
		defer unix.Close(fds[1])
		file := importFD(fds[0])
		defer file.DecRef(ctx)

		if got, err := host.GetSeals(file); !linuxerr.Equals(linuxerr.EINVAL, err) {
			t.Errorf("GetSeals on pipe = (%#x, %v), want EINVAL", got, err)
		}
	})

	t.Run("NotHostFD", func(t *testing.T) {
		file := &vfs.FileDescription{}
		if host.IsHostFD(file) {
			t.Errorf("IsHostFD on non-host file = true, want false")
		}
		if got, err := host.GetSeals(file); !linuxerr.Equals(linuxerr.EINVAL, err) {
			t.Errorf("GetSeals on non-host file = (%#x, %v), want EINVAL", got, err)
		}
	})
}
