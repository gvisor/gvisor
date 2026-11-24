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

package sandboxsetup

import (
	"os"
	"path/filepath"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func TestDeviceKind(t *testing.T) {
	for _, tc := range []struct {
		devType  string
		wantType uint32
		wantDir  string
		wantErr  bool
	}{
		{devType: "c", wantType: unix.S_IFCHR, wantDir: "char"},
		{devType: "u", wantType: unix.S_IFCHR, wantDir: "char"},
		{devType: "b", wantType: unix.S_IFBLK, wantDir: "block"},
		{devType: "p", wantType: unix.S_IFIFO, wantDir: "fifo"},
		{devType: "", wantErr: true},
		{devType: "x", wantErr: true},
	} {
		gotType, gotDir, err := deviceKind(&specs.LinuxDevice{Type: tc.devType})
		if (err != nil) != tc.wantErr || gotType != tc.wantType || gotDir != tc.wantDir {
			t.Errorf("deviceKind(%q) = %#o, %q, %v, want %#o, %q, error: %t", tc.devType, gotType, gotDir, err, tc.wantType, tc.wantDir, tc.wantErr)
		}
	}
}

// mountNodev reports whether the mount at path is nodev.
func mountNodev(t *testing.T, path string) bool {
	t.Helper()
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		t.Fatalf("statfs(%q) failed: %v", path, err)
	}
	return st.Flags&unix.ST_NODEV != 0
}

func TestCreateDevice(t *testing.T) {
	// FIFOs stand in for the devices, as they can be created in any user
	// namespace. The mode and owner that the spec asks for are not the creating
	// process's own.
	mode, uid, gid := os.FileMode(0600), uint32(os.Geteuid())+1, uint32(os.Getegid())+1
	dir := filepath.Join(t.TempDir(), "dev")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := MountDevicesDir(dir); err != nil {
		t.Skipf("can't mount a tmpfs here: %v", err)
	}
	t.Cleanup(func() { unix.Unmount(dir, unix.MNT_DETACH) })
	if mountNodev(t, dir) {
		t.Errorf("the devices directory is nodev, and devices can't be opened on it")
	}

	for _, tc := range []struct {
		name     string
		dev      specs.LinuxDevice
		wantName string
	}{
		{name: "defaults", dev: specs.LinuxDevice{Path: "/dev/nvidiactl", Type: "p", Major: 195, Minor: 255}, wantName: "fifo/dev/nvidiactl"},
		{name: "mode and owner in the spec", dev: specs.LinuxDevice{Path: "/dev/nvidia0", Type: "p", Major: 195, Minor: 0, FileMode: &mode, UID: &uid, GID: &gid}, wantName: "fifo/dev/nvidia0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, err := CreateDevice(&tc.dev, dir)
			if err != nil {
				t.Fatalf("CreateDevice() failed: %v", err)
			}
			if want := filepath.Join(dir, tc.wantName); path != want {
				t.Errorf("CreateDevice() = %q, want %q", path, want)
			}
			var st unix.Stat_t
			if err := unix.Stat(path, &st); err != nil {
				t.Fatalf("stat failed: %v", err)
			}
			if st.Mode&unix.S_IFMT != unix.S_IFIFO {
				t.Errorf("the device has mode %#o, want a FIFO", st.Mode)
			}
			// The device is open to everyone and owned by the creating process,
			// whatever mode and owner the spec asks for.
			if got := os.FileMode(st.Mode).Perm(); got != 0666 {
				t.Errorf("the device has permissions %v, want 0666", got)
			}
			if st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(os.Getegid()) {
				t.Errorf("the device is owned by %d:%d, want %d:%d", st.Uid, st.Gid, os.Geteuid(), os.Getegid())
			}
		})
	}

	t.Run("unsupported type", func(t *testing.T) {
		if path, err := CreateDevice(&specs.LinuxDevice{Type: "x", Major: 1, Minor: 1}, dir); err == nil {
			t.Errorf("CreateDevice() of an unsupported type = %q, want error", path)
		}
	})
	t.Run("exists", func(t *testing.T) {
		dev := specs.LinuxDevice{Path: "/dev/nvidiactl", Type: "p"}
		if path, err := CreateDevice(&dev, dir); err == nil {
			t.Errorf("CreateDevice() of a device that exists = %q, want error", path)
		}
	})
}

func TestCreateDeviceFifoNames(t *testing.T) {
	// A fifo is named by its path, so fifos with the same base name or the same
	// device number don't collide, and a path can't leave the directory.
	dir := filepath.Join(t.TempDir(), "dev")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := MountDevicesDir(dir); err != nil {
		t.Skipf("can't mount a tmpfs here: %v", err)
	}
	t.Cleanup(func() { unix.Unmount(dir, unix.MNT_DETACH) })
	for path, want := range map[string]string{
		"/run/a/app.fifo":       "fifo/run/a/app.fifo",
		"/run/b/app.fifo":       "fifo/run/b/app.fifo",
		"/../../../escape.fifo": "fifo/escape.fifo",
	} {
		got, err := CreateDevice(&specs.LinuxDevice{Path: path, Type: "p"}, dir)
		if err != nil {
			t.Errorf("CreateDevice(%q) failed: %v", path, err)
			continue
		}
		if wantPath := filepath.Join(dir, want); got != wantPath {
			t.Errorf("CreateDevice(%q) = %q, want %q", path, got, wantPath)
		}
	}
}

func TestCreateDeviceDirectoriesAreOpen(t *testing.T) {
	// The gofer has to search the directories that devices are created in,
	// whatever umask runsc runs with.
	dir := filepath.Join(t.TempDir(), "dev")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := MountDevicesDir(dir); err != nil {
		t.Skipf("can't mount a tmpfs here: %v", err)
	}
	t.Cleanup(func() { unix.Unmount(dir, unix.MNT_DETACH) })
	defer unix.Umask(unix.Umask(0077))

	path, err := CreateDevice(&specs.LinuxDevice{Path: "/run/a/app.fifo", Type: "p"}, dir)
	if err != nil {
		t.Fatalf("CreateDevice() failed: %v", err)
	}
	for d := filepath.Dir(path); d != dir; d = filepath.Dir(d) {
		var st unix.Stat_t
		if err := unix.Stat(d, &st); err != nil {
			t.Fatalf("stat(%q) failed: %v", d, err)
		}
		if got := os.FileMode(st.Mode).Perm(); got != 0755 {
			t.Errorf("%q has permissions %v, want 0755", d, got)
		}
	}
}
