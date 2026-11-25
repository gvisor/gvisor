// Copyright 2024 The gVisor Authors.
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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
)

func TestShouldExposeNvidiaDevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "nvidiactl", path: "/dev/nvidiactl", want: true},
		{name: "nvidia-uvm", path: "/dev/nvidia-uvm", want: true},
		{name: "nvidia0", path: "/dev/nvidia0", want: true},
		{name: "nvidia1", path: "/dev/nvidia1", want: true},
		{name: "nvidia42", path: "/dev/nvidia42", want: true},
		{name: "nvidia-uvm-tools", path: "/dev/nvidia-uvm-tools", want: true},
		{name: "nvidia-modeset", path: "/dev/nvidia-modeset", want: false},
		{name: "not nvidia", path: "/dev/sda", want: false},
		{name: "nvidia prefix but not device", path: "/dev/nvidia-cap1", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeNvidiaDevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeNvidiaDevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

// warningRecorder is a log.Emitter that records warning messages.
type warningRecorder struct {
	warnings []string
}

// Emit implements log.Emitter.Emit.
func (w *warningRecorder) Emit(_ int, level log.Level, _ time.Time, format string, v ...any) {
	if level == log.Warning {
		w.warnings = append(w.warnings, fmt.Sprintf(format, v...))
	}
}

func TestShouldExposeVFIODevice(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		want        bool
		wantWarning bool
	}{
		{name: "vfio dir", path: "/dev/vfio/vfio", want: true},
		{name: "vfio group", path: "/dev/vfio/0", want: true},
		{name: "vfio dir itself", path: "/dev/vfio", want: true},
		{name: "not vfio", path: "/dev/sda", want: false},
		{name: "not vfio and not clean", path: "/dev/sda/", want: false},
		{name: "vfio prefix but not dir", path: "/dev/vfiox", want: false},
		{name: "dotdot escape", path: "/dev/vfio/../../etc/shadow", want: false, wantWarning: true},
		{name: "dotdot within dir", path: "/dev/vfio/../vfio/0", want: false, wantWarning: true},
		{name: "trailing slash", path: "/dev/vfio/0/", want: false, wantWarning: true},
		{name: "double slash", path: "/dev/vfio//0", want: false, wantWarning: true},
		{name: "empty", path: "", want: false},
	}
	oldTarget := log.Log().Emitter
	defer log.SetTarget(oldTarget)
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			rec := &warningRecorder{}
			log.SetTarget(rec)
			got := ShouldExposeVFIODevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeVFIODevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
			gotWarning := len(rec.warnings) > 0 && strings.Contains(rec.warnings[0], tst.path)
			if gotWarning != tst.wantWarning || len(rec.warnings) > 1 {
				t.Errorf("ShouldExposeVFIODevice(%q) logged warnings %q, want warning naming the path: %v", tst.path, rec.warnings, tst.wantWarning)
			}
		})
	}
}

func TestShouldExposeTpuDevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// VFIO paths are accepted by path alone, regardless of sysfs.
		{name: "vfio dir", path: "/dev/vfio", want: true},
		{name: "vfio group", path: "/dev/vfio/0", want: true},
		{name: "vfio vfio", path: "/dev/vfio/vfio", want: true},
		{name: "vfio per-device node", path: "/dev/vfio/devices/vfio0", want: true},
		{name: "not tpu", path: "/dev/sda", want: false},
		{name: "vfio dotdot escape", path: "/dev/vfio/../../etc/shadow", want: false},
		{name: "vfio dotdot to iommu group", path: "/dev/vfio/../../sys/kernel/iommu_groups/0", want: false},
		{name: "vfio dotdot within dir", path: "/dev/vfio/../vfio/0", want: false},
		{name: "vfio trailing slash", path: "/dev/vfio/0/", want: false},
		{name: "vfio double slash", path: "/dev/vfio//0", want: false},
		{name: "group number outside vfio", path: "/etc/0", want: false},
		// Accel devices must be TPUs in sysfs; no host has accel999999.
		{name: "accel without hardware", path: "/dev/accel999999", want: false},
		{name: "accel dotdot escape", path: "/dev/accel0/../../etc/shadow", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeTpuDevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeTpuDevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

func TestSafeSetupAndMoveMountDanglingSymlink(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("filepath.EvalSymlinks(t.TempDir()) failed: %v", err)
	}
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, nil, 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", src, err)
	}
	srcFD, err := unix.OpenTree(unix.AT_FDCWD, src, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
			t.Skipf("open_tree unavailable: %v", err)
		}
		t.Fatalf("unix.OpenTree(%q) failed: %v", src, err)
	}
	defer unix.Close(srcFD)

	missing := filepath.Join(dir, "missing")
	dst := filepath.Join(dir, "dst-dangling")
	if err := os.Symlink(missing, dst); err != nil {
		t.Fatalf("os.Symlink() failed: %v", err)
	}
	if err := safeSetupAndMoveMount(srcFD, src, dst, ""); err == nil {
		t.Errorf("safeSetupAndMoveMount(%q -> %q) unexpectedly succeeded", dst, missing)
	} else if errors.Is(err, unix.ENOSYS) || errors.Is(err, os.ErrPermission) {
		t.Fatalf("safeSetupAndMoveMount(%q -> %q) failed unexpectedly: %v", dst, missing, err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("os.Lstat(%q) err = %v, want %v", missing, err, os.ErrNotExist)
	}
}

func TestShouldExposeRDMADevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "uverbs0", path: "/dev/infiniband/uverbs0", want: true},
		{name: "uverbs12", path: "/dev/infiniband/uverbs12", want: true},
		{name: "uverbs no number", path: "/dev/infiniband/uverbs", want: false},
		{name: "uverbs non-numeric suffix", path: "/dev/infiniband/uverbs0x", want: false},
		{name: "uverbs subpath", path: "/dev/infiniband/uverbs0/foo", want: false},
		{name: "dotdot escape", path: "/dev/infiniband/uverbs0/../../../etc/shadow", want: false},
		{name: "trailing slash", path: "/dev/infiniband/uverbs0/", want: false},
		{name: "trailing newline", path: "/dev/infiniband/uverbs0\n", want: false},
		{name: "dotdot to uverbs", path: "/dev/infiniband/../infiniband/uverbs0", want: false},
		{name: "double slash", path: "/dev/infiniband//uverbs0", want: false},
		{name: "other infiniband device", path: "/dev/infiniband/rdma_cm", want: false},
		{name: "not anchored", path: "/tmp/dev/infiniband/uverbs0", want: false},
		{name: "not rdma", path: "/dev/sda", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeRDMADevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeRDMADevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}
