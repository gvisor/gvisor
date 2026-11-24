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
	"os"
	"path/filepath"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/config"
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

func TestShouldExposeVFIODevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "vfio dir", path: "/dev/vfio/vfio", want: true},
		{name: "vfio group", path: "/dev/vfio/0", want: true},
		{name: "vfio dir itself", path: "/dev/vfio", want: true},
		{name: "not vfio", path: "/dev/sda", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeVFIODevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeVFIODevice(%q) = %v, want %v", tst.path, got, tst.want)
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
		// VFIO devices are always detected as TPU devices regardless of sysfs.
		{name: "vfio device", path: "/dev/vfio/0", want: true},
		{name: "vfio vfio", path: "/dev/vfio/vfio", want: true},
		{name: "not tpu", path: "/dev/sda", want: false},
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

func TestMsFlagsToMountAttr(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flags   uint32
		wantSet uint64
		wantClr uint64
	}{
		{name: "none"},
		{name: "readonly", flags: unix.MS_RDONLY, wantSet: unix.MOUNT_ATTR_RDONLY},
		{name: "nosuid", flags: unix.MS_NOSUID, wantSet: unix.MOUNT_ATTR_NOSUID},
		{name: "nodev", flags: unix.MS_NODEV, wantSet: unix.MOUNT_ATTR_NODEV},
		{name: "noexec", flags: unix.MS_NOEXEC, wantSet: unix.MOUNT_ATTR_NOEXEC},
		{name: "nodiratime", flags: unix.MS_NODIRATIME, wantSet: unix.MOUNT_ATTR_NODIRATIME},
		{
			name:    "noatime",
			flags:   unix.MS_NOATIME,
			wantSet: unix.MOUNT_ATTR_NOATIME,
			wantClr: unix.MOUNT_ATTR__ATIME,
		},
		{
			name:    "relatime",
			flags:   unix.MS_RELATIME,
			wantSet: unix.MOUNT_ATTR_RELATIME,
			wantClr: unix.MOUNT_ATTR__ATIME,
		},
		{
			name:    "strictatime",
			flags:   unix.MS_STRICTATIME,
			wantSet: unix.MOUNT_ATTR_STRICTATIME,
			wantClr: unix.MOUNT_ATTR__ATIME,
		},
		{
			// noatime wins over the other access time flags.
			name:    "noatime and relatime",
			flags:   unix.MS_NOATIME | unix.MS_RELATIME,
			wantSet: unix.MOUNT_ATTR_NOATIME,
			wantClr: unix.MOUNT_ATTR__ATIME,
		},
		{
			name:    "several",
			flags:   unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
			wantSet: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC,
		},
		{
			// Flags that are not mount attributes are ignored.
			name:  "bind",
			flags: unix.MS_BIND | unix.MS_REC,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotSet, gotClr := msFlagsToMountAttr(tc.flags)
			if gotSet != tc.wantSet || gotClr != tc.wantClr {
				t.Errorf("msFlagsToMountAttr(%#x) = %#x, %#x, want %#x, %#x", tc.flags, gotSet, gotClr, tc.wantSet, tc.wantClr)
			}
		})
	}
}

func TestSetupDev(t *testing.T) {
	nvproxy := &config.Config{NVProxy: true}
	nvidiactl := specs.LinuxDevice{Path: "/dev/nvidiactl", Type: "c", Major: 195, Minor: 255}
	specWith := func(devs ...specs.LinuxDevice) *specs.Spec {
		return &specs.Spec{Linux: &specs.Linux{Devices: devs}}
	}
	// A DeviceCreator that fails, so that the host's devices are mounted.
	fail := func(*specs.LinuxDevice) (string, error) { return "", errors.New("not permitted") }

	// A DeviceCreator that creates the device in a directory of its own. FIFOs
	// stand in for the devices, as they can be created in any user namespace.
	creator := func(t *testing.T, calls *int) DeviceCreator {
		dir := filepath.Join(t.TempDir(), "dev")
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := MountDevicesDir(dir); err != nil {
			t.Skipf("can't mount a tmpfs here: %v", err)
		}
		t.Cleanup(func() { unix.Unmount(dir, unix.MNT_DETACH) })
		return func(dev *specs.LinuxDevice) (string, error) {
			*calls++
			fifo := *dev
			fifo.Type = "p"
			return CreateDevice(&fifo, dir)
		}
	}
	// skipIfCantMount skips the test if err is that a mount is not permitted.
	skipIfCantMount := func(t *testing.T, err error) {
		t.Helper()
		if err != nil && strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("can't mount here: %v", err)
		}
	}

	t.Run("creates the dev directory", func(t *testing.T) {
		for name, spec := range map[string]*specs.Spec{
			"no devices": specWith(),
			"no linux":   {},
		} {
			root := t.TempDir()
			if err := SetupDev(spec, nvproxy, root, "/proc", fail); err != nil {
				t.Fatalf("%s: SetupDev() failed: %v", name, err)
			}
			if fi, err := os.Stat(filepath.Join(root, "dev")); err != nil || !fi.IsDir() {
				t.Errorf("%s: SetupDev() did not create the dev directory: %v", name, err)
			}
		}
	})

	t.Run("skips devices that are not exposed", func(t *testing.T) {
		// /dev/sda is not one of the devices that are exposed, so none is
		// created or mounted.
		root := t.TempDir()
		calls := 0
		count := func(*specs.LinuxDevice) (string, error) { calls++; return "", errors.New("unexpected call") }
		spec := specWith(specs.LinuxDevice{Path: "/dev/sda", Type: "b", Major: 8, Minor: 0})
		if err := SetupDev(spec, nvproxy, root, "/proc", count); err != nil {
			t.Fatalf("SetupDev() failed: %v", err)
		}
		if entries, _ := os.ReadDir(filepath.Join(root, "dev")); len(entries) != 0 {
			t.Errorf("SetupDev() created %v for a device that is not exposed, want nothing", entries)
		}
	})

	t.Run("fails for an Nvidia device with the numbers of another device", func(t *testing.T) {
		root := t.TempDir()
		calls := 0
		count := func(*specs.LinuxDevice) (string, error) { calls++; return "", errors.New("unexpected call") }
		spec := specWith(specs.LinuxDevice{Path: "/dev/nvidia0", Type: "c", Major: 1, Minor: 1})
		err := SetupDev(spec, nvproxy, root, "/proc", count)
		if err == nil || !strings.Contains(err.Error(), "/dev/nvidia0") {
			t.Errorf("SetupDev() = %v, want an error about /dev/nvidia0", err)
		}
		if calls != 0 {
			t.Errorf("SetupDev() asked for a device that it refuses to be created %d times, want 0", calls)
		}
	})

	t.Run("fails for a device of another proxy that is not on the host", func(t *testing.T) {
		root := t.TempDir()
		calls := 0
		count := func(*specs.LinuxDevice) (string, error) { calls++; return "", errors.New("unexpected call") }
		spec := specWith(specs.LinuxDevice{Path: "/dev/infiniband/uverbs99999", Type: "c", Major: 231, Minor: 99999})
		err := SetupDev(spec, &config.Config{RDMAProxy: true}, root, "/proc", count)
		if err == nil || !strings.Contains(err.Error(), "/dev/infiniband/uverbs99999") {
			t.Errorf("SetupDev() = %v, want an error about /dev/infiniband/uverbs99999", err)
		}
		if calls != 0 {
			t.Errorf("SetupDev() asked for a device that it refuses to be created %d times, want 0", calls)
		}
	})

	t.Run("skips devices when the proxy is not enabled", func(t *testing.T) {
		// Without /dev/nvidiactl in the spec, nvproxy is not enabled.
		root := t.TempDir()
		spec := specWith(specs.LinuxDevice{Path: "/dev/nvidia99999", Type: "c", Major: 195, Minor: 99999})
		if err := SetupDev(spec, &config.Config{}, root, "/proc", fail); err != nil {
			t.Fatalf("SetupDev() failed: %v", err)
		}
		if entries, _ := os.ReadDir(filepath.Join(root, "dev")); len(entries) != 0 {
			t.Errorf("SetupDev() created %v with nvproxy disabled, want nothing", entries)
		}
	})

	t.Run("mounts a device from the host", func(t *testing.T) {
		// The host has no /dev/nvidia99999 to fall back to, so the mount fails.
		root := t.TempDir()
		spec := specWith(specs.LinuxDevice{Path: "/dev/nvidia99999", Type: "c", Major: 195, Minor: 99999})
		err := SetupDev(spec, nvproxy, root, "/proc", fail)
		if err == nil || !strings.Contains(err.Error(), "/dev/nvidia99999") {
			t.Errorf("SetupDev() = %v, want an error about /dev/nvidia99999", err)
		}
	})

	t.Run("mounts the device that was created", func(t *testing.T) {
		root := t.TempDir()
		calls := 0
		spec := specWith(nvidiactl)
		err := SetupDev(spec, nvproxy, root, "/proc", creator(t, &calls))
		dst := filepath.Join(root, "dev", "nvidiactl")
		t.Cleanup(func() { unix.Unmount(dst, unix.MNT_DETACH) })
		skipIfCantMount(t, err)
		if err != nil {
			t.Fatalf("SetupDev() failed: %v", err)
		}
		if calls != 1 {
			t.Errorf("SetupDev() asked for devices to be created %d times, want 1", calls)
		}
		var st unix.Stat_t
		if err := unix.Lstat(dst, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
			t.Errorf("%s is not the device that was created: %v, mode %#o", dst, err, st.Mode)
		}
	})

	t.Run("keeps the device usable when the root becomes nodev", func(t *testing.T) {
		// SetupRootFS remounts the root nodev after SetupDev when it is read-only
		// or has an overlay. That doesn't reach the device, which is a mount of
		// its own.
		root := t.TempDir()
		if err := unix.Mount("tmpfs", root, "tmpfs", 0, ""); err != nil {
			t.Skipf("can't mount a tmpfs: %v", err)
		}
		t.Cleanup(func() { unix.Unmount(root, unix.MNT_DETACH) })
		calls := 0
		err := SetupDev(specWith(nvidiactl), nvproxy, root, "/proc", creator(t, &calls))
		dst := filepath.Join(root, "dev", "nvidiactl")
		t.Cleanup(func() { unix.Unmount(dst, unix.MNT_DETACH) })
		skipIfCantMount(t, err)
		if err != nil {
			t.Fatalf("SetupDev() failed: %v", err)
		}

		if err := unix.Mount("", root, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_NODEV, ""); err != nil {
			t.Skipf("can't remount the root nodev: %v", err)
		}
		if !mountNodev(t, filepath.Join(root, "dev")) {
			t.Fatalf("the root is not nodev after the remount")
		}
		if mountNodev(t, dst) {
			t.Errorf("the device is nodev after the root was remounted nodev, want it to have a mount of its own")
		}
	})

	t.Run("replaces a file left where a device was mounted", func(t *testing.T) {
		// Mounting a device needs a file to mount over, and one may be left in
		// place. It is replaced, and the mount then fails here, as the host has no
		// such device.
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, "dev"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "dev", "nvidia99999"), nil, 0644); err != nil {
			t.Fatal(err)
		}
		spec := specWith(specs.LinuxDevice{Path: "/dev/nvidia99999", Type: "c", Major: 195, Minor: 99999})
		err := SetupDev(spec, nvproxy, root, "/proc", fail)
		if err == nil || !strings.Contains(err.Error(), "mounting") {
			t.Errorf("SetupDev() = %v, want it to try to mount the device", err)
		}
	})
}

func TestCheckDevice(t *testing.T) {
	// The Nvidia drivers' major numbers are 195, and 511 for UVM.
	procDir := t.TempDir()
	devices := "Character devices:\n195 nvidia\n511 nvidia-uvm\n"
	if err := os.WriteFile(filepath.Join(procDir, "devices"), []byte(devices), 0644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		dev     specs.LinuxDevice
		wantErr bool
	}{
		{name: "control device", dev: specs.LinuxDevice{Path: "/dev/nvidiactl", Type: "c", Major: 195, Minor: 255}},
		{name: "unbuffered character device", dev: specs.LinuxDevice{Path: "/dev/nvidia1", Type: "u", Major: 195, Minor: 1}},
		{name: "uvm, which has a dynamic major number", dev: specs.LinuxDevice{Path: "/dev/nvidia-uvm", Type: "c", Major: 511, Minor: 0}},
		{name: "gpu with the numbers of another device", dev: specs.LinuxDevice{Path: "/dev/nvidia0", Type: "c", Major: 1, Minor: 1}, wantErr: true},
		{name: "uvm with the major number of no Nvidia driver", dev: specs.LinuxDevice{Path: "/dev/nvidia-uvm", Type: "c", Major: 510, Minor: 0}, wantErr: true},
		{name: "control device that is a block device", dev: specs.LinuxDevice{Path: "/dev/nvidiactl", Type: "b", Major: 195, Minor: 255}, wantErr: true},
		{name: "gpu that is a fifo", dev: specs.LinuxDevice{Path: "/dev/nvidia0", Type: "p"}, wantErr: true},
		{name: "rdma device that is not on the host", dev: specs.LinuxDevice{Path: "/dev/infiniband/uverbs99999", Type: "c", Major: 231, Minor: 99999}, wantErr: true},
		{name: "tpu device that is a block device", dev: specs.LinuxDevice{Path: "/dev/accel99999", Type: "b", Major: 1, Minor: 3}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkDevice(&tc.dev, procDir); (err != nil) != tc.wantErr {
				t.Errorf("checkDevice(%+v) = %v, want error: %t", tc.dev, err, tc.wantErr)
			}
		})
	}

	t.Run("no major numbers to check against", func(t *testing.T) {
		dev := specs.LinuxDevice{Path: "/dev/nvidia0", Type: "c", Major: 195, Minor: 0}
		if err := checkDevice(&dev, t.TempDir()); err == nil {
			t.Error("checkDevice() without /proc/devices = nil, want error")
		}
	})
}

func TestCheckHostDevice(t *testing.T) {
	// /dev/null is 1:3 on every host.
	for _, tc := range []struct {
		name    string
		dev     specs.LinuxDevice
		wantErr bool
	}{
		{name: "the device on the host", dev: specs.LinuxDevice{Path: "/dev/null", Type: "c", Major: 1, Minor: 3}},
		{name: "another device's numbers", dev: specs.LinuxDevice{Path: "/dev/null", Type: "c", Major: 1, Minor: 5}, wantErr: true},
		{name: "a path that is not a device", dev: specs.LinuxDevice{Path: "/dev", Type: "c", Major: 1, Minor: 3}, wantErr: true},
		{name: "a path that is not on the host", dev: specs.LinuxDevice{Path: "/dev/not-on-the-host", Type: "c", Major: 1, Minor: 3}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkHostDevice(&tc.dev); (err != nil) != tc.wantErr {
				t.Errorf("checkHostDevice(%+v) = %v, want error: %t", tc.dev, err, tc.wantErr)
			}
		})
	}
}
