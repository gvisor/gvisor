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

package nvconf

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
)

func TestOpenNvidiaCtlDevice(t *testing.T) {
	// This only has something to open on a host with the driver loaded.
	fd, err := openNvidiaCtlDevice()
	if err != nil && strings.Contains(err.Error(), "failed to open /dev/nvidiactl") {
		t.Skipf("can't open the control device here: %v", err)
	}
	if err != nil {
		t.Fatalf("openNvidiaCtlDevice() failed: %v", err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatalf("fstat failed: %v", err)
	}
	major, minor := unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev))
	if st.Mode&unix.S_IFMT != unix.S_IFCHR || major != nvgpu.NV_MAJOR_DEVICE_NUMBER || minor != nvgpu.NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE {
		t.Errorf("the device is mode %#o, rdev %d:%d, want a character device %d:%d", st.Mode, major, minor, nvgpu.NV_MAJOR_DEVICE_NUMBER, nvgpu.NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE)
	}
}

func TestOpenInMemoryCharDevice(t *testing.T) {
	// 1:3 is /dev/null, which stands in for a device that the host doesn't have a
	// node for. Each device is on a tmpfs of its own, so opening the same number
	// twice doesn't collide.
	for i := 0; i < 2; i++ {
		fd, err := openInMemoryCharDevice(1, 3)
		if err != nil && (strings.Contains(err.Error(), "not permitted") || strings.Contains(err.Error(), "not implemented")) {
			t.Skipf("can't make an in-memory device here: %v", err)
		}
		if err != nil {
			t.Fatalf("openInMemoryCharDevice() #%d failed: %v", i, err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			t.Fatalf("fstat failed: %v", err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(uint64(st.Rdev)) != 1 || unix.Minor(uint64(st.Rdev)) != 3 {
			t.Errorf("the device is mode %#o, rdev %d:%d, want a character device 1:3", st.Mode, unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev)))
		}
		unix.Close(fd)
	}
}
