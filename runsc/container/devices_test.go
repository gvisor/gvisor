// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package container

import (
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
)

func TestSandboxDeviceRulesForSpecDevices(t *testing.T) {
	// The devices may not be on the host, as when only a driver container has
	// them, so their rules come from the spec. A fifo has no device numbers, so it
	// gets no rule.
	spec := &specs.Spec{Linux: &specs.Linux{Devices: []specs.LinuxDevice{
		{Path: "/dev/nvidiactl", Type: "c", Major: 195, Minor: 255},
		{Path: "/dev/nvidia-uvm", Type: "u", Major: 511, Minor: 0},
		{Path: "/dev/infiniband/uverbs-test", Type: "c", Major: 231, Minor: 0},
		{Path: "/dev/test-fifo", Type: "p"},
	}}}
	rules, err := sandboxDeviceRules(&config.Config{Platform: "systrap"}, spec)
	if err != nil {
		t.Fatalf("sandboxDeviceRules(): %v", err)
	}
	// Only a cgroup v2 has the access to create devices.
	want, bad := []string{"rwm"}, []string{"r", "w", "rw", "m"}
	if !cgroup.IsOnlyV2() {
		want, bad = []string{"rw"}, []string{"r", "w", "m", "rwm"}
	}
	for _, d := range []struct {
		major, minor int64
	}{{195, 255}, {511, 0}, {231, 0}} {
		for _, access := range want {
			if r := (cgroup.DeviceRule{Type: "c", Major: d.major, Minor: d.minor, Access: access}); !slices.Contains(rules, r) {
				t.Errorf("sandboxDeviceRules() = %v, want it to include %v", rules, r)
			}
		}
		for _, access := range bad {
			if r := (cgroup.DeviceRule{Type: "c", Major: d.major, Minor: d.minor, Access: access}); slices.Contains(rules, r) {
				t.Errorf("sandboxDeviceRules() = %v, want no rule like %v", rules, r)
			}
		}
	}
}

func TestSandboxDeviceRulesUnsupportedDevice(t *testing.T) {
	for _, dev := range []specs.LinuxDevice{
		{Path: "/dev/test0", Type: "x", Major: 1, Minor: 0},
		{Path: "/dev/test1", Major: 1, Minor: 1},
		{Path: "/dev/test2", Type: "c", Major: -1, Minor: 2},
	} {
		spec := &specs.Spec{Linux: &specs.Linux{Devices: []specs.LinuxDevice{dev}}}
		if rules, err := sandboxDeviceRules(&config.Config{Platform: "systrap"}, spec); err == nil {
			t.Errorf("sandboxDeviceRules() with the device %+v = %v, want an error", dev, rules)
		}
	}
}
