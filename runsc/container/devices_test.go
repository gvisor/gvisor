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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
)

func TestParseDeviceMajors(t *testing.T) {
	const procDevices = `Character devices:
  1 mem
195 nvidia
235 nvidia-caps
510 nvidia-uvm

Block devices:
  8 sd
`
	got, err := parseDeviceMajors(strings.NewReader(procDevices), []string{"nvidia-uvm", "nvidia-caps"})
	if err != nil {
		t.Fatalf("parseDeviceMajors(): %v", err)
	}
	if want := []int64{235, 510}; !slices.Equal(got, want) {
		t.Errorf("parseDeviceMajors() = %v, want %v", got, want)
	}
}

func TestSandboxDeviceRules(t *testing.T) {
	// The cases below build rules from the host /dev/zero (1:5).
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Fatalf("stat(/dev/zero): %v", err)
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatalf("Mkfifo(%q): %v", fifo, err)
	}
	zeroRule := cgroup.DeviceRule{Type: "c", Major: 1, Minor: 5, Access: "rw"}
	zero := specs.LinuxDevice{Path: "/dev/zero", Type: "c", Major: 1, Minor: 5}
	for _, tc := range []struct {
		name    string
		policy  config.CharacterDevicePolicy
		devices []specs.LinuxDevice
		// wantZero is true if the rules must allow the host /dev/zero.
		wantZero bool
	}{
		{name: "EmulatedOnly", policy: config.CharDevEmulatedOnly, devices: []specs.LinuxDevice{zero}},
		{name: "Passthrough", policy: config.CharDevPassthrough, devices: []specs.LinuxDevice{zero}, wantZero: true},
		// The host path is not a device, so it is skipped.
		{name: "NotADevice", policy: config.CharDevPassthrough, devices: []specs.LinuxDevice{{Path: fifo, Type: "c", Major: 1, Minor: 5}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := testutil.TestConfig(t)
			conf.CharacterDevicePolicy = tc.policy
			spec := &specs.Spec{Linux: &specs.Linux{Devices: tc.devices}}
			rules, err := sandboxDeviceRules(conf, spec)
			if err != nil {
				t.Fatalf("sandboxDeviceRules(): %v", err)
			}
			base, err := sandboxDeviceRules(conf, &specs.Spec{})
			if err != nil {
				t.Fatalf("sandboxDeviceRules() for an empty spec: %v", err)
			}
			want := base
			if tc.wantZero {
				want = append(slices.Clone(base), zeroRule)
			}
			if !slices.Equal(rules, want) {
				t.Errorf("sandboxDeviceRules() = %+v, want %+v", rules, want)
			}
		})
	}
}

func TestSpecDeviceNeedsHostAccess(t *testing.T) {
	char := func(path string) specs.LinuxDevice {
		return specs.LinuxDevice{Path: path, Type: "c"}
	}
	// nvidia returns a spec entry for an NVIDIA device with the given major.
	nvidia := func(path string, major int64) specs.LinuxDevice {
		return specs.LinuxDevice{Path: path, Type: "c", Major: major}
	}
	// nvidiaMajors are the NVIDIA majors when nvproxy is enabled: the GPU and
	// control devices, and example majors for uvm and caps.
	nvidiaMajors := []int64{195, 511, 237}
	for _, tc := range []struct {
		name   string
		policy config.CharacterDevicePolicy
		rdma   bool
		// hooks is true if the spec has a CreateContainer hook.
		hooks bool
		// nvidiaMajors are passed to specDeviceNeedsHostAccess.
		nvidiaMajors []int64
		// listed are the other devices in the spec, which may enable a proxy.
		listed []specs.LinuxDevice
		dev    specs.LinuxDevice
		want   bool
	}{
		{name: "EmulatedOnly", dev: char("/dev/kvm")},
		{name: "PreferEmulated", policy: config.CharDevPreferEmulated, dev: char("/dev/kvm"), want: true},
		{name: "Passthrough", policy: config.CharDevPassthrough, dev: char("/dev/kvm"), want: true},
		{name: "Block", policy: config.CharDevPassthrough, dev: specs.LinuxDevice{Path: "/dev/sda", Type: "b"}},
		{name: "CreateContainerHook", hooks: true, dev: specs.LinuxDevice{Path: "/dev/sda", Type: "b"}, want: true},
		{name: "NVProxyGPU", nvidiaMajors: nvidiaMajors, dev: nvidia("/dev/nvidia0", 195), want: true},
		{name: "NVProxyCaps", nvidiaMajors: nvidiaMajors, dev: nvidia("/dev/nvidia-caps/nvidia-cap1", 237), want: true},
		{name: "NVProxyOtherMajor", nvidiaMajors: nvidiaMajors, dev: nvidia("/dev/foo", 10)},
		{name: "NVProxyDisabled", dev: nvidia("/dev/nvidia0", 195)},
		{name: "TPUProxyAccel", dev: char("/dev/accel0"), want: true},
		{name: "TPUProxyVFIO", dev: char("/dev/vfio/0"), want: true},
		{name: "RDMAProxy", rdma: true, dev: char("/dev/infiniband/uverbs0"), want: true},
		{name: "RDMAProxyDisabled", dev: char("/dev/infiniband/uverbs0")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := testutil.TestConfig(t)
			conf.CharacterDevicePolicy = tc.policy
			conf.RDMAProxy = tc.rdma
			spec := &specs.Spec{Linux: &specs.Linux{Devices: append(slices.Clone(tc.listed), tc.dev)}}
			if tc.hooks {
				spec.Hooks = &specs.Hooks{CreateContainer: []specs.Hook{{Path: "/bin/true"}}}
			}
			if got := specDeviceNeedsHostAccess(conf, spec, &tc.dev, tc.nvidiaMajors); got != tc.want {
				t.Errorf("specDeviceNeedsHostAccess(%+v) = %t, want %t", tc.dev, got, tc.want)
			}
		})
	}
}
