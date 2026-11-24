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
	"errors"
	"fmt"
	"os"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/platform/platformdesc"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// sandboxDeviceRules returns the device cgroup rules for the host devices that
// runsc, the sentry and the gofer open on behalf of a container with the given
// spec.
func sandboxDeviceRules(conf *config.Config, spec *specs.Spec) ([]cgroup.DeviceRule, error) {
	rules := []cgroup.DeviceRule{
		// runsc runs in the sandbox cgroup while it spawns the sandbox processes
		// when it cannot clone them directly into the cgroup, and opens
		// /dev/null and pseudo-terminals for them.
		{Type: "c", Major: 1, Minor: 3, Access: "rw"},
		{Type: "c", Major: 5, Minor: 2, Access: "rw"},
		{Type: "c", Major: 136, Minor: cgroup.DeviceAny, Access: "rw"},
		// The gofer creates overlayfs whiteouts in overlay upper layers.
		{Type: "c", Major: 0, Minor: 0, Access: "m"},
	}
	// A device that does not exist is left to whatever opens it later, which
	// reports the error.
	addFromPath := func(path, access string) error {
		r, err := deviceRuleForPath(path, access)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		rules = append(rules, r)
		return nil
	}
	addFromSpec := func(dev specs.LinuxDevice, access string) error {
		// A fifo has no device numbers, so it needs no rule.
		if dev.Type == "p" {
			return nil
		}
		r, err := deviceRuleForSpec(dev, access)
		if err != nil {
			return err
		}
		rules = append(rules, r)
		return nil
	}
	// The sentry holds /dev/cpu_dma_latency open to cap host CPU idle states.
	if err := addFromPath("/dev/cpu_dma_latency", "w"); err != nil {
		return nil, err
	}
	// runsc opens the platform's device and donates it to the sentry.
	p, err := platformdesc.Lookup(conf.Platform)
	if err != nil {
		return nil, err
	}
	if p.Device != "" {
		path := conf.PlatformDeviceFor(conf.Platform)
		if path == "" {
			path = p.Device
		}
		if err := addFromPath(path, "rw"); err != nil {
			return nil, err
		}
	}
	// The gofer opens the container's devices for the sentry, and the process that
	// starts it may create them. They may not be in the host's /dev, so their
	// numbers come from the spec.
	if spec.Linux != nil {
		// Creating a device needs the "m" access. On cgroup v2 it is always
		// added. On cgroup v1 it is left out, because the kernel rejects the
		// rule if the parent cgroup doesn't allow it, and that would fail the
		// start. Without it, creating a device fails, and the gofer uses the
		// host's device instead.
		access := "rw"
		if cgroup.IsOnlyV2() {
			access = "rwm"
		}
		for _, dev := range spec.Linux.Devices {
			if err := addFromSpec(dev, access); err != nil {
				return nil, err
			}
		}
	}
	if specutils.GPUFunctionalityRequestedViaHook(spec, conf) {
		// nvidia-container-cli, which may run in the sandbox cgroup, creates
		// the device files for the GPUs visible to the container inside its
		// rootfs, where the image can spoof them. Allow the NVIDIA drivers'
		// devices by major number instead.
		majors, err := specutils.NvidiaCharMajors("/proc")
		if err != nil {
			return nil, err
		}
		for _, major := range majors {
			rules = append(rules, cgroup.DeviceRule{Type: "c", Major: major, Minor: cgroup.DeviceAny, Access: "rwm"})
		}
	}
	return rules, nil
}

func deviceRuleForPath(path, access string) (cgroup.DeviceRule, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return cgroup.DeviceRule{}, fmt.Errorf("stat(%q): %w", path, err)
	}
	r := cgroup.DeviceRule{
		Major:  int64(unix.Major(st.Rdev)),
		Minor:  int64(unix.Minor(st.Rdev)),
		Access: access,
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFCHR:
		r.Type = "c"
	case unix.S_IFBLK:
		r.Type = "b"
	default:
		return r, fmt.Errorf("%q is not a device", path)
	}
	return r, nil
}

// deviceRuleForSpec returns the rule for the device dev, by its type and
// numbers.
func deviceRuleForSpec(dev specs.LinuxDevice, access string) (cgroup.DeviceRule, error) {
	r := cgroup.DeviceRule{Major: dev.Major, Minor: dev.Minor, Access: access}
	switch dev.Type {
	case "c", "u":
		r.Type = "c"
	case "b":
		r.Type = "b"
	default:
		return r, fmt.Errorf("device %q has unsupported type %q", dev.Path, dev.Type)
	}
	// A negative number is a wildcard in a rule.
	if dev.Major < 0 || dev.Minor < 0 {
		return r, fmt.Errorf("device %q has invalid numbers %d:%d", dev.Path, dev.Major, dev.Minor)
	}
	return r, nil
}

// allowDevices extends the sandbox cgroup cg with the host devices that the
// sandbox opens on behalf of a container with the given spec.
func allowDevices(conf *config.Config, cg cgroup.Cgroup, spec *specs.Spec) error {
	if cg == nil {
		return nil
	}
	rules, err := sandboxDeviceRules(conf, spec)
	if err != nil {
		return err
	}
	if err := cg.AllowDevices(rules); err != nil {
		return handleCgroupInstallErr(conf, "device cgroup", err)
	}
	return nil
}
