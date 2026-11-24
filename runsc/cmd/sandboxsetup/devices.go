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
	"fmt"
	"os"
	"path/filepath"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// DeviceCreator is used when the gofer process cannot create devices itself,
// because mknod(2) of a device is not permitted in the user namespace that it
// runs in. It creates the device dev, and returns the path that the caller
// bind-mounts it from.
type DeviceCreator func(dev *specs.LinuxDevice) (string, error)

// deviceKind returns the file type bits of the node that dev names, and the
// directory of devices of its kind that it is created in.
func deviceKind(dev *specs.LinuxDevice) (uint32, string, error) {
	switch dev.Type {
	case "c", "u":
		return unix.S_IFCHR, "char", nil
	case "b":
		return unix.S_IFBLK, "block", nil
	case "p":
		return unix.S_IFIFO, "fifo", nil
	default:
		return 0, "", fmt.Errorf("unsupported device type %q", dev.Type)
	}
}

// createDevice creates the device dev at path. Like the nodes in the host's
// /dev, it is owned by root and open to everyone, so that the gofer can open
// it. The sentry gives the device that the container sees the mode and owner
// from the spec.
func createDevice(dev *specs.LinuxDevice, fileType uint32, path string) error {
	const mode = 0666
	if err := unix.Mknod(path, fileType|mode, int(unix.Mkdev(uint32(dev.Major), uint32(dev.Minor)))); err != nil {
		return err
	}
	// The mode can differ from the one asked for because of the umask.
	return unix.Chmod(path, mode)
}

// MountDevicesDir mounts the tmpfs that devices are created in at dir, which
// the gofer creates.
//
// A tmpfs mounted from a user namespace is nodev, and a device can't be opened
// on it, so this has to run in the initial user namespace. It stays mounted for
// the lifetime of the gofer.
func MountDevicesDir(dir string) error {
	if err := unix.Mount("dev", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC, "mode=755"); err != nil {
		return fmt.Errorf("mounting a tmpfs on %q: %w", dir, err)
	}
	return nil
}

// CreateDevice creates the device dev in dir, and returns its path. It is in a
// directory for its kind, char, block or fifo, and is named by its device
// number, as in /dev/char. A fifo has no device number, so it is named by its
// path instead.
//
// This has to run in the mount namespace of the gofer, with the privileges of
// the initial user namespace, after MountDevicesDir. The gofer can't create
// the device itself, because by default it runs in a user namespace, where
// mknod(2) of a device is not permitted.
func CreateDevice(dev *specs.LinuxDevice, dir string) (string, error) {
	fileType, kind, err := deviceKind(dev)
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("%d:%d", dev.Major, dev.Minor)
	if fileType == unix.S_IFIFO {
		name = filepath.Clean("/" + dev.Path)
	}
	path := filepath.Join(dir, kind, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", err
	}
	// The umask can make the directories less open, and the gofer has to search
	// them.
	for d := filepath.Dir(path); d != filepath.Clean(dir); d = filepath.Dir(d) {
		if err := os.Chmod(d, 0755); err != nil {
			return "", err
		}
	}
	if err := createDevice(dev, fileType, path); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}
