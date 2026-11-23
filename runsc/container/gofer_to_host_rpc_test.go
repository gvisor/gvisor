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

package container

import (
	"os"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func TestGoferToHostRPCMountNSThread(t *testing.T) {
	// The mount namespace of this process stands in for the gofer's, which joining
	// needs privileges for.
	rpc := &goferToHostRPC{goferPID: os.Getpid()}
	dir := t.TempDir()
	var want unix.Stat_t
	if err := unix.Stat(dir, &want); err != nil {
		t.Fatalf("stat(%q) failed: %v", dir, err)
	}

	var thread chan mountNSRequest
	for i := 0; i < 2; i++ {
		var res OpenMountResult
		err := rpc.OpenMount(&OpenMountArgs{Mount: &specs.Mount{Source: dir}}, &res)
		if err != nil && strings.Contains(err.Error(), "not permitted") {
			t.Skipf("can't join a mount namespace here: %v", err)
		}
		if err != nil {
			t.Fatalf("OpenMount() failed: %v", err)
		}
		if len(res.Files) != 1 {
			t.Fatalf("OpenMount() returned %d files, want 1", len(res.Files))
		}
		var got unix.Stat_t
		if err := unix.Fstat(int(res.Files[0].Fd()), &got); err != nil {
			t.Fatalf("fstat failed: %v", err)
		}
		res.Files[0].Close()
		if got.Dev != want.Dev || got.Ino != want.Ino {
			t.Errorf("OpenMount() opened %d:%d, want %d:%d", got.Dev, got.Ino, want.Dev, want.Ino)
		}
		// Every request is served by the thread that the first one started.
		if i == 0 {
			thread = rpc.mountNSRequests
		} else if rpc.mountNSRequests != thread {
			t.Errorf("the second request started another thread")
		}
	}
}

func TestGoferToHostRPCMountNSThreadSetupFailure(t *testing.T) {
	// There is no gofer with this PID, so the thread can't join its mount
	// namespace. Every request gets that error, and not only the first one.
	rpc := &goferToHostRPC{goferPID: -1}
	for i := 0; i < 3; i++ {
		var res OpenMountResult
		err := rpc.OpenMount(&OpenMountArgs{Mount: &specs.Mount{Source: t.TempDir()}}, &res)
		if err == nil || !strings.Contains(err.Error(), "mount namespace thread") {
			t.Errorf("OpenMount() #%d = %v, want an error from the mount namespace thread", i, err)
		}
	}
}
