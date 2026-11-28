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

package runsccmd

import (
	"os/exec"
	"runtime"

	runc "github.com/containerd/go-runc"
	"golang.org/x/sys/unix"
)

// startLocked starts cmd with m on a new goroutine, which stays locked to its
// OS thread until the child process exits.
//
// Linux sends the parent-death signal of a child (PR_SET_PDEATHSIG) when the
// thread that forked the child exits, not when the process exits. Go ends an
// OS thread when a goroutine exits while it is locked to that thread, which
// some libraries do on purpose (for example, containerd's mount.Mount for
// overlay mounts with long options). A thread that is locked to a goroutine
// runs no other goroutine, so no such library call can end it.
//
// The goroutine waits for the child to exit with WNOWAIT, so the child is
// still reaped by m (for example, by containerd's reaper).
func startLocked(m ProcessMonitor, cmd *exec.Cmd) (chan runc.Exit, error) {
	type result struct {
		ec  chan runc.Exit
		err error
	}
	started := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		ec, err := m.Start(cmd)
		pid := 0
		if err == nil {
			pid = cmd.Process.Pid
		}
		started <- result{ec: ec, err: err}
		if err == nil {
			waitExited(pid)
		}
		runtime.UnlockOSThread()
	}()
	r := <-started
	return r.ec, r.err
}

// waitExited blocks until the child process pid exits, without reaping it. It
// also returns if pid is not a child, for example because it was already
// reaped.
func waitExited(pid int) {
	for {
		var info unix.Siginfo
		if err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil); err != unix.EINTR {
			return
		}
	}
}
