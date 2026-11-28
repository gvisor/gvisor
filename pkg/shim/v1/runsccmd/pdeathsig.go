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
	"sync"

	runc "github.com/containerd/go-runc"
)

// startThread returns a channel that carries functions to run on the thread
// that forks commands with a parent-death signal. The first call starts the
// goroutine that serves it.
var startThread = sync.OnceValue(func() chan<- func() {
	ch := make(chan func())
	go func() {
		// Do not unlock: the thread must stay alive for the lifetime of the
		// process, and no other goroutine may run on it.
		runtime.LockOSThread()
		// If this goroutine exits (for example, if f calls runtime.Goexit),
		// Go ends the thread, the children it forked get their parent-death
		// signal, and later starts block forever. Crash instead.
		defer panic("runsccmd: start thread exited")
		for f := range ch {
			f()
		}
	}()
	return ch
})

// startMonitored starts cmd with Monitor. If cmd has a parent-death signal,
// it starts cmd on an OS thread that is locked to one goroutine and never
// exits. These starts run one at a time.
//
// Linux sends the parent-death signal of a child (PR_SET_PDEATHSIG) when the
// thread that forked the child exits, not when the process exits. Go ends an
// OS thread when a goroutine exits while it is locked to that thread, which
// some libraries do on purpose (for example, containerd's mount.Mount for
// overlay mounts with long options). Without a dedicated thread, such a
// goroutine can end the thread that forked a running child, and the child
// then gets its parent-death signal.
func startMonitored(cmd *exec.Cmd) (chan runc.Exit, error) {
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig == 0 {
		return Monitor.Start(cmd)
	}
	var (
		ec  chan runc.Exit
		err error
	)
	done := make(chan struct{})
	startThread() <- func() {
		defer close(done)
		ec, err = Monitor.Start(cmd)
	}
	<-done
	return ec, err
}
