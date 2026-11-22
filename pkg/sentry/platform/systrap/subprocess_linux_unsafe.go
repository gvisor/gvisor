// Copyright 2018 The gVisor Authors.
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

//go:build amd64 || linux
// +build amd64 linux

package systrap

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostsyscall"
)

// unmaskAllSignals unmasks all signals on the current thread.
//
// It is called in a child process after fork(), so the race instrumentation
// has to be disabled.
//
//go:nosplit
//go:norace
func unmaskAllSignals() unix.Errno {
	var set linux.SignalSet
	errno := hostsyscall.RawSyscallErrno6(unix.SYS_RT_SIGPROCMASK, linux.SIG_SETMASK, uintptr(unsafe.Pointer(&set)), 0, linux.SignalSetSize, 0, 0)
	return errno
}
