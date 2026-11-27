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

package lisafs

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

func TestConnectBlocking(t *testing.T) {
	for _, tc := range []struct {
		flags    uint32
		blocking bool
		err      error
	}{
		{flags: 0, blocking: true},
		{flags: linux.SOCK_NONBLOCK, blocking: false},
		{flags: linux.SOCK_CLOEXEC, err: unix.EINVAL},
		{flags: linux.SOCK_NONBLOCK | linux.SOCK_CLOEXEC, err: unix.EINVAL},
		{flags: 1 << 31, err: unix.EINVAL},
	} {
		blocking, err := connectBlocking(tc.flags)
		if err != tc.err || (err == nil && blocking != tc.blocking) {
			t.Errorf("connectBlocking(%#x) = %t, %v, want %t, %v", tc.flags, blocking, err, tc.blocking, tc.err)
		}
	}
}
