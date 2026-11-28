// Copyright 2022 The gVisor Authors.
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

package iouringfs

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
)

func TestRoundUpPowerOfTwo(t *testing.T) {
	tests := []struct {
		input  uint32
		output uint32
	}{
		{0, 1},
		{1, 1},
		{2, 2},
		{3, 4},
		{4, 4},
		{5, 8},
		{6, 8},
		{7, 8},
		{8, 8},
		{1 << 31, 2147483648},
		{1<<31 - 1, 2147483648},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			s, ok := roundUpPowerOfTwo(tt.input)
			if s != tt.output {
				t.Errorf("Expected %d, got %d", tt.output, s)
			}
			if !ok {
				t.Errorf("Expected no error, got %t. Input %d, expected %d", ok, tt.input, tt.output)
			}
		})
	}
}

func TestRoundUpPowerOfTwoOverflow(t *testing.T) {
	tests := []struct {
		input  uint32
		output uint32
	}{
		{1<<31 + 1, 0},
		{math.MaxUint32, 0},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			s, ok := roundUpPowerOfTwo(tt.input)
			if s != tt.output || ok {
				t.Errorf("Expected value %d and overflow, got %d and %t", tt.output, s, ok)
			}
		})
	}
}

func TestAtomicUint32AtOffset(t *testing.T) {
	buf := make([]byte, 4096)
	a := atomicUint32AtOffset(buf, 512)

	want := uint32(123456)
	hostarch.ByteOrder.PutUint32(buf[512:], want)
	if a.Load() != want {
		t.Errorf("Expected %d, got %d", want, a.Load())
	}

	// Update value through slice.
	want = 654321
	hostarch.ByteOrder.PutUint32(buf[512:], want)
	if a.Load() != want {
		t.Errorf("Expected %d, got %d", want, a.Load())
	}

	// Update value through pointer.
	want = 789012
	a.Store(want)
	if got := hostarch.ByteOrder.Uint32(buf[512:]); got != want {
		t.Errorf("Expected %d, got %d", want, got)
	}
}

func TestUint32PtrAtOffsetEndOfSlice(t *testing.T) {
	const sizeOfUint32 int = 4
	buf := make([]byte, 4096)

	// Cast successful at end of slice
	_ = atomicUint32AtOffset(buf, 4096-sizeOfUint32)
}

func TestUint32PtrAtOffsetInvalidOffsets(t *testing.T) {
	tests := []struct {
		offset      int
		panicSubstr string
	}{
		{1, "unaligned"},
		{511, "unaligned"},
		{-1, "overrun"},
		{4093, "overrun"},
		{4094, "overrun"},
		{4095, "overrun"},
		{4096, "overrun"},
		{5000, "overrun"},
	}
	const sizeOfUint32 int = 4

	for i, tt := range tests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			buf := make([]byte, 4096)

			defer func() {
				if r := recover(); r != nil {
					if strings.Contains(fmt.Sprintf("%s", r), tt.panicSubstr) {
						t.Logf("Got expected panic: %v", r)
						return
					}

					t.Errorf("Unexpected panic: %v", r)
				}
			}()

			_ = atomicUint32AtOffset(buf, tt.offset)

			t.Errorf("Didn't get expected panic")
		})
	}
}

func TestCompletionResult(t *testing.T) {
	tests := []struct {
		name string
		n    int32
		err  error
		want int32
	}{
		{name: "success", n: 4096, want: 4096},
		{name: "empty", want: 0},
		{name: "eof", err: io.EOF, want: 0},
		{name: "short_read", n: 128, err: io.EOF, want: 128},
		{name: "restart_sys", err: linuxerr.ERESTARTSYS, want: -4},
		{name: "restart_nointr", err: linuxerr.ERESTARTNOINTR, want: -4},
		{name: "restart_nohand", err: linuxerr.ERESTARTNOHAND, want: -4},
		{name: "restart_block", err: linuxerr.ERESTART_RESTARTBLOCK, want: -4},
		{name: "interrupted", err: linuxerr.EINTR, want: -4},
		{name: "io_error", err: linuxerr.EIO, want: -5},
		{name: "bad_fd", err: linuxerr.EBADF, want: -9},
		{name: "bad_address", err: linuxerr.EFAULT, want: -14},
		{name: "would_block", err: linuxerr.EAGAIN, want: -11},
		{name: "partial_then_fault", n: 6, err: linuxerr.EFAULT, want: 6},
		{name: "partial_then_restart", n: 6, err: linuxerr.ERESTARTSYS, want: 6},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := completionResult(test.n, test.err); got != test.want {
				t.Errorf("completionResult(%d, %v) = %d, want %d", test.n, test.err, got, test.want)
			}
			if test.err == nil || test.err == io.EOF {
				return
			}
			// File operations may wrap errno values. Normalize after extracting
			// the errno so wrapped restart errors cannot escape into a CQE.
			wrapped := &os.PathError{
				Op:   "read",
				Path: "file",
				Err:  &os.SyscallError{Syscall: "pread", Err: test.err},
			}
			if got := completionResult(test.n, wrapped); got != test.want {
				t.Errorf("completionResult(%d, %v) = %d, want %d", test.n, wrapped, got, test.want)
			}
		})
	}
}
