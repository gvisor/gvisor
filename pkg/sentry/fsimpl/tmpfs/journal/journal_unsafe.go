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

package journal

import (
	"unsafe"

	"gvisor.dev/gvisor/pkg/safecopy"
)

// safeCopyOut copies src into dst, returning an error on SIGBUS or SIGSEGV
// (for example, when writing to a sparse MAP_SHARED journal page hits ENOSPC).
//
// Preconditions: len(dst) >= len(src).
func safeCopyOut(dst, src []byte) error {
	if len(src) == 0 {
		return nil
	}
	_, err := safecopy.CopyOut(unsafe.Pointer(&dst[0]), src)
	return err
}

// safeStore64 atomically stores little-endian v to b, returning an error on
// SIGBUS or SIGSEGV.
//
// Preconditions: len(b) >= 8 and b is 8-byte aligned.
func safeStore64(b []byte, v uint64) error {
	_, err := safecopy.SwapUint64(unsafe.Pointer(&b[0]), v)
	return err
}

// safeStore32 atomically stores little-endian v to b, returning an error on
// SIGBUS or SIGSEGV.
//
// Preconditions: len(b) >= 4 and b is 4-byte aligned.
func safeStore32(b []byte, v uint32) error {
	_, err := safecopy.SwapUint32(unsafe.Pointer(&b[0]), v)
	return err
}
