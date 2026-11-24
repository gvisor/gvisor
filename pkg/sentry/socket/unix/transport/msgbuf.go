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

package transport

import (
	"math/bits"

	"gvisor.dev/gvisor/pkg/sync"
)

// Message payloads are pooled by power-of-two capacity so that a busy socket
// does not allocate and zero a buffer per message.
const (
	minPooledShift = 12 // 4 KiB
	maxPooledShift = 22 // maxBufferSize
)

var msgBufPools [maxPooledShift - minPooledShift + 1]sync.Pool

// msgBufPoolIndex returns the pool for buffers of the given capacity. Small
// buffers are not pooled, which bounds a queue to twice its accounted bytes.
func msgBufPoolIndex(capacity int) (int, bool) {
	if capacity < 1<<minPooledShift {
		return 0, false
	}
	shift := bits.Len(uint(capacity - 1))
	if shift > maxPooledShift {
		return 0, false
	}
	return shift - minPooledShift, true
}

// getMsgBuf returns a slice of length n whose contents are unspecified.
func getMsgBuf(n int64) []byte {
	i, ok := msgBufPoolIndex(int(n))
	if !ok {
		return make([]byte, n)
	}
	if p, _ := msgBufPools[i].Get().(*[]byte); p != nil {
		return (*p)[:n]
	}
	return make([]byte, n, 1<<(i+minPooledShift))
}

// putMsgBuf returns b to its pool. The caller must hold the only reference to
// b's backing array.
func putMsgBuf(b []byte) {
	c := cap(b)
	i, ok := msgBufPoolIndex(c)
	if !ok || c != 1<<(i+minPooledShift) {
		return
	}
	b = b[:0]
	msgBufPools[i].Put(&b)
}
