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

// Binary fuse_probe creates a file, writes to it, and reports the errno
// returned by fsync(2) and close(2). It is used by //test/root to check that
// deferred write errors from a FUSE bind mount are not dropped by the sandbox.
//
// Output is a single line: "write=<errno> fsync=<errno> close=<errno>", where
// <errno> is the symbolic errno name or "OK".
package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func name(err error) string {
	if err == nil {
		return "OK"
	}
	if errno, ok := err.(unix.Errno); ok {
		return unix.ErrnoName(errno)
	}
	return err.Error()
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <path>\n", os.Args[0])
		os.Exit(2)
	}
	path := os.Args[1]

	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open(%q): %v\n", path, err)
		os.Exit(1)
	}

	buf := make([]byte, 64<<10)
	for i := range buf {
		buf[i] = byte(i)
	}
	_, writeErr := unix.Write(fd, buf)
	fsyncErr := unix.Fsync(fd)
	closeErr := unix.Close(fd)

	fmt.Printf("write=%s fsync=%s close=%s\n", name(writeErr), name(fsyncErr), name(closeErr))
}
