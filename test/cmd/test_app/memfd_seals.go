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

package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/flag"
)

// memfdSeals checks the seals and shared mappings of memfd FDs that were
// passed in from the host. It exits with a non-zero status if a check fails.
type memfdSeals struct {
	fds           string
	wantSeals     string
	writeCheckFDs string
	rdonlyFDs     string
}

// Name implements subcommands.Command.Name.
func (*memfdSeals) Name() string { return "memfd_seals" }

// Synopsis implements subcommands.Command.Synopsis.
func (*memfdSeals) Synopsis() string {
	return "checks the seals and shared mappings of memfd FDs"
}

// Usage implements subcommands.Command.Usage.
func (*memfdSeals) Usage() string {
	return "memfd_seals --fds=<fd>,... --want-seals=<mask>,... [--write-check-fds=<fd>,...] [--rdonly-fds=<fd>,...]\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *memfdSeals) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.fds, "fds", "", "comma-separated list of memfd FDs to check")
	f.StringVar(&c.wantSeals, "want-seals", "", "comma-separated list of the seals that fcntl(F_GET_SEALS) must return for each FD in --fds")
	f.StringVar(&c.writeCheckFDs, "write-check-fds", "", "comma-separated list of FDs for which write(2) from a MAP_SHARED, PROT_READ mapping must succeed")
	f.StringVar(&c.rdonlyFDs, "rdonly-fds", "", "comma-separated list of FDs that are not open for writing, for which mmap(PROT_WRITE, MAP_SHARED) must fail with EACCES")
}

// Execute implements subcommands.Command.Execute.
func (c *memfdSeals) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	fds, err := parseInts(c.fds)
	if err != nil || len(fds) == 0 {
		log.Printf("invalid --fds %q: %v", c.fds, err)
		return subcommands.ExitUsageError
	}
	want, err := parseInts(c.wantSeals)
	if err != nil || len(want) != len(fds) {
		log.Printf("--want-seals %q must have one mask for each of --fds %q: %v", c.wantSeals, c.fds, err)
		return subcommands.ExitUsageError
	}
	writeCheck, err := parseInts(c.writeCheckFDs)
	if err != nil {
		log.Printf("invalid --write-check-fds %q: %v", c.writeCheckFDs, err)
		return subcommands.ExitUsageError
	}
	rdonly, err := parseInts(c.rdonlyFDs)
	if err != nil {
		log.Printf("invalid --rdonly-fds %q: %v", c.rdonlyFDs, err)
		return subcommands.ExitUsageError
	}

	status := subcommands.ExitSuccess
	fail := func(format string, a ...any) {
		log.Printf(format, a...)
		status = subcommands.ExitFailure
	}
	for i, fd := range fds {
		got, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
		if err != nil {
			fail("fd %d: fcntl(F_GET_SEALS) failed: %v", fd, err)
		} else if got != want[i] {
			fail("fd %d: fcntl(F_GET_SEALS) = %#x, want %#x", fd, got, want[i])
		}
	}
	for _, fd := range writeCheck {
		if err := writeFromSharedMapping(fd); err != nil {
			fail("fd %d: %v", fd, err)
		}
	}
	for _, fd := range rdonly {
		mem, err := unix.Mmap(fd, 0, 1, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err == nil {
			unix.Munmap(mem)
			fail("fd %d: mmap(PROT_WRITE, MAP_SHARED) of a read-only FD succeeded, want EACCES", fd)
		} else if err != unix.EACCES {
			fail("fd %d: mmap(PROT_WRITE, MAP_SHARED) of a read-only FD failed with %v, want EACCES", fd, err)
		}
	}
	return status
}

// parseInts parses a comma-separated list of integers in any base accepted by
// strconv.ParseInt with base 0.
func parseInts(list string) ([]int, error) {
	if list == "" {
		return nil, nil
	}
	var out []int
	for _, s := range strings.Split(list, ",") {
		v, err := strconv.ParseInt(s, 0, 32)
		if err != nil {
			return nil, err
		}
		out = append(out, int(v))
	}
	return out, nil
}

// writeFromSharedMapping maps fd with MAP_SHARED and PROT_READ, and writes the
// first byte of the mapping to a pipe.
func writeFromSharedMapping(fd int) error {
	mem, err := unix.Mmap(fd, 0, 1, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("mmap(PROT_READ, MAP_SHARED) failed: %w", err)
	}
	defer unix.Munmap(mem)
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		return fmt.Errorf("pipe failed: %w", err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])
	if n, err := unix.Write(p[1], mem[:1]); err != nil {
		return fmt.Errorf("write from the shared mapping failed: %w", err)
	} else if n != 1 {
		return fmt.Errorf("write from the shared mapping wrote %d bytes, want 1", n)
	}
	return nil
}
