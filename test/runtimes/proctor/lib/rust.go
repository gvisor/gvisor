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

package lib

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Locations of the Rust standard library test binaries. The binaries in
// rustLibtestDir use the libtest harness. The binaries in rustStandaloneDir
// do not use a harness, and each binary is one test.
const (
	rustLibtestDir    = "/root/rust-tests/libtest"
	rustStandaloneDir = "/root/rust-tests/standalone"
)

// rustRunner implements TestRunner for Rust.
//
// The name of a libtest test is "<binary>:<test>", for example
// "std:fs::tests::copy_file_ok". The name of a standalone test is the name of
// its binary.
type rustRunner struct{}

var _ TestRunner = rustRunner{}

// ListTests implements TestRunner.ListTests.
//
// Tests marked #[ignore] are not listed, because libtest does not run them
// when they are selected by name.
func (rustRunner) ListTests() ([]string, error) {
	bins, err := os.ReadDir(rustLibtestDir)
	if err != nil {
		return nil, err
	}
	var tests []string
	for _, bin := range bins {
		path := filepath.Join(rustLibtestDir, bin.Name())
		all, err := rustListTests(path)
		if err != nil {
			return nil, err
		}
		ignored, err := rustListTests(path, "--ignored")
		if err != nil {
			return nil, err
		}
		for name := range all {
			if _, ok := ignored[name]; !ok {
				tests = append(tests, bin.Name()+":"+name)
			}
		}
	}

	standalone, err := os.ReadDir(rustStandaloneDir)
	if err != nil {
		return nil, err
	}
	for _, bin := range standalone {
		tests = append(tests, bin.Name())
	}
	return tests, nil
}

// rustListTests returns the names of the tests in the libtest binary at path
// that the libtest arguments args select.
func rustListTests(path string, args ...string) (map[string]struct{}, error) {
	cmd := exec.Command(path, append([]string{"--list", "--format=terse"}, args...)...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list tests in %q: %v", path, err)
	}
	names := make(map[string]struct{})
	for _, line := range strings.Split(string(out), "\n") {
		// When a benchmark is selected by name without "--bench", libtest runs
		// it once as a test.
		name, ok := strings.CutSuffix(line, ": test")
		if !ok {
			name, ok = strings.CutSuffix(line, ": benchmark")
		}
		if ok {
			names[name] = struct{}{}
		}
	}
	return names, nil
}

// TestCmds implements TestRunner.TestCmds.
func (rustRunner) TestCmds(tests []string) []*exec.Cmd {
	var (
		cmds  []*exec.Cmd
		bins  []string
		names = make(map[string][]string)
	)
	for _, test := range tests {
		bin, name, ok := strings.Cut(test, ":")
		if !ok {
			cmds = append(cmds, exec.Command(filepath.Join(rustStandaloneDir, test)))
			continue
		}
		if _, ok := names[bin]; !ok {
			bins = append(bins, bin)
		}
		names[bin] = append(names[bin], name)
	}
	for _, bin := range bins {
		args := append([]string{"--exact"}, names[bin]...)
		cmds = append(cmds, exec.Command(filepath.Join(rustLibtestDir, bin), args...))
	}
	return cmds
}
