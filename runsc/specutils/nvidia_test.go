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

package specutils

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseDeviceMajors(t *testing.T) {
	const procDevices = `Character devices:
  1 mem
195 nvidia
235 nvidia-caps
510 nvidia-uvm

Block devices:
  8 sd
`
	got, err := parseDeviceMajors(strings.NewReader(procDevices), []string{"nvidia-uvm", "nvidia-caps"})
	if err != nil {
		t.Fatalf("parseDeviceMajors(): %v", err)
	}
	if want := []int64{235, 510}; !slices.Equal(got, want) {
		t.Errorf("parseDeviceMajors() = %v, want %v", got, want)
	}
}

func TestNvidiaCharMajors(t *testing.T) {
	// The frontend driver's major number is always there. The others are the
	// ones that /proc/devices lists.
	procDir := t.TempDir()
	devices := "Character devices:\n195 nvidia\n195 nvidiactl\n511 nvidia-uvm\n235 nvidia-caps\n\nBlock devices:\n  8 sd\n"
	if err := os.WriteFile(filepath.Join(procDir, "devices"), []byte(devices), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := NvidiaCharMajors(procDir)
	if err != nil {
		t.Fatalf("NvidiaCharMajors(): %v", err)
	}
	if want := []int64{195, 511, 235}; !slices.Equal(got, want) {
		t.Errorf("NvidiaCharMajors() = %v, want %v", got, want)
	}

	if _, err := NvidiaCharMajors(t.TempDir()); err == nil {
		t.Error("NvidiaCharMajors() of a procfs without /proc/devices succeeded, want error")
	}
}
