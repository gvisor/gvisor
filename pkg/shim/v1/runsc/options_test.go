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

package runsc

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/google/go-cmp/cmp"
)

func TestRunscConfigAcceptsScalarValues(t *testing.T) {
	const config = `
binary_name = "runsc"

[runsc_config]
debug-log = "/var/log/runsc/"
profile = true
overlay2 = "none"
watchdog-action = "log"
num-network-channels = 4
float-flag = 1.5
directfs = false
`
	var opts Options
	if _, err := toml.Decode(config, &opts); err != nil {
		t.Fatalf("toml.Decode: %v", err)
	}
	want := Options{
		BinaryName: "runsc",
		RunscConfig: map[string]string{
			"debug-log":            "/var/log/runsc/",
			"profile":              "true",
			"overlay2":             "none",
			"watchdog-action":      "log",
			"num-network-channels": "4",
			"float-flag":           "1.5",
			"directfs":             "false",
		},
	}
	if diff := cmp.Diff(want, opts); diff != "" {
		t.Errorf("unexpected options (-want +got):\n%s", diff)
	}
}

func TestRunscConfigRejectsNonTable(t *testing.T) {
	var opts Options
	_, err := toml.Decode("runsc_config = true\n", &opts)
	if err == nil {
		t.Fatalf("toml.Decode succeeded, got runsc_config %v", opts.RunscConfig)
	}
	if !strings.Contains(err.Error(), "runsc_config must be a table") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunscConfigRejectsNonScalarValues(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{name: "array", value: `["a", "b"]`},
		{name: "table", value: `{ a = "b" }`},
		{name: "datetime", value: `2026-11-21T10:00:00Z`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := "[runsc_config]\nflag = " + tc.value + "\n"
			var opts Options
			_, err := toml.Decode(config, &opts)
			if err == nil {
				t.Fatalf("toml.Decode succeeded, got runsc_config %v", opts.RunscConfig)
			}
			if !strings.Contains(err.Error(), "flag") {
				t.Errorf("error does not name the flag: %v", err)
			}
		})
	}
}
