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

package controlapi

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Tests that ProcessData.Table() prints with the correct format.
func TestProcessListTable(t *testing.T) {
	testCases := []struct {
		pl       []*Process
		expected string
	}{
		{
			pl:       []*Process{},
			expected: "UID       PID       PPID      PGID      C         TTY       STIME     TIME      CMD",
		},
		{
			pl: []*Process{
				{
					UID:   0,
					PID:   0,
					PPID:  0,
					PGID:  0,
					C:     0,
					TTY:   "?",
					STime: "0",
					Time:  "0",
					Cmd:   "zero",
				},
				{
					UID:   1,
					PID:   1,
					PPID:  1,
					PGID:  1,
					C:     1,
					TTY:   "pts/4",
					STime: "1",
					Time:  "1",
					Cmd:   "one",
				},
			},
			expected: `UID       PID       PPID      PGID      C         TTY       STIME     TIME      CMD
0         0         0         0         0         ?         0         0         zero
1         1         1         1         1         pts/4     1         1         one`,
		},
	}

	for _, tc := range testCases {
		output := ProcessListToTable(tc.pl)

		if tc.expected != output {
			t.Errorf("PrintTable(%v): got:\n%s\nwant:\n%s", tc.pl, output, tc.expected)
		}
	}
}

func TestProcessListJSON(t *testing.T) {
	testCases := []struct {
		pl       []*Process
		expected string
	}{
		{
			pl:       []*Process{},
			expected: "[]",
		},
		{
			pl: []*Process{
				{
					UID:   0,
					PID:   0,
					PPID:  0,
					C:     0,
					STime: "0",
					Time:  "0",
					Cmd:   "zero",
				},
				{
					UID:   1,
					PID:   1,
					PPID:  1,
					C:     1,
					STime: "1",
					Time:  "1",
					Cmd:   "one",
				},
			},
			expected: "[0,1]",
		},
	}

	for _, tc := range testCases {
		output, err := PrintPIDsJSON(tc.pl)
		if err != nil {
			t.Errorf("failed to generate JSON: %v", err)
		}

		if tc.expected != output {
			t.Errorf("PrintJSON(%v): got:\n%s\nwant:\n%s", tc.pl, output, tc.expected)
		}
	}
}

func TestProcessListToJSON(t *testing.T) {
	pl := []*Process{
		{
			UID:         0,
			PID:         1,
			PPID:        0,
			PGID:        1,
			Threads:     []int32{1},
			C:           0,
			TTY:         "?",
			STime:       "0",
			Time:        "0",
			Cmd:         "init",
			OOMScoreAdj: 0,
		},
		{
			UID:         1000,
			PID:         2,
			PPID:        1,
			PGID:        2,
			Threads:     []int32{2, 3},
			C:           50,
			TTY:         "pts/0",
			STime:       "1",
			Time:        "1",
			Cmd:         "hog",
			OOMScoreAdj: 1000,
		},
	}

	out, err := ProcessListToJSON(pl)
	if err != nil {
		t.Fatalf("ProcessListToJSON(%v) failed: %v", pl, err)
	}

	var got []map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal(%q) failed: %v", out, err)
	}
	want := []map[string]any{
		{
			"uid":           float64(0),
			"pid":           float64(1),
			"ppid":          float64(0),
			"pgid":          float64(1),
			"threads":       []any{float64(1)},
			"c":             float64(0),
			"tty":           "?",
			"stime":         "0",
			"time":          "0",
			"cmd":           "init",
			"oom_score_adj": float64(0),
		},
		{
			"uid":           float64(1000),
			"pid":           float64(2),
			"ppid":          float64(1),
			"pgid":          float64(2),
			"threads":       []any{float64(2), float64(3)},
			"c":             float64(50),
			"tty":           "pts/0",
			"stime":         "1",
			"time":          "1",
			"cmd":           "hog",
			"oom_score_adj": float64(1000),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ProcessListToJSON(%v) mismatch (-want +got):\n%s", pl, diff)
	}
}

// Tests that ExecArgs are formatted without their environment.
func TestExecArgsFormatOmitsEnv(t *testing.T) {
	args := &ExecArgs{
		Filename: "/bin/sh",
		Argv:     []string{"sh", "-c", "true"},
		Envv:     []string{"SECRET=hunter2"},
	}
	want := "/bin/sh -c true"
	if got := fmt.Sprintf("%+v", args); got != want {
		t.Errorf("%%+v: got %q, want %q", got, want)
	}
}
