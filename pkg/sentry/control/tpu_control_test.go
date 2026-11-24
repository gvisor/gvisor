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

package control

import (
	"errors"
	"testing"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

func TestRunTPURequests(t *testing.T) {
	first := &tpuTaskInfo{}
	second := &tpuTaskInfo{}
	third := &tpuTaskInfo{}
	firstErr := errors.New("first request failed")
	thirdErr := errors.New("third request failed")

	for _, tc := range []struct {
		name       string
		tasks      []*tpuTaskInfo
		failures   map[*tpuTaskInfo]error
		want       []*tpuTaskInfo
		wantErrors []error
	}{
		{name: "no tasks"},
		{
			name:  "mixed response",
			tasks: []*tpuTaskInfo{first, second, third},
			failures: map[*tpuTaskInfo]error{
				second: firstErr,
			},
			want:       []*tpuTaskInfo{first, third},
			wantErrors: []error{firstErr},
		},
		{
			name:  "all failed",
			tasks: []*tpuTaskInfo{first, third},
			failures: map[*tpuTaskInfo]error{
				first: firstErr,
				third: thirdErr,
			},
			wantErrors: []error{firstErr, thirdErr},
		},
		{
			name:  "all acknowledged",
			tasks: []*tpuTaskInfo{first, second},
			want:  []*tpuTaskInfo{first, second},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acknowledged, err := runTPURequests(tc.tasks, func(info *tpuTaskInfo) error {
				return tc.failures[info]
			})
			if len(acknowledged) != len(tc.want) {
				t.Fatalf("acknowledged = %v, want %v", acknowledged, tc.want)
			}
			for i, info := range acknowledged {
				if info != tc.want[i] {
					t.Errorf("acknowledged[%d] = %p, want %p", i, info, tc.want[i])
				}
			}
			if (err == nil) != (len(tc.wantErrors) == 0) {
				t.Fatalf("error = %v, want errors %v", err, tc.wantErrors)
			}
			for _, want := range tc.wantErrors {
				if !errors.Is(err, want) {
					t.Errorf("error = %v, missing %v", err, want)
				}
			}
		})
	}
}

func TestRunTPURequestsWaitsForAll(t *testing.T) {
	first := &tpuTaskInfo{}
	second := &tpuTaskInfo{}
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	requestErr := errors.New("request failed")
	go func() {
		defer close(done)
		acknowledged, err := runTPURequests([]*tpuTaskInfo{first, second}, func(info *tpuTaskInfo) error {
			if info == first {
				close(started)
				<-release
				return nil
			}
			return requestErr
		})
		if len(acknowledged) != 1 || acknowledged[0] != first || !errors.Is(err, requestErr) {
			t.Errorf("runTPURequests() = (%v, %v), want ([first], %v)", acknowledged, err, requestErr)
		}
	}()
	<-started
	select {
	case <-done:
		t.Fatal("runTPURequests returned before the first request completed")
	default:
	}
	close(release)
	<-done
}

func TestRecordTPUCheckpointResult(t *testing.T) {
	first := &kernel.Task{}
	second := &kernel.Task{}
	requestErr := errors.New("checkpoint failed")
	for _, tc := range []struct {
		name          string
		acknowledged  []*tpuTaskInfo
		err           error
		wantPrepared  bool
		wantSavedTask []*kernel.Task
	}{
		{name: "none acknowledged", err: requestErr},
		{
			name:          "partial checkpoint",
			acknowledged:  []*tpuTaskInfo{{task: first}},
			err:           requestErr,
			wantPrepared:  true,
			wantSavedTask: []*kernel.Task{first},
		},
		{
			name:          "complete checkpoint",
			acknowledged:  []*tpuTaskInfo{{task: first}, {task: second}},
			wantPrepared:  true,
			wantSavedTask: []*kernel.Task{first, second},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &kernel.Kernel{}
			prepared, err := recordTPUCheckpointResult(k, tc.acknowledged, tc.err)
			if prepared != tc.wantPrepared || !errors.Is(err, tc.err) {
				t.Errorf("recordTPUCheckpointResult() = (%t, %v), want (%t, %v)", prepared, err, tc.wantPrepared, tc.err)
			}
			got := k.PopCheckpointState(tpuTasksStateKey)
			if len(tc.wantSavedTask) == 0 {
				if got != nil {
					t.Errorf("saved tasks = %v, want none", got)
				}
				return
			}
			tasks, ok := got.([]*kernel.Task)
			if !ok || len(tasks) != len(tc.wantSavedTask) {
				t.Fatalf("saved tasks = %v, want %v", got, tc.wantSavedTask)
			}
			for i, task := range tasks {
				if task != tc.wantSavedTask[i] {
					t.Errorf("saved task[%d] = %p, want %p", i, task, tc.wantSavedTask[i])
				}
			}
		})
	}
}

func TestTPUPreparationWhilePaused(t *testing.T) {
	k, err := testutil.Boot()
	if err != nil {
		t.Fatal(err)
	}
	defer k.Timekeeper().Destroy()
	defer k.GlobalInit().Release(k.SupervisorContext())
	k.Pause()
	defer k.Unpause()
	// An unusable task ensures that rejection precedes FD lookup or dispatch.
	tasks := []*tpuTaskInfo{{}}
	released := false
	prepared, err := prepareTPUTasks(k, tasks, func(prepare func() (bool, error)) (bool, error) {
		defer func() { released = true }()
		return prepare()
	})
	if prepared || !errors.Is(err, linuxerr.EBUSY) || !released {
		t.Fatalf("prepareTPUTasks() = (%t, %v), released=%t", prepared, err, released)
	}
	if got := k.PopCheckpointState(tpuTasksStateKey); got != nil {
		t.Errorf("checkpoint state = %v, want nil", got)
	}
}

func TestPausedWithoutTPUTasks(t *testing.T) {
	k, err := testutil.Boot()
	if err != nil {
		t.Fatal(err)
	}
	defer k.Timekeeper().Destroy()
	defer k.GlobalInit().Release(k.SupervisorContext())
	k.Pause()
	defer k.Unpause()
	prepared, err := preSaveTPU(k, func(func() (bool, error)) (bool, error) {
		t.Fatal("pause coordination called without TPU tasks")
		return false, linuxerr.EBUSY
	})
	if prepared || err != nil {
		t.Fatalf("preSaveTPU() = (%t, %v), want (false, nil)", prepared, err)
	}
}
