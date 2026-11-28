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

package kernel

import (
	"testing"
)

// countingWork is a TaskWorker that counts its runs and optionally calls
// register from TaskWork.
type countingWork struct {
	runs     int
	register func(t *Task)
}

// TaskWork implements TaskWorker.TaskWork.
func (w *countingWork) TaskWork(t *Task) {
	w.runs++
	if w.register != nil {
		w.register(t)
	}
}

// TestExitTaskWorkRunsPendingWork checks that work pending when a task exits
// runs exactly once, as Linux's do_exit() runs it in exit_task_work().
func TestExitTaskWorkRunsPendingWork(t *testing.T) {
	task := &Task{}
	first, second := &countingWork{}, &countingWork{}
	if !task.RegisterWork(first) || !task.RegisterWork(second) {
		t.Fatal("RegisterWork failed before the task exited")
	}

	task.runExitTaskWork()
	if first.runs != 1 || second.runs != 1 {
		t.Errorf("task work runs = %d, %d; want 1, 1", first.runs, second.runs)
	}
	if got := task.taskWorkCount.Load(); got != 0 {
		t.Errorf("task work count after exit = %d, want 0", got)
	}

	task.runExitTaskWork()
	if first.runs != 1 || second.runs != 1 {
		t.Errorf("task work runs after a second exit pass = %d, %d; want 1, 1", first.runs, second.runs)
	}
}

// TestExitTaskWorkRejectsLaterWork checks that RegisterWork fails once the
// task has run its exit task work, as Linux's task_work_add() returns ESRCH
// after exit_task_work().
func TestExitTaskWorkRejectsLaterWork(t *testing.T) {
	task := &Task{}
	task.runExitTaskWork()

	work := &countingWork{}
	if task.RegisterWork(work) {
		t.Error("RegisterWork succeeded after the task exited")
	}
	if got := task.taskWorkCount.Load(); got != 0 {
		t.Errorf("task work count = %d, want 0", got)
	}
}

// TestExitTaskWorkRefusesWorkDuringExit checks that RegisterWork refuses work
// that TaskWork registers during the exit pass, which therefore never runs.
func TestExitTaskWorkRefusesWorkDuringExit(t *testing.T) {
	task := &Task{}
	later := &countingWork{}
	registered := true
	task.RegisterWork(&countingWork{register: func(tk *Task) {
		registered = tk.RegisterWork(later)
	}})

	task.runExitTaskWork()
	if registered {
		t.Error("RegisterWork succeeded during the exit pass")
	}
	if later.runs != 0 {
		t.Errorf("work registered during the exit pass ran %d times, want 0", later.runs)
	}
	if got := task.taskWorkCount.Load(); got != 0 {
		t.Errorf("task work count = %d, want 0", got)
	}
}
