// Copyright 2020 The gVisor Authors.
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

// TaskWorker is a deferred task.
//
// This must be savable.
type TaskWorker interface {
	// TaskWork will be executed prior to returning to user space, or once
	// when the task exits. Note that TaskWork may call RegisterWork again, but
	// this will not be executed until the next return to user space, unlike in
	// Linux. This effectively allows registration of indefinite user return
	// hooks, but not by default.
	//
	// When run on exit, TaskWork runs after the task has released its
	// MemoryManager and FD table, as in Linux's kernel/exit.c:do_exit(), so it
	// must not access the task's memory. Work registered from then on, by
	// TaskWork or otherwise, is refused by RegisterWork and never runs.
	TaskWork(t *Task)
}

// RegisterWork registers work to be performed prior to t's next return to
// user space, or when t exits. It returns false, without registering work, if
// t has already run its task work on exit, as Linux's
// kernel/task_work.c:task_work_add() returns -ESRCH after exit_task_work().
// Callers whose work only matters before t returns to user space may ignore
// the result. See TaskWorker.TaskWork for semantics regarding registration.
//
// +checklocksexclude:t.taskWorkMu
func (t *Task) RegisterWork(work TaskWorker) bool {
	t.taskWorkMu.Lock()
	defer t.taskWorkMu.Unlock()
	if t.taskWorkExited {
		return false
	}
	t.taskWorkCount.Add(1)
	t.taskWork = append(t.taskWork, work)
	return true
}

// runExitTaskWork runs t's pending task work, which would otherwise never
// run, and makes RegisterWork fail from then on. It is Linux's
// kernel/exit.c:do_exit() calling exit_task_work().
//
// +checklocksexclude:t.taskWorkMu
func (t *Task) runExitTaskWork() {
	t.taskWorkMu.Lock()
	queue := t.taskWork
	t.taskWork = nil
	t.taskWorkCount.Store(0)
	t.taskWorkExited = true
	t.taskWorkMu.Unlock()
	for _, work := range queue {
		work.TaskWork(t)
	}
}
