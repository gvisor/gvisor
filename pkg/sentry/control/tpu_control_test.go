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
	"runtime"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
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

// newTPUDiscoveryTasks creates one thread group with the given task names and a
// marker FD in its leader. The marker substitutes for a VFIO FD in discovery.
func newTPUDiscoveryTasks(t testing.TB, names []string) (*kernel.Kernel, []*kernel.Task, *vfs.FileDescription) {
	t.Helper()
	k, err := testutil.Boot()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Timekeeper().Destroy)
	ctx := k.SupervisorContext()
	t.Cleanup(func() { k.GlobalInit().Release(ctx) })
	mntns, err := k.VFS().NewMountNamespace(ctx, auth.CredentialsFromContext(ctx), "", "tmpfs", &vfs.MountOptions{}, k)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mntns.DecRef(ctx) })
	root := mntns.Root(ctx)
	t.Cleanup(func() { root.DecRef(ctx) })
	var tasks []*kernel.Task
	for _, name := range names {
		task, err := testutil.CreateTask(ctx, name, k.GlobalInit(), mntns, root, root)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			task.MemoryManager().DecUsers(ctx)
			task.FDTable().DecRef(ctx)
		})
		tasks = append(tasks, task)
	}
	vd := k.VFS().NewAnonVirtualDentry("tpu-discovery-marker")
	defer vd.DecRef(ctx)
	file := &vfs.FileDescription{}
	if err := file.Init(&mockFDImpl{}, linux.O_RDONLY, auth.CredentialsFromContext(ctx), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.DecRef(ctx) })
	if _, err := tasks[0].NewFDFrom(0, file, kernel.FDFlags{}); err != nil {
		t.Fatal(err)
	}
	return k, tasks, file
}

func TestFindTPUTasks(t *testing.T) {
	k, tasks, marker := newTPUDiscoveryTasks(t, []string{"libtpu00010002", "worker", "libtpu123", "libtpuXXXX0002", "libtpu00030004"})
	for _, hasDevice := range []bool{false, true} {
		infos := findTPUTasksWithDeviceCheck(k, func(file *vfs.FileDescription) bool {
			return hasDevice && file == marker
		})
		if !hasDevice {
			if len(infos) != 0 {
				t.Fatalf("discovery without a device returned %d tasks", len(infos))
			}
			continue
		}
		if len(infos) != 2 {
			t.Fatalf("discovery returned %d tasks, want 2", len(infos))
		}
		for i, index := range []int{0, 4} {
			if got := infos[i]; got.task != tasks[index] || got.reqWriteFd != int32(2*i+1) || got.rspReadFd != int32(2*i+2) {
				t.Errorf("discovery result %d = %+v, want task %p with FDs %d and %d", i, got, tasks[index], 2*i+1, 2*i+2)
			}
		}
	}
}

func TestFindTPUTasksWithPendingWriter(t *testing.T) {
	for _, name := range []string{"libtpu00010002", "worker", "libtpu123"} {
		t.Run(name, func(t *testing.T) {
			k, _, marker := newTPUDiscoveryTasks(t, []string{name})
			entered := make(chan struct{})
			release := make(chan struct{})
			done := make(chan []*tpuTaskInfo, 1)
			writerDone := make(chan struct{})
			go func() {
				done <- findTPUTasksWithDeviceCheck(k, func(file *vfs.FileDescription) bool {
					close(entered)
					<-release
					return file == marker
				})
			}()
			<-entered
			go func() {
				_ = k.TaskSet().IsExiting()
				close(writerDone)
			}()
			// Wait for the writer to reach the semaphore, after announcing
			// itself to new readers. A start signal alone does not establish
			// that the write lock is pending.
			deadline := time.Now().Add(10 * time.Second)
			buf := make([]byte, 1<<20)
			for {
				stacks := string(buf[:runtime.Stack(buf, true)])
				pending := false
				for _, stack := range strings.Split(stacks, "\n\n") {
					if strings.Contains(stack, "[semacquire]") && strings.Contains(stack, "(*TaskSet).IsExiting") && strings.Contains(stack, "(*CrossGoroutineRWMutex).Lock") {
						pending = true
						break
					}
				}
				if pending {
					break
				}
				if time.Now().After(deadline) {
					close(release)
					t.Fatalf("TaskSet writer did not block:\n%s", stacks)
				}
				runtime.Gosched()
			}
			close(release)
			select {
			case infos := <-done:
				want := 0
				if name == "libtpu00010002" {
					want = 1
				}
				if len(infos) != want {
					t.Errorf("discovery returned %d tasks, want %d", len(infos), want)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("discovery blocked with a pending TaskSet writer")
			}
			select {
			case <-writerDone:
			case <-time.After(10 * time.Second):
				t.Fatal("TaskSet writer did not finish after discovery")
			}
		})
	}
}
