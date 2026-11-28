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

//go:build linux

package runsccmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	runc "github.com/containerd/go-runc"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// TestRunscUpdateCLI verifies Update runs the OCI update flow: JSON resources on
// stdin and "update --resources - <id>" in argv (same contract as go-runc).
func TestRunscUpdateCLI(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	argsLog := filepath.Join(dir, "args.txt")
	stdinLog := filepath.Join(dir, "stdin.txt")
	script := filepath.Join(dir, "fake-runsc")
	scriptBody := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >%q
cat >%q
exit 0
`, argsLog, stdinLog)
	if err := os.WriteFile(script, []byte(scriptBody), 0o755); err != nil {
		t.Fatal(err)
	}

	limit := int64(4096)
	wantRes := &specs.LinuxResources{
		Memory: &specs.LinuxMemory{Limit: &limit},
	}

	r := &Runsc{
		Command: script,
		Root:    filepath.Join(dir, "root"),
	}
	if err := r.Update(ctx, "cid-1", wantRes); err != nil {
		t.Fatalf("Update: %v", err)
	}

	rawArgs, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Fields(string(rawArgs))
	var joined strings.Builder
	for _, a := range args {
		joined.WriteString(a)
		joined.WriteByte(' ')
	}
	s := joined.String()
	// go-runc may pass "--resources -"; we use "--resources=-" (same stdin contract).
	if !strings.Contains(s, "update ") || !strings.Contains(s, "--resources") || !strings.Contains(s, "cid-1") {
		t.Fatalf("argv missing expected update flags: %q", string(rawArgs))
	}

	rawStdin, err := os.ReadFile(stdinLog)
	if err != nil {
		t.Fatal(err)
	}
	var got specs.LinuxResources
	if err := json.Unmarshal(rawStdin, &got); err != nil {
		t.Fatalf("stdin JSON: %v", err)
	}
	if got.Memory == nil || got.Memory.Limit == nil || *got.Memory.Limit != limit {
		t.Fatalf("stdin resources: got %+v, want memory limit %d", got.Memory, limit)
	}
}

// TestCmdOutputDoesNotAliasPooledBuffer verifies that cmdOutput copies its
// output before returning. Its buffers come from a sync.Pool and are released
// on return, so an alias would be overwritten by the next runsc invocation
// while the caller is still unmarshaling it.
func TestCmdOutputDoesNotAliasPooledBuffer(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-runsc")
	const want = "original output"
	scriptBody := fmt.Sprintf("#!/bin/sh\nprintf '%%s' %q\n", want)
	if err := os.WriteFile(script, []byte(scriptBody), 0o755); err != nil {
		t.Fatal(err)
	}

	r := &Runsc{Command: script, Root: filepath.Join(dir, "root")}
	out, _, err := cmdOutput(r.command(t.Context(), "state", "cid-1"), true)
	if err != nil {
		t.Fatalf("cmdOutput: %v", err)
	}
	if string(out) != want {
		t.Fatalf("cmdOutput() = %q, want %q", out, want)
	}

	// Scribble over the pooled buffers, as a subsequent command would.
	for i := 0; i < 8; i++ {
		b := getBuf()
		b.WriteString(strings.Repeat("X", len(want)*4))
		putBuf(b)
	}

	if string(out) != want {
		t.Errorf("cmdOutput() result was corrupted to %q; it aliases a pooled buffer", out)
	}
}

// TestCmdOutputSeparateStderr verifies the non-combined path also copies.
func TestCmdOutputSeparateStderr(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-runsc")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'out'\nprintf 'err' >&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	r := &Runsc{Command: script, Root: filepath.Join(dir, "root")}
	stdout, stderr, err := cmdOutput(r.command(t.Context(), "state", "cid-1"), false)
	if err != nil {
		t.Fatalf("cmdOutput: %v", err)
	}

	for i := 0; i < 8; i++ {
		b := getBuf()
		b.WriteString(strings.Repeat("X", 64))
		putBuf(b)
	}

	if string(stdout) != "out" {
		t.Errorf("stdout = %q, want %q", stdout, "out")
	}
	if string(stderr) != "err" {
		t.Errorf("stderr = %q, want %q", stderr, "err")
	}
}

// TestCommandWaitDelayUnblocksWait covers a runsc that dies while a child still
// holds the pipe cmdOutput gave it. Without WaitDelay, Wait stays blocked on
// that fd and the caller keeps the container lock.
func TestCommandWaitDelayUnblocksWait(t *testing.T) {
	old := waitDelay
	waitDelay = 200 * time.Millisecond
	t.Cleanup(func() { waitDelay = old })

	fake := filepath.Join(t.TempDir(), "fake-runsc")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nsleep 60 &\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("failed to write fake runsc: %v", err)
	}

	r := &Runsc{Command: fake}
	start := time.Now()
	if _, _, err := cmdOutput(r.command(context.Background()), false); err == nil {
		t.Fatal("cmdOutput reported success for a command whose pipes never closed")
	}
	// Below waitDelay means the command failed at startup and never exercised
	// the delay. Above the child lifetime means Wait sat on the inherited fd.
	elapsed := time.Since(start)
	if elapsed < 200*time.Millisecond || elapsed > 30*time.Second {
		t.Fatalf("cmdOutput returned after %v, want between waitDelay and the child lifetime", elapsed)
	}
}

// pollingMonitor is a ProcessMonitor that polls for process exit instead of
// blocking a thread in wait4(2).
type pollingMonitor struct{}

// Start implements ProcessMonitor.Start.
func (pollingMonitor) Start(cmd *exec.Cmd) (chan runc.Exit, error) {
	return nil, cmd.Start()
}

// Wait implements ProcessMonitor.Wait.
func (pollingMonitor) Wait(cmd *exec.Cmd, _ chan runc.Exit) (int, error) {
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(cmd.Process.Pid, &ws, unix.WNOHANG, nil)
		if err != nil {
			return -1, err
		}
		if pid == cmd.Process.Pid {
			// Wait for the output to be copied. The process is already
			// reaped, so ignore the error.
			cmd.Wait()
			if ws.Signaled() {
				return 128 + int(ws.Signal()), nil
			}
			return ws.ExitStatus(), nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestWaitSurvivesLockedThreadExit verifies that a running "runsc wait"
// started with a parent-death signal is not killed when goroutines exit while
// locked to their OS thread, which makes Go end that thread.
func TestWaitSurvivesLockedThreadExit(t *testing.T) {
	dir := t.TempDir()
	startedDir := filepath.Join(dir, "started")
	if err := os.Mkdir(startedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	doneFile := filepath.Join(dir, "done")
	script := filepath.Join(dir, "fake-runsc")
	const wantStatus = 7
	scriptBody := fmt.Sprintf(`#!/bin/sh
touch %q/$$
while [ ! -e %q ]; do sleep 0.01; done
printf '{"exitStatus":%d}'
`, startedDir, doneFile, wantStatus)
	if err := os.WriteFile(script, []byte(scriptBody), 0o755); err != nil {
		t.Fatal(err)
	}

	// With one P, the waits may all fork from the main thread, which Go
	// never ends.
	if n := runtime.GOMAXPROCS(0); n < 4 {
		runtime.GOMAXPROCS(4)
		t.Cleanup(func() { runtime.GOMAXPROCS(n) })
	}
	// Like the shim's reaper, do not block a thread in wait4(2): a blocked
	// thread is never ended, which would keep the forking thread alive.
	oldMonitor := Monitor
	Monitor = &LogMonitor{Next: pollingMonitor{}}
	t.Cleanup(func() { Monitor = oldMonitor })

	r := &Runsc{
		Command:      script,
		Root:         filepath.Join(dir, "root"),
		PdeathSignal: unix.SIGKILL,
	}
	// Start the waits from many goroutines, so that without a dedicated
	// locked thread they fork from many OS threads.
	const numWaits = 32
	var wg sync.WaitGroup
	errs := make([]error, numWaits)
	for i := range numWaits {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, err := r.Wait(t.Context(), fmt.Sprintf("cid-%d", i))
			if err == nil && status != wantStatus {
				err = fmt.Errorf("status %d, want %d", status, wantStatus)
			}
			errs[i] = err
		}()
	}
	t.Cleanup(func() {
		// Let the scripts exit even if the test fails early.
		os.WriteFile(doneFile, nil, 0o644)
		wg.Wait()
	})

	for deadline := time.Now().Add(30 * time.Second); ; {
		entries, err := os.ReadDir(startedDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) == numWaits {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d waits started", len(entries), numWaits)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Lock goroutines to threads in batches, holding each batch until all of
	// its goroutines are locked, so that each batch ends several distinct
	// OS threads.
	for range 32 {
		const batch = 16
		var locked, release sync.WaitGroup
		locked.Add(batch)
		release.Add(1)
		for range batch {
			go func() {
				runtime.LockOSThread()
				locked.Done()
				release.Wait()
			}()
		}
		locked.Wait()
		release.Done()
	}
	// Give the kernel time to deliver parent-death signals.
	time.Sleep(500 * time.Millisecond)

	if err := os.WriteFile(doneFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("Wait(cid-%d): %v", i, err)
		}
	}
}

// tidMonitor is a ProcessMonitor that records the thread ID that starts each
// command.
type tidMonitor struct {
	mu sync.Mutex
	// pdeathsigTIDs holds the thread IDs that started commands with a
	// parent-death signal, and otherTIDs those that started other commands.
	//
	// +checklocks:mu
	pdeathsigTIDs []int
	// +checklocks:mu
	otherTIDs []int
	// waits counts the started commands that Wait has not returned for.
	waits sync.WaitGroup
}

// Start implements ProcessMonitor.Start.
func (m *tidMonitor) Start(cmd *exec.Cmd) (chan runc.Exit, error) {
	tid := unix.Gettid()
	m.mu.Lock()
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Pdeathsig != 0 {
		m.pdeathsigTIDs = append(m.pdeathsigTIDs, tid)
	} else {
		m.otherTIDs = append(m.otherTIDs, tid)
	}
	m.mu.Unlock()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	m.waits.Add(1)
	return nil, nil
}

// Wait implements ProcessMonitor.Wait.
func (m *tidMonitor) Wait(cmd *exec.Cmd, _ chan runc.Exit) (int, error) {
	defer m.waits.Done()
	err := cmd.Wait()
	if cmd.ProcessState == nil {
		return -1, err
	}
	return cmd.ProcessState.ExitCode(), nil
}

// TestPdeathsigCommandsStartOffCallerThread verifies that a command with a
// parent-death signal starts from an OS thread that is not the thread of the
// caller, and that a command without one starts from the thread of the
// caller. It covers each Runsc start path (direct, and cmdOutput through Wait
// and Kill, with and without IO) and commands started through Monitor
// directly. It checks only which thread starts each command;
// TestWaitSurvivesLockedThreadExit checks that the thread stays alive.
func TestPdeathsigCommandsStartOffCallerThread(t *testing.T) {
	dir := t.TempDir()
	// Exec creates a temporary file in XDG_RUNTIME_DIR.
	t.Setenv("XDG_RUNTIME_DIR", dir)
	script := filepath.Join(dir, "fake-runsc")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := &tidMonitor{}
	oldMonitor := Monitor
	Monitor = &LogMonitor{Next: m}
	t.Cleanup(func() { Monitor = oldMonitor })

	r := &Runsc{
		Command:      script,
		Root:         filepath.Join(dir, "root"),
		PdeathSignal: unix.SIGKILL,
	}
	noPdeathsig := &Runsc{
		Command: script,
		Root:    filepath.Join(dir, "root"),
	}
	var ios []runc.IO
	for range 3 {
		io, err := runc.NewNullIO()
		if err != nil {
			t.Fatalf("NewNullIO: %v", err)
		}
		ios = append(ios, io)
	}
	calls := map[string]func(ctx context.Context){
		"Create": func(ctx context.Context) { r.Create(ctx, "cid", dir, nil) },
		"CreateWithIO": func(ctx context.Context) {
			r.Create(ctx, "cid", dir, &CreateOpts{IO: ios[0]})
		},
		"Start":       func(ctx context.Context) { r.Start(ctx, "cid", nil) },
		"StartWithIO": func(ctx context.Context) { r.Start(ctx, "cid", ios[1]) },
		"Exec":        func(ctx context.Context) { r.Exec(ctx, "cid", specs.Process{}, nil) },
		"ExecWithIO": func(ctx context.Context) {
			r.Exec(ctx, "cid", specs.Process{}, &ExecOpts{IO: ios[2]})
		},
		"Run": func(ctx context.Context) { r.Run(ctx, "cid", dir, nil) },
		"Events": func(ctx context.Context) {
			ec, err := r.Events(ctx, "cid", time.Second)
			if err != nil {
				return
			}
			for range ec {
			}
		},
		"Wait": func(ctx context.Context) { r.Wait(ctx, "cid") },
		"Kill": func(ctx context.Context) { r.Kill(ctx, "cid", 9, nil) },
	}

	// Run each call on its own locked thread. Lock all of these threads
	// before any call starts, and keep them until every call returns, so that
	// no call runs on the thread of another call or of a started command.
	var (
		done, release sync.WaitGroup
		mu            sync.Mutex
		callerTIDs    = map[int]bool{}
		noPdeathTID   int
	)
	begin := make(chan struct{})
	release.Add(1)
	run := func(call func(ctx context.Context)) int {
		done.Add(1)
		tidCh := make(chan int, 1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			tid := unix.Gettid()
			mu.Lock()
			callerTIDs[tid] = true
			mu.Unlock()
			tidCh <- tid
			<-begin
			call(t.Context())
			done.Done()
			release.Wait()
		}()
		return <-tidCh
	}
	for _, call := range calls {
		run(call)
	}
	noPdeathTID = run(func(ctx context.Context) { noPdeathsig.Kill(ctx, "cid", 9, nil) })
	// A command that does not come from Runsc has no SysProcAttr.
	noAttrTID := run(func(ctx context.Context) {
		cmd := exec.CommandContext(ctx, script)
		if ec, err := Monitor.Start(cmd); err == nil {
			Monitor.Wait(cmd, ec)
		}
	})
	close(begin)
	done.Wait()
	release.Done()
	// Let the Wait calls that run after their Runsc method returned (Events)
	// finish before Monitor is restored.
	m.waits.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.pdeathsigTIDs) != len(calls) {
		t.Fatalf("got %d starts with a parent-death signal, want %d", len(m.pdeathsigTIDs), len(calls))
	}
	for _, tid := range m.pdeathsigTIDs {
		if callerTIDs[tid] {
			t.Errorf("command with a parent-death signal started from caller thread %d", tid)
		}
	}
	if want := map[int]bool{noPdeathTID: true, noAttrTID: true}; len(m.otherTIDs) != len(want) || !want[m.otherTIDs[0]] || !want[m.otherTIDs[1]] || m.otherTIDs[0] == m.otherTIDs[1] {
		t.Errorf("commands without a parent-death signal started from threads %v, want caller threads %d and %d", m.otherTIDs, noPdeathTID, noAttrTID)
	}
}

// reapInStartMonitor is a ProcessMonitor that reaps the command in Start, so the
// command is already reaped when Start returns.
type reapInStartMonitor struct{}

// Start implements ProcessMonitor.Start.
func (reapInStartMonitor) Start(cmd *exec.Cmd) (chan runc.Exit, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	cmd.Wait()
	ec := make(chan runc.Exit, 1)
	ec <- runc.Exit{Pid: cmd.Process.Pid, Status: cmd.ProcessState.ExitCode()}
	return ec, nil
}

// Wait implements ProcessMonitor.Wait.
func (reapInStartMonitor) Wait(_ *exec.Cmd, ec chan runc.Exit) (int, error) {
	return (<-ec).Status, nil
}

// TestPdeathsigStartGoroutinesExit verifies that the goroutine that starts a
// command with a parent-death signal exits after the command exits, whether
// the monitor reaps the command before or after the goroutine sees the exit.
func TestPdeathsigStartGoroutinesExit(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-runsc")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldMonitor := Monitor
	t.Cleanup(func() { Monitor = oldMonitor })

	// settled returns the lowest goroutine count seen within d.
	settled := func(d time.Duration) int {
		low := runtime.NumGoroutine()
		for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
			low = min(low, runtime.NumGoroutine())
		}
		return low
	}
	for _, tc := range []struct {
		name string
		next ProcessMonitor
	}{
		// runc.Monitor reaps the command in its own goroutine.
		{name: "runc.Monitor", next: runc.Monitor},
		// reapInStartMonitor reaps the command before the goroutine waits.
		{name: "reapInStartMonitor", next: reapInStartMonitor{}},
		// pollingMonitor reaps the command only when Wait polls.
		{name: "pollingMonitor", next: pollingMonitor{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			Monitor = &LogMonitor{Next: tc.next}
			r := &Runsc{
				Command:      script,
				Root:         filepath.Join(dir, "root"),
				PdeathSignal: unix.SIGKILL,
			}
			// Warm up, so that goroutines that start on first use are in
			// the baseline.
			if err := r.Kill(t.Context(), "cid", 9, nil); err != nil {
				t.Fatalf("Kill: %v", err)
			}
			base := settled(time.Second)
			const n = 16
			for i := range n {
				if err := r.Kill(t.Context(), "cid", 9, nil); err != nil {
					t.Fatalf("Kill %d: %v", i, err)
				}
			}
			for deadline := time.Now().Add(10 * time.Second); runtime.NumGoroutine() > base; time.Sleep(10 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatalf("%d goroutines after %d commands exited, want at most %d", runtime.NumGoroutine(), n, base)
				}
			}
		})
	}
}

// TestStartErrorWithPdeathsig verifies that an error to start a command with a
// parent-death signal is returned, and that later commands still start.
func TestStartErrorWithPdeathsig(t *testing.T) {
	dir := t.TempDir()
	missing := &Runsc{
		Command:      filepath.Join(dir, "missing-runsc"),
		Root:         filepath.Join(dir, "root"),
		PdeathSignal: unix.SIGKILL,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- missing.Kill(t.Context(), "cid", 9, nil) }()
	select {
	case err := <-errCh:
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Kill with a missing runsc binary: got error %v, want %v", err, fs.ErrNotExist)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("Kill with a missing runsc binary did not return")
	}

	script := filepath.Join(dir, "fake-runsc")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &Runsc{
		Command:      script,
		Root:         filepath.Join(dir, "root"),
		PdeathSignal: unix.SIGKILL,
	}
	if err := r.Kill(t.Context(), "cid", 9, nil); err != nil {
		t.Errorf("Kill after a failed start: %v", err)
	}
}

// TestFormatShimLogPath verifies that %ID% tags are replaced with the ID, and
// that a directory path gets the default log file name.
func TestFormatShimLogPath(t *testing.T) {
	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "/var/log/shim.log", want: "/var/log/shim.log"},
		{path: "/var/log/", want: "/var/log/runsc-shim-cid-1.log"},
		{path: "/var/log/%ID%/shim.log", want: "/var/log/cid-1/shim.log"},
		{path: "/var/log/%ID%/", want: "/var/log/cid-1/runsc-shim-cid-1.log"},
		{path: "/var/log/%ID%/%ID%.log", want: "/var/log/cid-1/cid-1.log"},
	} {
		if got := FormatShimLogPath(tc.path, "cid-1"); got != tc.want {
			t.Errorf("FormatShimLogPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}
