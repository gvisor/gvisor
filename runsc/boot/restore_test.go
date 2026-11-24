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

package boot

import (
	"errors"
	"flag"
	"math"
	"os"
	"testing"
	"testing/synctest"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/control/controlapi"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

func TestSaveAsyncDuringRestoreSetup(t *testing.T) {
	l := &Loader{k: &kernel.Kernel{}, state: created}
	// Restore can own the kernel before the loader leaves created.
	l.restoring.Store(true)
	if err := l.SaveAsync(); err != linuxerr.EBUSY {
		t.Fatalf("SaveAsync() error = %v, want %v", err, linuxerr.EBUSY)
	}
}

func TestSaveAsyncReportsConversionFailure(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	// An uncompressed checkpoint requires all three state and page files.
	files, err := fd.NewFromFiles([]*os.File{file, file})
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		defer file.Close()
	}

	synctest.Test(t, func(t *testing.T) {
		l := &Loader{
			k:       &kernel.Kernel{},
			root:    containerInfo{spec: &specs.Spec{}},
			saveFDs: files,
			state:   started,
		}
		if err := l.SaveAsync(); err != nil {
			t.Fatalf("SaveAsync() failed to start: %v", err)
		}
		synctest.Wait()
		if got := l.k.CheckpointGen().Count; got != 1 {
			t.Errorf("checkpoint completed %d times, want 1", got)
		}
		if err := l.SaveAsync(); err != linuxerr.ENXIO {
			t.Errorf("second SaveAsync() error = %v, want %v", err, linuxerr.ENXIO)
		}
	})
}

func TestSaveConversionFailureNotification(t *testing.T) {
	for _, tc := range []struct {
		name          string
		state         loaderState
		restoring     bool
		pending       bool
		wantBusy      bool
		wantGenerated uint32
	}{
		{
			name:          "AdmittedCheckpoint",
			state:         started,
			wantGenerated: 1,
		},
		{
			name:      "RestoreHookInProgress",
			state:     restoringStarted,
			restoring: true,
			wantBusy:  true,
		},
		{
			name:          "BackgroundPagesLoading",
			state:         restoringStarted,
			wantGenerated: 1,
		},
		{
			name:          "PendingCheckpointCleanup",
			state:         started,
			pending:       true,
			wantBusy:      true,
			wantGenerated: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &kernel.Kernel{}
			l := &Loader{k: k, state: tc.state}
			l.checkpointResumePending.Store(tc.pending)
			l.restoring.Store(tc.restoring)

			// The admitted case has no output file, so conversion fails
			// before checkpoint preparation starts.
			err := l.save(&controlapi.SaveOpts{})
			if gotBusy := errors.Is(err, linuxerr.EBUSY); gotBusy != tc.wantBusy {
				t.Fatalf("save() error = %v, EBUSY = %t, want EBUSY = %t", err, gotBusy, tc.wantBusy)
			}
			if err == nil {
				t.Fatal("save() succeeded without an output file")
			}
			if got := k.CheckpointGen().Count; got != tc.wantGenerated {
				t.Errorf("checkpoint generation = %d, want %d", got, tc.wantGenerated)
			}
		})
	}
}

func TestTSCOffsetFromSnapshot(t *testing.T) {
	const (
		ghz3     = uint64(3_000_000_000)
		nsPerDay = uint64(86_400_000_000_000)
	)
	for _, tc := range []struct {
		name         string
		baseCycle    uint64
		baseFreq     uint64
		baseRealtime uint64
		curCycle     uint64
		curRealtime  uint64
		want         uint64
		wantOK       bool
	}{
		{
			name:         "NoTimeElapsed",
			baseCycle:    1000,
			baseFreq:     ghz3,
			baseRealtime: 5_000,
			curCycle:     400,
			curRealtime:  5_000,
			want:         600,
			wantOK:       true,
		},
		{
			name:         "RealtimeBehindSnapshot",
			baseCycle:    1000,
			baseFreq:     ghz3,
			baseRealtime: 10_000,
			curCycle:     400,
			curRealtime:  5_000,
			want:         600,
			wantOK:       true,
		},
		{
			name:         "OneSecond",
			baseCycle:    1000,
			baseFreq:     ghz3,
			baseRealtime: 0,
			curCycle:     1000,
			curRealtime:  1_000_000_000,
			want:         ghz3,
			wantOK:       true,
		},
		{
			// deltaNs * baseFreq overflows 64 bits here.
			name:         "OneDay",
			baseCycle:    1_000_000,
			baseFreq:     ghz3,
			baseRealtime: 1_000,
			curCycle:     1_000_000,
			curRealtime:  1_000 + nsPerDay,
			want:         86_400 * ghz3,
			wantOK:       true,
		},
		{
			name:         "NegativeOffset",
			baseCycle:    1000,
			baseFreq:     ghz3,
			baseRealtime: 0,
			curCycle:     5000,
			curRealtime:  0,
			want:         ^uint64(4000) + 1,
			wantOK:       true,
		},
		{
			name:         "ElapsedCyclesOverflow",
			baseCycle:    0,
			baseFreq:     math.MaxUint64,
			baseRealtime: 0,
			curCycle:     0,
			curRealtime:  2_000_000_000,
			wantOK:       false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tscOffsetFromSnapshot(tc.baseCycle, tc.baseFreq, tc.baseRealtime, tc.curCycle, tc.curRealtime)
			if ok != tc.wantOK {
				t.Fatalf("tscOffsetFromSnapshot() ok = %t, want %t", ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("tscOffsetFromSnapshot() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestTPUPreparationRejectsOCIPause(t *testing.T) {
	l := &Loader{ociPauseCount: 1}
	prepared, err := l.withTPUPreparation(func() (bool, error) {
		t.Fatal("preparation ran while OCI-paused")
		return true, nil
	})
	if prepared || !errors.Is(err, linuxerr.EBUSY) {
		t.Fatalf("preparation = (%t, %v), want (false, EBUSY)", prepared, err)
	}
	// Admission must release pauseMu even on rejection.
	l.pauseMu.Lock()
	l.ociPauseCount = 0
	l.pauseMu.Unlock()
	if _, err := l.withTPUPreparation(func() (bool, error) { return false, nil }); err != nil {
		t.Fatal(err)
	}
}

func TestOCIPauseWaitsForTPUPreparation(t *testing.T) {
	// Loader tests install a seccomp filter compatible with systrap.
	platformFlag := flag.Lookup("platform")
	previous := platformFlag.Value.String()
	if err := platformFlag.Value.Set("systrap"); err != nil {
		t.Fatal(err)
	}
	defer platformFlag.Value.Set(previous)
	k, err := testutil.Boot()
	if err != nil {
		t.Fatal(err)
	}
	defer k.Timekeeper().Destroy()
	defer k.GlobalInit().Release(k.SupervisorContext())
	synctest.Test(t, func(t *testing.T) {
		l := &Loader{k: k}
		cm := &containerManager{l: l}
		started := make(chan struct{})
		release := make(chan struct{})
		done := make(chan struct{})
		pauseDone := make(chan error, 1)
		go func() {
			defer close(done)
			l.withTPUPreparation(func() (bool, error) {
				close(started)
				<-release
				if k.IsPaused() {
					t.Error("kernel paused during TPU exchange")
				}
				return true, nil
			})
		}()
		<-started
		go func() { pauseDone <- cm.Pause(nil, nil) }()
		if l.pauseMu.TryLock() {
			l.pauseMu.Unlock()
			t.Fatal("TPU preparation did not hold pauseMu")
		}
		select {
		case err := <-pauseDone:
			t.Fatalf("Pause returned during TPU exchange: %v", err)
		default:
		}
		close(release)
		<-done
		if err := <-pauseDone; err != nil {
			t.Fatal(err)
		}
		if !k.IsPaused() {
			t.Error("kernel did not pause after preparation")
		}
		if err := cm.Resume(nil, nil); err != nil {
			t.Fatal(err)
		}
	})
}
