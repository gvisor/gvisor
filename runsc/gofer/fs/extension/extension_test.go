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

package extension

import (
	"errors"
	"maps"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/runsc/flag"
)

type fakeExtension struct {
	name string
}

func (f fakeExtension) Name() string {
	return f.name
}

func (fakeExtension) TryHandleMount(*specs.Spec, *specs.Mount, string, bool) (lisafs.ConnectionImpl, lisafs.ConnectionOpts, error) {
	return nil, lisafs.ConnectionOpts{}, nil
}

func (fakeExtension) SeccompRules() seccomp.SyscallRules {
	return seccomp.NewSyscallRules()
}

type flagExtension struct {
	fakeExtension
	setFlagsSeen *bool
}

func (f flagExtension) SetFlags(*flag.FlagSet) {
	if f.setFlagsSeen != nil {
		*f.setFlagsSeen = true
	}
}

type prepareExtension struct {
	fakeExtension
	prepareGofer func(GoferPrepareContext) (GoferPrepareResult, error)
}

func (f prepareExtension) PrepareGofer(ctx GoferPrepareContext) (GoferPrepareResult, error) {
	if f.prepareGofer == nil {
		return GoferPrepareResult{}, nil
	}
	return f.prepareGofer(ctx)
}

type prepareBeforeRootFSExtension struct {
	fakeExtension
	prepareBeforeRootFS func(GoferPrepareContext) (GoferPrepareResult, error)
}

func (f prepareBeforeRootFSExtension) PrepareBeforeRootFS(ctx GoferPrepareContext) (GoferPrepareResult, error) {
	if f.prepareBeforeRootFS == nil {
		return GoferPrepareResult{}, nil
	}
	return f.prepareBeforeRootFS(ctx)
}

func TestRegisterAndRegistered(t *testing.T) {
	registered = nil

	e1 := fakeExtension{name: "first"}
	e2 := fakeExtension{name: "second"}
	Register(e1)
	Register(e2)

	got := Registered()
	if len(got) != 2 {
		t.Fatalf("len(Registered()) = %d, want 2", len(got))
	}
	if got[0] != e1 || got[1] != e2 {
		t.Fatalf("Registered() = %v, want [%v %v]", got, e1, e2)
	}
}

func TestSetFlags(t *testing.T) {
	registered = nil

	called := false
	Register(fakeExtension{name: "first"})
	Register(flagExtension{fakeExtension: fakeExtension{name: "second"}, setFlagsSeen: &called})
	SetFlags(&flag.FlagSet{})

	if !called {
		t.Fatal("SetFlags did not call extension")
	}
}

func TestPrepareGofer(t *testing.T) {
	registered = nil

	Register(fakeExtension{name: "first"})
	Register(prepareExtension{
		fakeExtension: fakeExtension{name: "second"},
		prepareGofer: func(ctx GoferPrepareContext) (GoferPrepareResult, error) {
			if ctx.ContainerID != "container" || ctx.BundleDir != "/bundle" {
				t.Fatalf("GoferPrepareContext = %+v", ctx)
			}
			return GoferPrepareResult{
				FlagOverrides: map[string]string{"first-fd": "3"},
				PassFDs:       []int{3},
			}, nil
		},
	})
	Register(prepareExtension{
		fakeExtension: fakeExtension{name: "third"},
		prepareGofer: func(GoferPrepareContext) (GoferPrepareResult, error) {
			return GoferPrepareResult{
				FlagOverrides: map[string]string{"second-fd": "4"},
				PassFDs:       []int{4},
			}, nil
		},
	})

	got, err := PrepareGofer(GoferPrepareContext{ContainerID: "container", BundleDir: "/bundle"})
	if err != nil {
		t.Fatalf("PrepareGofer: %v", err)
	}
	if got.FlagOverrides["first-fd"] != "3" || got.FlagOverrides["second-fd"] != "4" {
		t.Fatalf("PrepareGofer overrides = %v", got.FlagOverrides)
	}
	wantFDs := []int{3, 4}
	if !slices.Equal(got.PassFDs, wantFDs) {
		t.Errorf("PrepareGofer().PassFDs = %v, want %v", got.PassFDs, wantFDs)
	}
}

func TestPrepareGoferError(t *testing.T) {
	registered = nil
	want := errors.New("setup failed")
	Register(prepareExtension{
		fakeExtension: fakeExtension{name: "first"},
		prepareGofer: func(GoferPrepareContext) (GoferPrepareResult, error) {
			return GoferPrepareResult{}, want
		},
	})

	if _, err := PrepareGofer(GoferPrepareContext{}); !errors.Is(err, want) {
		t.Fatalf("PrepareGofer error = %v, want %v", err, want)
	}
}

func TestPrepareBeforeRootFS(t *testing.T) {
	orig := registered
	t.Cleanup(func() { registered = orig })
	registered = nil

	Register(fakeExtension{name: "first"})
	Register(prepareBeforeRootFSExtension{
		fakeExtension: fakeExtension{name: "second"},
		prepareBeforeRootFS: func(ctx GoferPrepareContext) (GoferPrepareResult, error) {
			if ctx.ContainerID != "container" || ctx.BundleDir != "/bundle" {
				t.Errorf("PrepareBeforeRootFS callback got ctx = %+v, want ContainerID=%q BundleDir=%q", ctx, "container", "/bundle")
			}
			return GoferPrepareResult{
				FlagOverrides: map[string]string{"host-fd": "7", "shared": "old"},
				PassFDs:       []int{7},
			}, nil
		},
	})
	Register(prepareBeforeRootFSExtension{
		fakeExtension: fakeExtension{name: "third"},
		prepareBeforeRootFS: func(ctx GoferPrepareContext) (GoferPrepareResult, error) {
			return GoferPrepareResult{
				FlagOverrides: map[string]string{"shared": "new", "extra": "val"},
				PassFDs:       []int{8},
			}, nil
		},
	})

	got, err := PrepareBeforeRootFS(GoferPrepareContext{ContainerID: "container", BundleDir: "/bundle"})
	if err != nil {
		t.Fatalf("PrepareBeforeRootFS() error = %v, want nil", err)
	}
	wantOverrides := map[string]string{"host-fd": "7", "shared": "new", "extra": "val"}
	if !maps.Equal(got.FlagOverrides, wantOverrides) {
		t.Errorf("PrepareBeforeRootFS().FlagOverrides = %v, want %v", got.FlagOverrides, wantOverrides)
	}
	wantFDs := []int{7, 8}
	if !slices.Equal(got.PassFDs, wantFDs) {
		t.Errorf("PrepareBeforeRootFS().PassFDs = %v, want %v", got.PassFDs, wantFDs)
	}
}

func TestPrepareBeforeRootFSError(t *testing.T) {
	orig := registered
	t.Cleanup(func() { registered = orig })
	registered = nil
	want := errors.New("host setup failed")
	Register(prepareBeforeRootFSExtension{
		fakeExtension: fakeExtension{name: "first"},
		prepareBeforeRootFS: func(GoferPrepareContext) (GoferPrepareResult, error) {
			return GoferPrepareResult{}, want
		},
	})

	if _, err := PrepareBeforeRootFS(GoferPrepareContext{}); !errors.Is(err, want) {
		t.Fatalf("PrepareBeforeRootFS() error = %v, want %v", err, want)
	}
}
