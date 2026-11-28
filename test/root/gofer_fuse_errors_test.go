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

package root

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/docker/docker/api/types/mount"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// This file tests that deferred write errors reported by a host FUSE
// filesystem on fsync(2) and on the flush performed by close(2) are
// propagated to the sandboxed application (gvisor/gvisor#16043).
//
// Remote filesystems that commit data asynchronously (JuiceFS, NFS, ...)
// report EDQUOT/ENOSPC/EIO only at fsync or close time. A sandbox that
// swallows those errors makes applications believe their data was stored.
//
// The test mounts an in-process go-fuse loopback filesystem on the host that
// fails FLUSH and FSYNC with EDQUOT for files whose name ends in ".edquot",
// and bind-mounts it into a container in two layouts:
//
//   - Layout A: the bind mount source *is* the FUSE directory. runsc detects
//     FUSE/NFS sources and disables file handle sharing for them.
//   - Layout B: the bind mount source is a tmpfs directory that has the FUSE
//     directory mounted inside it. runsc only inspects the bind source, so the
//     FUSE submount keeps shared file handles.
//
// In both layouts fsync(2) and close(2) must return EDQUOT, as they do on the
// host.

// edquotSuffix marks files for which FLUSH and FSYNC fail with EDQUOT.
const edquotSuffix = ".edquot"

// edquotNode is a loopback FUSE node that fails Flush and Fsync with EDQUOT
// for files whose name ends in edquotSuffix. All other operations, and all
// other files, behave like a regular loopback filesystem.
type edquotNode struct {
	fs.LoopbackNode
}

var (
	_ = (fs.NodeFlusher)((*edquotNode)(nil))
	_ = (fs.NodeFsyncer)((*edquotNode)(nil))
)

func (n *edquotNode) failing() bool {
	return strings.HasSuffix(n.Path(n.Root()), edquotSuffix)
}

// Flush implements fs.NodeFlusher.
func (n *edquotNode) Flush(ctx context.Context, f fs.FileHandle) syscall.Errno {
	if n.failing() {
		return syscall.EDQUOT
	}
	if ff, ok := f.(fs.FileFlusher); ok {
		return ff.Flush(ctx)
	}
	return 0
}

// Fsync implements fs.NodeFsyncer.
func (n *edquotNode) Fsync(ctx context.Context, f fs.FileHandle, flags uint32) syscall.Errno {
	if n.failing() {
		return syscall.EDQUOT
	}
	if ff, ok := f.(fs.FileFsyncer); ok {
		return ff.Fsync(ctx, flags)
	}
	return syscall.ENOTSUP
}

// mountEDQUOTFS mounts an edquotNode loopback filesystem over a fresh backing
// directory and returns the mount point. The filesystem is unmounted when the
// test ends.
func mountEDQUOTFS(t *testing.T) string {
	t.Helper()
	backing := filepath.Join(t.TempDir(), "backing")
	mnt := filepath.Join(t.TempDir(), "fuse")
	for _, dir := range []string{backing, mnt} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", dir, err)
		}
	}
	var st syscall.Stat_t
	if err := syscall.Stat(backing, &st); err != nil {
		t.Fatalf("Stat(%q): %v", backing, err)
	}
	root := &fs.LoopbackRoot{Path: backing, Dev: uint64(st.Dev)}
	root.NewNode = func(r *fs.LoopbackRoot, parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
		return &edquotNode{LoopbackNode: fs.LoopbackNode{RootData: r}}
	}
	server, err := fs.Mount(mnt, root.NewNode(root, nil, "", &st), &fs.Options{
		MountOptions: fuse.MountOptions{
			// The sandbox (and the Docker daemon) access the mount as a
			// different process than the one serving it.
			AllowOther: true,
			Options:    []string{"default_permissions"},
			FsName:     "edquotfs",
			Name:       "edquotfs",
		},
		NullPermissions: true,
		// go-fuse logs every opcode it does not implement (e.g. FUSE_STATX,
		// which the kernel then retries as GETATTR). That is noise here.
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("mounting edquotfs at %q: %v", mnt, err)
	}
	if err := server.WaitMount(); err != nil {
		t.Fatalf("waiting for edquotfs mount at %q: %v", mnt, err)
	}
	t.Cleanup(func() {
		if err := server.Unmount(); err != nil {
			t.Logf("unmounting edquotfs at %q: %v", mnt, err)
		}
		server.Wait()
	})
	return mnt
}

// mountTmpfsWithSubmount creates a host tmpfs with fuseDir bind-mounted at
// <tmpfs>/sub, i.e. a bind mount source whose own filesystem type is not
// FUSE but which contains a FUSE mount. Both mounts are undone when the test
// ends.
func mountTmpfsWithSubmount(t *testing.T, fuseDir string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "b")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dir, err)
	}
	if err := unix.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
		t.Fatalf("mounting tmpfs at %q: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(dir, unix.MNT_DETACH); err != nil {
			t.Logf("unmounting tmpfs at %q: %v", dir, err)
		}
	})
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatalf("Mkdir(%q): %v", sub, err)
	}
	if err := unix.Mount(fuseDir, sub, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind-mounting %q at %q: %v", fuseDir, sub, err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(sub, unix.MNT_DETACH); err != nil {
			t.Logf("unmounting bind at %q: %v", sub, err)
		}
	})
	return dir
}

// probeResult is the parsed output of //test/root/fuse_probe.
type probeResult struct {
	write, fsync, close string
}

func parseProbe(out string) (probeResult, error) {
	var r probeResult
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) != 3 {
		return r, fmt.Errorf("unexpected probe output %q", out)
	}
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			return r, fmt.Errorf("unexpected probe field %q in %q", f, out)
		}
		switch k {
		case "write":
			r.write = v
		case "fsync":
			r.fsync = v
		case "close":
			r.close = v
		default:
			return r, fmt.Errorf("unexpected probe field %q in %q", f, out)
		}
	}
	return r, nil
}

// runProbe runs fuse_probe inside a container created by mk, with hostDir
// bind-mounted at /mnt, against /mnt/<rel>. label names the runtime in logs.
func runProbe(ctx context.Context, t *testing.T, label string, mk func(context.Context, testutil.Logger) *dockerutil.Container, hostDir, rel string) probeResult {
	t.Helper()
	d := mk(ctx, t)
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{
		Image:   "basic/alpine",
		WorkDir: "/probe",
		Mounts: []mount.Mount{{
			Type:   mount.TypeBind,
			Source: hostDir,
			Target: "/mnt",
		}},
	}
	if err := d.CopyFiles(&opts, "/probe", "test/root/fuse_probe/fuse_probe"); err != nil {
		t.Fatalf("CopyFiles: %v", err)
	}
	out, err := d.Run(ctx, opts, "./fuse_probe", filepath.Join("/mnt", rel))
	if err != nil {
		t.Fatalf("fuse_probe on %q (%s) failed: %v\noutput: %s", rel, label, err, out)
	}
	r, err := parseProbe(out)
	if err != nil {
		t.Fatalf("fuse_probe on %q (%s): %v", rel, label, err)
	}
	t.Logf("%s: %s -> write=%s fsync=%s close=%s", label, rel, r.write, r.fsync, r.close)
	return r
}

// TestGoferFUSEDeferredWriteErrors checks that fsync(2) and close(2) on a
// file in a FUSE bind mount return the error reported by the FUSE server.
func TestGoferFUSEDeferredWriteErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	fuseDir := mountEDQUOTFS(t)
	tmpfsDir := mountTmpfsWithSubmount(t, fuseDir)

	layouts := []struct {
		name    string
		hostDir string
		rel     string
	}{
		{name: "FUSESource", hostDir: fuseDir, rel: "a" + edquotSuffix},
		{name: "FUSEBelowTmpfsSource", hostDir: tmpfsDir, rel: filepath.Join("sub", "b"+edquotSuffix)},
	}

	// Control: the FUSE filesystem itself must report EDQUOT on both calls
	// when accessed natively, otherwise the sandbox results are meaningless.
	for _, l := range layouts {
		got := runProbe(ctx, t, "native", dockerutil.MakeNativeContainer, l.hostDir, l.rel)
		if got.write != "OK" || got.fsync != "EDQUOT" || got.close != "EDQUOT" {
			t.Skipf("native runtime does not see the expected errors in layout %s (write=%s fsync=%s close=%s); FUSE on this host does not behave as the test requires", l.name, got.write, got.fsync, got.close)
		}
	}

	// Sanity check: files not marked to fail must work end to end.
	if got := runProbe(ctx, t, dockerutil.Runtime(), dockerutil.MakeContainer, fuseDir, "ok.txt"); got.write != "OK" || got.fsync != "OK" || got.close != "OK" {
		t.Fatalf("unmarked file on FUSE mount: got write=%s fsync=%s close=%s, want all OK", got.write, got.fsync, got.close)
	}

	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) {
			got := runProbe(ctx, t, dockerutil.Runtime(), dockerutil.MakeContainer, l.hostDir, l.rel)
			if got.write != "OK" {
				t.Errorf("write: got %s, want OK", got.write)
			}
			if got.fsync != "EDQUOT" {
				t.Errorf("fsync: got %s, want EDQUOT (deferred write error dropped)", got.fsync)
			}
			if got.close != "EDQUOT" {
				t.Errorf("close: got %s, want EDQUOT (deferred write error dropped)", got.close)
			}
		})
	}
}
