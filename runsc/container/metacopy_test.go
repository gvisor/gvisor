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

package container

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

func metacopyPattern(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((int(seed) + i*31) & 0xff)
	}
	return b
}

func startMetacopyContainer(t *testing.T, overlay2, tarAnnotation string) (*Container, *config.Config, func()) {
	t.Helper()
	conf := testutil.TestConfig(t)
	if err := conf.Overlay2.Set(overlay2); err != nil {
		t.Fatalf("Overlay2.Set(%q): %v", overlay2, err)
	}
	spec, _ := sleepSpecConf(t)
	spec.Root.Readonly = false
	// Keep only /etc tmpfs so files under testutil.TmpDir() stay on the root
	// overlay's lower layer rather than a separate bind mount.
	spec.Mounts = []specs.Mount{{Type: "tmpfs", Destination: "/etc"}}
	if tarAnnotation != "" {
		spec.Annotations[specutils.AnnotationRootfsUpperTar] = tarAnnotation
		conf.AllowRootfsTarAnnotation = true
	}
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("SetupContainer: %v", err)
	}
	cont, err := New(conf, Args{ID: testutil.RandomContainerID(), Spec: spec, BundleDir: bundleDir})
	if err != nil {
		cleanup()
		t.Fatalf("New: %v", err)
	}
	if err := cont.Start(conf); err != nil {
		cont.Destroy()
		cleanup()
		t.Fatalf("Start: %v", err)
	}
	return cont, conf, func() {
		cont.Destroy()
		cleanup()
	}
}

func TestOverlayMetacopy(t *testing.T) {
	lowerDir, err := os.MkdirTemp(testutil.TmpDir(), "metacopy-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(lowerDir)
	if err := os.Chmod(lowerDir, 0755); err != nil {
		t.Fatalf("Chmod(%q): %v", lowerDir, err)
	}

	const (
		bigSize   = 2 << 20 // Larger than the 1 MiB upper tmpfs limit.
		smallSize = 8 << 10
	)
	fixtures := map[string][]byte{
		"big":    metacopyPattern(1, bigSize),
		"write":  metacopyPattern(2, smallSize),
		"trunc":  metacopyPattern(3, smallSize),
		"otrunc": metacopyPattern(4, bigSize),
		"tar":    metacopyPattern(5, smallSize),
		"atime":  metacopyPattern(6, smallSize),
	}
	for name, data := range fixtures {
		if err := os.WriteFile(filepath.Join(lowerDir, name), data, 0644); err != nil {
			t.Fatalf("WriteFile(%s): %v", name, err)
		}
	}
	oldTime := time.Unix(1000000, 0)
	if err := os.Chtimes(filepath.Join(lowerDir, "atime"), oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes(atime): %v", err)
	}

	cont, conf, cleanup := startMetacopyContainer(t, "root:memory,size=1m,metacopy=on", "")
	defer cleanup()

	runOutput := func(c *Container, cfg *config.Config, script string) string {
		t.Helper()
		out, err := executeCombinedOutput(cfg, c, nil, "/bin/sh", "-e", "-c", script)
		if err != nil {
			t.Fatalf("command %q failed: %v\noutput: %s", script, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	mustRun := func(c *Container, cfg *config.Config, script string) {
		t.Helper()
		_ = runOutput(c, cfg, script)
	}
	readGuest := func(c *Container, cfg *config.Config, p string) []byte {
		t.Helper()
		out, err := executeCombinedOutput(cfg, c, nil, "/bin/cat", p)
		if err != nil {
			t.Fatalf("cat(%s): %v", p, err)
		}
		return out
	}
	pathOf := func(name string) string { return filepath.Join(lowerDir, name) }

	// chown/chmod on a 2 MiB file inside a 1 MiB upper tmpfs proves data was not copied.
	bigPath := pathOf("big")
	mustRun(cont, conf, fmt.Sprintf("chown 1234:5678 %q && chmod 0640 %q", bigPath, bigPath))
	if got, want := runOutput(cont, conf, fmt.Sprintf("stat -c '%%u %%g %%a %%s' %q", bigPath)), fmt.Sprintf("1234 5678 640 %d", bigSize); got != want {
		t.Fatalf("stat(%s) = %q, want %q", bigPath, got, want)
	}
	wantBigSum := sha256.Sum256(fixtures["big"])
	if got := strings.Fields(runOutput(cont, conf, fmt.Sprintf("sha256sum %q", bigPath)))[0]; got != hex.EncodeToString(wantBigSum[:]) {
		t.Fatalf("sha256(%s) = %s, want %x", bigPath, got, wantBigSum)
	}

	// Write-open copies data up without modifying the lower file.
	writePath := pathOf("write")
	mustRun(cont, conf, fmt.Sprintf("chown 1001:1001 %q && printf 'WXYZ' | dd of=%q bs=1 conv=notrunc status=none", writePath, writePath))
	if got, want := readGuest(cont, conf, writePath), append([]byte("WXYZ"), fixtures["write"][4:]...); !bytes.Equal(got, want) {
		t.Fatalf("write-open content mismatch (len %d vs %d)", len(got), len(want))
	}
	if lowerBytes, err := os.ReadFile(writePath); err != nil || !bytes.Equal(lowerBytes, fixtures["write"]) {
		t.Fatalf("lower file %s modified after write-open (err=%v)", writePath, err)
	}

	// Truncate copies up and shrinks to the requested size.
	truncPath := pathOf("trunc")
	mustRun(cont, conf, fmt.Sprintf("chown 1002:1002 %q && truncate -s 16 %q", truncPath, truncPath))
	if got := readGuest(cont, conf, truncPath); !bytes.Equal(got, fixtures["trunc"][:16]) {
		t.Fatalf("truncate content = %x, want %x", got, fixtures["trunc"][:16])
	}

	// O_TRUNC on a 2 MiB metacopy file inside a 1 MiB upper tmpfs drops lower data without copying it.
	otruncPath := pathOf("otrunc")
	mustRun(cont, conf, fmt.Sprintf("chown 1003:1003 %q && printf 'short' > %q", otruncPath, otruncPath))
	if got := readGuest(cont, conf, otruncPath); string(got) != "short" {
		t.Fatalf("O_TRUNC content = %q, want %q", got, "short")
	}

	// Reading a metacopy file updates atime without changing mtime or ctime,
	// while honoring O_NOATIME.
	atimePath := pathOf("atime")
	mustRun(cont, conf, fmt.Sprintf("chown 1005:1005 %q", atimePath))
	statTimes := func(cmd string) (int64, string, string) {
		t.Helper()
		f := strings.Fields(runOutput(cont, conf, cmd))
		sec, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			t.Fatalf("ParseInt(%q): %v", f[0], err)
		}
		return sec, f[1], f[2]
	}
	atime0, mtime0, ctime0 := statTimes(fmt.Sprintf("stat -c '%%X %%.9Y %%.9Z' %q", atimePath))
	if atime0 != oldTime.Unix() {
		t.Fatalf("initial atime = %d, want %d", atime0, oldTime.Unix())
	}
	mustRun(cont, conf, fmt.Sprintf("dd if=%q of=/dev/null bs=16 count=1 iflag=noatime status=none", atimePath))
	if a, m, c := statTimes(fmt.Sprintf("stat -c '%%X %%.9Y %%.9Z' %q", atimePath)); a != atime0 || m != mtime0 || c != ctime0 {
		t.Fatalf("O_NOATIME read changed times: (%d, %s, %s) != (%d, %s, %s)", a, m, c, atime0, mtime0, ctime0)
	}
	mustRun(cont, conf, fmt.Sprintf("dd if=%q of=/dev/null bs=16 count=1 status=none", atimePath))
	atime1, mtime1, ctime1 := statTimes(fmt.Sprintf("stat -c '%%X %%.9Y %%.9Z' %q", atimePath))
	if atime1 <= atime0 || mtime1 != mtime0 || ctime1 != ctime0 {
		t.Fatalf("after read: got (%d, %s, %s), want atime>%d and mtime/ctime=(%s, %s)", atime1, mtime1, ctime1, atime0, mtime0, ctime0)
	}
	if fa, fm, fc := statTimes(fmt.Sprintf("stat -c '%%X %%.9Y %%.9Z' - < %q", atimePath)); fa != atime1 || fm != mtime0 || fc != ctime0 {
		t.Fatalf("fstat after read: got (%d, %s, %s), want (%d, %s, %s)", fa, fm, fc, atime1, mtime0, ctime0)
	}

	// Tar export carries lower data inline without metacopy/redirect xattrs, and
	// restores the snapshot data even if the lower file changes.
	tarPath := pathOf("tar")
	mustRun(cont, conf, fmt.Sprintf("chown 1004:1004 %q", tarPath))
	tarFile, err := os.CreateTemp(testutil.TmpDir(), "metacopy-upper-*.tar")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(tarFile.Name())
	defer tarFile.Close()
	if err := cont.TarRootfsUpperLayer(tarFile); err != nil {
		t.Fatalf("TarRootfsUpperLayer: %v", err)
	}
	if _, err := tarFile.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	wantEntry := "./" + strings.TrimPrefix(tarPath, "/")
	found := false
	tr := tar.NewReader(tarFile)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Reader.Next: %v", err)
		}
		if hdr.Name != wantEntry {
			continue
		}
		found = true
		for _, k := range []string{"SCHILY.xattr.trusted.overlay.metacopy", "SCHILY.xattr.trusted.overlay.redirect"} {
			if _, ok := hdr.PAXRecords[k]; ok {
				t.Errorf("tar entry %s unexpectedly carries %s", hdr.Name, k)
			}
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("ReadAll(%s): %v", hdr.Name, err)
		}
		if !bytes.Equal(data, fixtures["tar"]) {
			t.Errorf("tar entry %s data mismatch", hdr.Name)
		}
	}
	if !found {
		t.Fatalf("missing tar entry %s", wantEntry)
	}

	if err := os.WriteFile(tarPath, []byte("different-lower"), 0644); err != nil {
		t.Fatalf("WriteFile(replaced lower): %v", err)
	}
	cont2, conf2, cleanup2 := startMetacopyContainer(t, "root:memory,metacopy=on", tarFile.Name())
	defer cleanup2()
	if got := readGuest(cont2, conf2, tarPath); !bytes.Equal(got, fixtures["tar"]) {
		t.Fatalf("restored %s returned %d bytes, want snapshot data (%d bytes)", tarPath, len(got), len(fixtures["tar"]))
	}
}
