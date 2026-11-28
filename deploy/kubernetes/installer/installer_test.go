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

// Package main_test tests the installer binary through its interface: the
// environment, the host files under HOST_ROOT, the Kubernetes API, the ready
// file and the exit status. Host commands (nsenter) are stubs.
package main_test

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

// installerPath is the installer binary under test.
var installerPath string

func TestMain(m *testing.M) {
	// The fake runsc of setRelease is a copy of this test binary: it sleeps.
	if filepath.Base(os.Args[0]) == "runsc" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	path, err := testutil.FindFile("deploy/kubernetes/installer/installer")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot find the installer binary: %v\n", err)
		os.Exit(1)
	}
	installerPath = path
	os.Exit(m.Run())
}

// nsenterStub stands for the host commands that the installer runs with
// nsenter. STUB_CRI_FAIL makes the CRI plugin unhealthy "with-block" or
// "without-block" (the gvisor-deploy block in STUB_CONFIG).
// For k3s, a restart renders the template in STUB_K3S_DIR, with the default
// config in STUB_K3S_BASE.
const nsenterStub = `#!/bin/bash
while [[ $# -gt 0 && "$1" != "--" ]]; do shift; done
shift
echo "$*" >>"${STUB_LOG}"
case "$1 ${2:-}" in
  "systemctl restart")
    if [[ -n "${STUB_RESTART_SLEEP:-}" ]]; then sleep "${STUB_RESTART_SLEEP}"; fi
    if [[ "$3" == k3s* && -n "${STUB_K3S_DIR:-}" ]]; then
      tmpl=""
      for t in config-v3.toml.tmpl config.toml.tmpl; do
        if [[ -f "${STUB_K3S_DIR}/$t" ]]; then tmpl="${STUB_K3S_DIR}/$t"; break; fi
      done
      if [[ -n "${tmpl}" ]]; then
        while IFS= read -r line || [[ -n "${line}" ]]; do
          if [[ "${line}" == *'{{ template "base" . }}'* ]]; then cat "${STUB_K3S_BASE}"; else printf '%s\n' "${line}"; fi
        done <"${tmpl}" >"${STUB_K3S_DIR}/config.toml"
      else
        cp "${STUB_K3S_BASE}" "${STUB_K3S_DIR}/config.toml"
      fi
    fi
    exit "${STUB_RESTART_RC:-0}" ;;
  "systemctl is-active")
    if [[ "$3" == "${STUB_ACTIVE_UNIT:-containerd}" ]]; then echo active; exit 0; fi
    echo inactive; exit 3 ;;
  "ctr --address")
    status=ok
    case "${STUB_CRI_FAIL:-}" in
      with-block) if grep -q "BEGIN gvisor-deploy" "${STUB_CONFIG}"; then status=error; fi ;;
      without-block) if ! grep -q "BEGIN gvisor-deploy" "${STUB_CONFIG}"; then status=error; fi ;;
    esac
    echo "TYPE ID PLATFORMS STATUS"
    echo "io.containerd.grpc.v1 cri - ${status}"
    exit 0 ;;
esac
echo "unexpected host command: $*" >&2
exit 1
`

// fakeAPI is a fake Kubernetes API server.
type fakeAPI struct {
	srv *httptest.Server

	mu sync.Mutex
	// labels records the gvisor.dev/runsc values of node label patches; nil
	// removes the label.
	labels []*string
	// dsPatches records the DaemonSet patches.
	dsPatches []map[string]any
}

func newFakeAPI(t *testing.T) *fakeAPI {
	a := &fakeAPI{}
	a.srv = httptest.NewTLSServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test-token" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/nodes/node1":
		var p struct {
			Metadata struct {
				Labels map[string]*string `json:"labels"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.labels = append(a.labels, p.Metadata.Labels["gvisor.dev/runsc"])
		w.Write([]byte("{}"))
	case r.URL.Path == "/apis/apps/v1/namespaces/ns/daemonsets/ds" && r.Method == http.MethodPatch:
		var p map[string]any
		if err := json.Unmarshal(body, &p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.dsPatches = append(a.dsPatches, p)
		w.Write([]byte("{}"))
	case r.URL.Path == "/apis/apps/v1/namespaces/ns/daemonsets/ds" && r.Method == http.MethodGet:
		gen, updated := 1, 0
		if len(a.dsPatches) > 0 {
			gen, updated = 2, 1
		}
		fmt.Fprintf(w, `{"metadata":{"generation":%d},"status":{"observedGeneration":%d,"desiredNumberScheduled":1,"updatedNumberScheduled":%d,"numberReady":%d,"numberUnavailable":0}}`, gen, gen, updated, updated)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// lastLabel returns the last node label value, and whether there was a patch.
func (a *fakeAPI) lastLabel() (*string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.labels) == 0 {
		return nil, false
	}
	return a.labels[len(a.labels)-1], true
}

// host is a fake Kubernetes node.
type host struct {
	t         *testing.T
	root      string // HOST_ROOT
	artifacts string // ARTIFACTS_DIR
	stubs     string
	stubLog   string
	saDir     string
	readyFile string
	api       *fakeAPI
	// config is the host path of the config that containerd loads.
	config string
	// env is added to the installer environment.
	env []string
}

const containerdConfig = "/etc/containerd/config.toml"

// newHost returns a host with the given containerd config.
func newHost(t *testing.T, config string) *host {
	h := newBareHost(t)
	h.writeHost(containerdConfig, config)
	h.writeHost("/run/containerd/containerd.sock", "")
	h.config = containerdConfig
	return h
}

func newBareHost(t *testing.T) *host {
	dir := t.TempDir()
	h := &host{
		t:         t,
		root:      filepath.Join(dir, "host"),
		artifacts: filepath.Join(dir, "artifacts"),
		stubs:     filepath.Join(dir, "stubs"),
		stubLog:   filepath.Join(dir, "stub.log"),
		saDir:     filepath.Join(dir, "sa"),
		readyFile: filepath.Join(dir, "ready"),
		api:       newFakeAPI(t),
	}
	for _, d := range []string{h.root, h.stubs, h.saDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(h.stubs, "nsenter"), []byte(nsenterStub), 0755); err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.api.srv.Certificate().Raw})
	if err := os.WriteFile(filepath.Join(h.saDir, "ca.crt"), ca, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.saDir, "token"), []byte("test-token\n"), 0644); err != nil {
		t.Fatal(err)
	}
	h.setRelease("a")
	return h
}

// setRelease writes the release files to install. runsc is a copy of the
// test binary, which sleeps when it runs as runsc; version makes the files
// unique.
func (h *host) setRelease(version string) {
	h.t.Helper()
	if err := os.RemoveAll(h.artifacts); err != nil {
		h.t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		h.t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		h.t.Fatal(err)
	}
	files := map[string][]byte{
		"runsc":                    append(data, []byte("release-"+version)...),
		"containerd-shim-runsc-v1": []byte("shim-" + version),
		"gvisor-bin/sidecar":       []byte("sidecar-" + version),
	}
	for name, content := range files {
		p := filepath.Join(h.artifacts, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			h.t.Fatal(err)
		}
		if err := os.WriteFile(p, content, 0755); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *host) path(p string) string {
	return filepath.Join(h.root, p)
}

func (h *host) writeHost(p, content string) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(h.path(p)), 0755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(h.path(p), []byte(content), 0644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *host) readHost(p string) string {
	h.t.Helper()
	data, err := os.ReadFile(h.path(p))
	if err != nil {
		h.t.Fatal(err)
	}
	return string(data)
}

func (h *host) exists(p string) bool {
	_, err := os.Lstat(h.path(p))
	return err == nil
}

// restarts returns the number of runtime restarts.
func (h *host) restarts() int {
	return strings.Count(h.hostCommands(), "systemctl restart")
}

// hostCommands returns the host commands that the installer ran.
func (h *host) hostCommands() string {
	data, _ := os.ReadFile(h.stubLog)
	return string(data)
}

// versions returns the installed version directories.
func (h *host) versions() []string {
	entries, _ := os.ReadDir(h.path("/opt/gvisor/versions"))
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// result is the outcome of an installer run.
type result struct {
	ready  bool // The ready file exists.
	exited bool // The installer exited by itself.
	code   int  // The exit status, if exited.
	logs   string
}

// lockedBuffer is a bytes.Buffer for concurrent use.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (h *host) command(args []string, extraEnv []string) (*exec.Cmd, *lockedBuffer) {
	u, err := url.Parse(h.api.srv.URL)
	if err != nil {
		h.t.Fatal(err)
	}
	cmd := exec.Command(installerPath, args...)
	cmd.Env = append([]string{
		"PATH=" + h.stubs + ":/usr/bin:/bin",
		"HOST_ROOT=" + h.root,
		"ARTIFACTS_DIR=" + h.artifacts,
		"NODE_NAME=node1",
		"KUBERNETES_SERVICE_HOST=" + u.Hostname(),
		"KUBERNETES_SERVICE_PORT=" + u.Port(),
		"SERVICE_ACCOUNT_DIR=" + h.saDir,
		"READY_FILE=" + h.readyFile,
		"HEALTH_TIMEOUT=1s",
		"STUB_LOG=" + h.stubLog,
		"STUB_CONFIG=" + h.path(h.config),
	}, append(h.env, extraEnv...)...)
	// The installer gets its own process group, so that kill also stops the
	// stubs that it runs.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	logs := &lockedBuffer{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	return cmd, logs
}

// kill stops a started installer and its child processes.
func kill(cmd *exec.Cmd) {
	syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	cmd.Wait()
}

// run runs the installer until it is ready, exits, or logs that it stopped
// (UNINSTALL FAILED), then stops it.
func (h *host) run(args []string, extraEnv ...string) result {
	h.t.Helper()
	os.Remove(h.readyFile)
	cmd, logs := h.command(args, extraEnv)
	if err := cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.After(60 * time.Second)
	for {
		select {
		case err := <-done:
			r := result{exited: true, logs: logs.String()}
			if ee, ok := err.(*exec.ExitError); ok {
				r.code = ee.ExitCode()
			}
			_, statErr := os.Stat(h.readyFile)
			r.ready = statErr == nil
			return r
		case <-deadline:
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
			h.t.Fatalf("installer did not finish; logs:\n%s", logs.String())
		case <-time.After(20 * time.Millisecond):
		}
		_, statErr := os.Stat(h.readyFile)
		if statErr == nil || strings.Contains(logs.String(), "UNINSTALL FAILED") {
			cmd.Process.Signal(syscall.SIGTERM)
			<-done
			return result{ready: statErr == nil, logs: logs.String()}
		}
	}
}

func (h *host) install(extraEnv ...string) result {
	return h.run([]string{"run"}, append([]string{"MODE=install"}, extraEnv...)...)
}

func (h *host) uninstall(extraEnv ...string) result {
	return h.run([]string{"run"}, append([]string{"MODE=uninstall"}, extraEnv...)...)
}

func (h *host) wantLabel(want *string) {
	h.t.Helper()
	got, ok := h.api.lastLabel()
	if !ok {
		h.t.Fatalf("no node label patch")
	}
	switch {
	case want == nil && got != nil:
		h.t.Fatalf("node label = %q, want removed", *got)
	case want != nil && (got == nil || *got != *want):
		h.t.Fatalf("node label = %v, want %q", got, *want)
	}
}

func installedLabel() *string {
	s := "installed"
	return &s
}

var binaryNameRE = regexp.MustCompile(`(?m)^binary_name = "([^"]+)"$`)

// checkInstalled checks the host after an install.
func (h *host) checkInstalled(r result, configBefore, plugin string) {
	h.t.Helper()
	if !r.ready {
		h.t.Fatalf("installer not ready; logs:\n%s", r.logs)
	}
	h.wantLabel(installedLabel())
	config := h.readHost(h.config)
	if !strings.HasPrefix(config, configBefore) {
		h.t.Errorf("config does not start with the original config:\n%s", config)
	}
	for _, want := range []string{
		fmt.Sprintf("[plugins.%q.containerd.runtimes.runsc]", plugin),
		`runtime_path = "/opt/gvisor/bin/containerd-shim-runsc-v1"`,
		`ConfigPath = "/etc/gvisor/runsc.toml"`,
	} {
		if !strings.Contains(config, want) {
			h.t.Errorf("config has no %q:\n%s", want, config)
		}
	}
	m := binaryNameRE.FindStringSubmatch(h.readHost("/etc/gvisor/runsc.toml"))
	if m == nil {
		h.t.Fatalf("runsc.toml has no binary_name:\n%s", h.readHost("/etc/gvisor/runsc.toml"))
	}
	for _, f := range []string{m[1], filepath.Join(filepath.Dir(m[1]), "gvisor-bin/sidecar"), "/opt/gvisor/bin/containerd-shim-runsc-v1"} {
		st, err := os.Stat(h.path(f))
		if err != nil || st.Mode()&0111 == 0 {
			h.t.Errorf("%s is not an installed executable: %v", f, err)
		}
	}
}

// checkClean checks that the host has no files of the installer, and the
// original config.
func (h *host) checkClean(configBefore string) {
	h.t.Helper()
	if got := h.readHost(h.config); got != configBefore {
		h.t.Errorf("config changed:\n got %q\nwant %q", got, configBefore)
	}
	for _, p := range []string{"/opt/gvisor", "/etc/gvisor"} {
		if h.exists(p) {
			h.t.Errorf("%s exists", p)
		}
	}
}

const (
	criV2 = "io.containerd.grpc.v1.cri"
	criV3 = "io.containerd.cri.v1.runtime"
)

func TestInstallAndUninstall(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config string
		plugin string
	}{
		{
			name:   "version 2",
			config: "version = 2\n\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc]\n  runtime_type = \"io.containerd.runc.v2\"\n",
			plugin: criV2,
		},
		{
			name:   "version 3",
			config: "version = 3\n\n[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]\n  runtime_type = 'io.containerd.runc.v2'\n",
			plugin: criV3,
		},
		{
			name:   "version 4 without final newline",
			config: "version = 4\n[plugins]\n  x = 1",
			plugin: criV3,
		},
		{
			name:   "final empty line",
			config: "version = 2\n\n",
			plugin: criV2,
		},
		{
			name:   "version after comments",
			config: "# containerd config\n\nversion=3 # comment\n",
			plugin: criV3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHost(t, tc.config)
			h.checkInstalled(h.install(), tc.config, tc.plugin)
			if h.restarts() != 1 {
				t.Errorf("restarts = %d, want 1", h.restarts())
			}

			// A second run with the same release and config does not restart.
			r := h.install()
			h.checkInstalled(r, tc.config, tc.plugin)
			if h.restarts() != 1 || !strings.Contains(r.logs, "not restarting") {
				t.Errorf("second install restarted containerd (restarts = %d); logs:\n%s", h.restarts(), r.logs)
			}

			r = h.uninstall()
			if !r.ready {
				t.Fatalf("uninstall not ready; logs:\n%s", r.logs)
			}
			h.wantLabel(nil)
			h.checkClean(tc.config)
			if h.restarts() != 2 {
				t.Errorf("restarts = %d, want 2", h.restarts())
			}
		})
	}
}

func TestRunscFlagsAndPodAnnotations(t *testing.T) {
	h := newHost(t, "version = 2\n")
	r := h.install("RUNSC_FLAGS=platform=systrap\n --debug = true \n")
	h.checkInstalled(r, "version = 2\n", criV2)
	conf := h.readHost("/etc/gvisor/runsc.toml")
	m := binaryNameRE.FindStringSubmatch(conf)
	if m == nil {
		t.Fatalf("runsc.toml has no binary_name:\n%s", conf)
	}
	want := "# Generated by gvisor-deploy. Do not edit.\n" +
		"binary_name = \"" + m[1] + "\"\n" +
		"\n" +
		"[runsc_config]\n" +
		"  platform = \"systrap\"\n" +
		"  debug = \"true\"\n"
	if conf != want {
		t.Errorf("runsc.toml:\n got %q\nwant %q", conf, want)
	}
	if !strings.Contains(h.readHost(h.config), `pod_annotations = ["dev.gvisor.*"]`) {
		t.Errorf("config has no default pod annotations:\n%s", h.readHost(h.config))
	}

	// New settings replace the block.
	h.checkInstalled(h.install("POD_ANNOTATIONS=x.*"), "version = 2\n", criV2)
	config := h.readHost(h.config)
	if n := strings.Count(config, "BEGIN gvisor-deploy"); n != 1 || !strings.Contains(config, `pod_annotations = ["x.*"]`) || strings.Contains(config, "dev.gvisor") {
		t.Errorf("config after a settings change (%d blocks):\n%s", n, config)
	}
	if h.restarts() != 2 {
		t.Errorf("restarts = %d, want 2", h.restarts())
	}

	// An empty POD_ANNOTATIONS passes no annotations.
	h = newHost(t, "version = 2\n")
	h.checkInstalled(h.install("POD_ANNOTATIONS="), "version = 2\n", criV2)
	if strings.Contains(h.readHost(h.config), "pod_annotations") {
		t.Errorf("config has pod annotations:\n%s", h.readHost(h.config))
	}

	// Valid handler names other than runsc.
	for _, handler := range []string{"runsc-v2", "a"} {
		h = newHost(t, "version = 2\n")
		r = h.install("RUNTIME_HANDLER=" + handler)
		if !r.ready {
			t.Fatalf("install with handler %q not ready; logs:\n%s", handler, r.logs)
		}
		if want := `[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.` + handler + `]`; !strings.Contains(h.readHost(h.config), want) {
			t.Errorf("config has no %q:\n%s", want, h.readHost(h.config))
		}
	}
}

func TestInvalidSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
	}{
		{"handler with space", "RUNTIME_HANDLER=bad name"},
		{"handler with bracket", "RUNTIME_HANDLER=runsc]"},
		{"handler with dot", "RUNTIME_HANDLER=runsc.x"},
		{"handler with upper case", "RUNTIME_HANDLER=Runsc"},
		{"handler with leading dash", "RUNTIME_HANDLER=-runsc"},
		{"handler too long", "RUNTIME_HANDLER=" + strings.Repeat("a", 64)},
		{"runsc flag without value", "RUNSC_FLAGS=noequals"},
		{"runsc flag without key", "RUNSC_FLAGS==x"},
		{"runsc flag with space", "RUNSC_FLAGS=a b=c"},
		{"runsc flag with bracket", "RUNSC_FLAGS=x]=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const config = "version = 2\n"
			h := newHost(t, config)
			r := h.install(tc.env)
			if !r.exited || r.code == 0 || r.ready {
				t.Fatalf("install = %+v, want a failure", r)
			}
			h.checkClean(config)
		})
	}
}

func TestRefusesConflictingHandler(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config string
	}{
		{"table", "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runsc]\n  runtime_type = \"x\"\n"},
		{"single-quoted table", "version = 3\n[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'runsc']\n"},
		{"inline table", "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes]\n  runsc = { runtime_type = \"x\" }\n"},
		{"dotted key", "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes]\n  runsc.runtime_type = \"x\"\n"},
		{"options table", "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runsc.options]\n  x = 1\n"},
		{"double-quoted table", "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.\"runsc\"]\n"},
		{"inline table in containerd table", "version = 3\n[plugins.'io.containerd.cri.v1.runtime'.containerd]\n  runtimes.runsc = { runtime_type = 'x' }\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHost(t, tc.config)
			h.wantRefusal(h.install())
			h.checkClean(tc.config)
		})
	}
}

// wantRefusal checks that the installer refused the node without a change.
func (h *host) wantRefusal(r result) {
	h.t.Helper()
	if !r.ready || !strings.Contains(r.logs, "NOT INSTALLING") {
		h.t.Fatalf("install = %+v, want a refusal", r)
	}
	h.wantLabel(nil)
	if h.restarts() != 0 {
		h.t.Errorf("restarts = %d, want 0", h.restarts())
	}
}

func TestRefusesUnsupportedConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config string
	}{
		{"empty", ""},
		{"no version key", "[plugins]\n  x = 1\n"},
		{"version in a table", "[plugins]\nversion = 3\n"},
		{"version 1", "version = 1\n"},
		{"version 5", "version = 5\n"},
		{"block without end marker", "version = 2\n\n# BEGIN gvisor-deploy: managed by the gVisor installer. Do not edit.\n[a]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHost(t, tc.config)
			h.wantRefusal(h.install())
			h.checkClean(tc.config)
		})
	}
}

func TestUninstallFailsWithoutEndMarker(t *testing.T) {
	const config = "version = 2\n"
	h := newHost(t, config)
	h.checkInstalled(h.install(), config, criV2)
	broken := strings.Replace(h.readHost(h.config), "# END gvisor-deploy", "# removed", 1)
	h.writeHost(h.config, broken)
	r := h.uninstall()
	if !r.exited || r.code == 0 || r.ready {
		t.Fatalf("uninstall = %+v, want a failure", r)
	}
	if got := h.readHost(h.config); got != broken {
		t.Errorf("config changed:\n got %q\nwant %q", got, broken)
	}
	if h.restarts() != 1 {
		t.Errorf("restarts = %d, want 1 (the install)", h.restarts())
	}
	h.checkNoRestartPending()
}

func TestUnsupportedNode(t *testing.T) {
	const config = "version = 2\n"
	h := newHost(t, config)
	h.writeHost("/var/lib/rancher/rke2/marker", "")
	h.wantRefusal(h.install())
	h.checkClean(config)

	// Uninstall has nothing to do, and must not block the uninstall of other
	// nodes.
	if r := h.uninstall(); !r.ready {
		t.Fatalf("uninstall = %+v, want ready", r)
	}
	h.wantLabel(nil)
}

func TestRefusesNodeWhenHealthCheckFails(t *testing.T) {
	// The health check fails before any change.
	const config = "version = 2\n"
	h := newHost(t, config)
	h.wantRefusal(h.install("STUB_CRI_FAIL=without-block"))
	h.checkClean(config)
}

// checkNoRestartPending checks that no restart is pending, and that the
// config backup is removed.
func (h *host) checkNoRestartPending() {
	h.t.Helper()
	for _, p := range []string{"/opt/gvisor/restart-pending", "/opt/gvisor/config-backup"} {
		if h.exists(p) {
			h.t.Errorf("%s exists", p)
		}
	}
}

func TestRollbackWhenContainerdIsUnhealthy(t *testing.T) {
	const config = "version = 2\n"
	h := newHost(t, config)
	r := h.install("STUB_CRI_FAIL=with-block")
	if !r.ready || !strings.Contains(r.logs, "NOT INSTALLING") {
		t.Fatalf("install = %+v, want a refusal after rollback", r)
	}
	h.wantLabel(nil)
	if got := h.readHost(h.config); got != config {
		t.Errorf("config not restored:\n got %q\nwant %q", got, config)
	}
	if h.restarts() != 2 {
		t.Errorf("restarts = %d, want 2 (change and rollback)", h.restarts())
	}
	h.checkNoRestartPending()
}

func TestFailedRollbackIsCompletedLater(t *testing.T) {
	const config = "version = 2\n"
	h := newHost(t, config)

	// containerd does not restart, also with the previous config: the
	// installer fails, and keeps the restart pending.
	r := h.install("STUB_RESTART_RC=1")
	if !r.exited || r.code == 0 || r.ready {
		t.Fatalf("install = %+v, want a failure", r)
	}
	if got := h.readHost(h.config); got != config {
		t.Errorf("config not restored:\n got %q\nwant %q", got, config)
	}
	if h.restarts() != 2 {
		t.Errorf("restarts = %d, want 2 (change and rollback)", h.restarts())
	}
	for _, p := range []string{"/opt/gvisor/restart-pending", "/opt/gvisor/config-backup"} {
		if !h.exists(p) {
			t.Errorf("%s does not exist", p)
		}
	}

	// The next run completes the install.
	h.checkInstalled(h.install(), config, criV2)
	if h.restarts() != 3 {
		t.Errorf("restarts = %d, want 3", h.restarts())
	}
	h.checkNoRestartPending()
}

func TestUninstallRollbackIsNotRetried(t *testing.T) {
	const config = "version = 2\n"
	h := newHost(t, config)
	h.checkInstalled(h.install(), config, criV2)
	installed := h.readHost(h.config)

	// containerd is not healthy without the block: the uninstall is rolled
	// back, and the installer stays not ready.
	r := h.uninstall("STUB_CRI_FAIL=without-block")
	if r.ready || r.exited || !strings.Contains(r.logs, "UNINSTALL FAILED") {
		t.Fatalf("uninstall = %+v, want a not-ready installer", r)
	}
	if got := h.readHost(h.config); got != installed {
		t.Errorf("config not restored:\n got %q\nwant %q", got, installed)
	}
	restarts := h.restarts()

	// A restarted installer does not try again.
	r = h.uninstall()
	if r.ready || r.exited || !strings.Contains(r.logs, "not retrying") {
		t.Fatalf("second uninstall = %+v, want a not-ready installer that does not retry", r)
	}
	if h.restarts() != restarts {
		t.Errorf("second uninstall restarted containerd")
	}
	if got := h.readHost(h.config); got != installed {
		t.Errorf("second uninstall changed the config")
	}

	// A new install clears the state, and then uninstall works.
	h.checkInstalled(h.install(), config, criV2)
	if r := h.uninstall(); !r.ready {
		t.Fatalf("uninstall after a new install = %+v, want ready", r)
	}
	h.checkClean(config)
}

// interruptInstall kills the installer while it restarts containerd after
// the config change.
func interruptInstall(t *testing.T, h *host) {
	t.Helper()
	os.Remove(h.readyFile)
	cmd, logs := h.command([]string{"run"}, []string{"MODE=install", "STUB_RESTART_SLEEP=30"})
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer kill(cmd)
	for start := time.Now(); h.restarts() == 0; time.Sleep(20 * time.Millisecond) {
		if time.Since(start) > 30*time.Second {
			t.Fatalf("installer did not restart containerd; logs:\n%s", logs.String())
		}
	}
	if !strings.Contains(h.readHost(h.config), "BEGIN gvisor-deploy") {
		t.Fatalf("config has no block before the restart")
	}
}

func TestInterruptedInstallIsCompleted(t *testing.T) {
	const config = "version = 2\n"
	h := newHost(t, config)
	interruptInstall(t, h)

	// The next run restarts containerd, although the config does not change.
	r := h.install()
	h.checkInstalled(r, config, criV2)
	if h.restarts() != 2 || strings.Contains(r.logs, "not restarting") {
		t.Errorf("pending restart not done (restarts = %d); logs:\n%s", h.restarts(), r.logs)
	}
	h.checkNoRestartPending()
}

func TestUninstallKeepsPendingRestartWhenEditFails(t *testing.T) {
	const config = "version = 2\n"
	h := newHost(t, config)
	interruptInstall(t, h)
	installed := h.readHost(h.config)
	broken := strings.Replace(installed, "# END gvisor-deploy", "# removed", 1)
	h.writeHost(h.config, broken)

	// The uninstall fails, and the restart of the interrupted install stays
	// pending.
	r := h.uninstall()
	if !r.exited || r.code == 0 || r.ready {
		t.Fatalf("uninstall = %+v, want a failure", r)
	}
	for _, p := range []string{"/opt/gvisor/restart-pending", "/opt/gvisor/config-backup"} {
		if !h.exists(p) {
			t.Errorf("%s does not exist", p)
		}
	}

	// When the config is repaired, the uninstall completes.
	h.writeHost(h.config, installed)
	if r := h.uninstall(); !r.ready {
		t.Fatalf("uninstall = %+v, want ready", r)
	}
	h.checkClean(config)
}

func TestInterruptedInstallIsRolledBack(t *testing.T) {
	const config = "version = 2\n"
	h := newHost(t, config)
	interruptInstall(t, h)

	// containerd is not healthy after the pending restart: the next run
	// restores the config from before the interrupted run.
	r := h.install("STUB_CRI_FAIL=with-block")
	if !r.ready || !strings.Contains(r.logs, "NOT INSTALLING") {
		t.Fatalf("install = %+v, want a refusal after rollback", r)
	}
	if got := h.readHost(h.config); got != config {
		t.Errorf("config not restored:\n got %q\nwant %q", got, config)
	}
	h.checkNoRestartPending()
}

func TestUpgradeKeepsVersionInUse(t *testing.T) {
	const config = "version = 2\n"
	h := newHost(t, config)
	h.checkInstalled(h.install(), config, criV2)
	old := h.versions()
	if len(old) != 1 {
		t.Fatalf("versions = %v, want 1", old)
	}

	// A process runs the installed runsc (a copy of the test binary, which
	// sleeps).
	running := exec.Command(h.path("/opt/gvisor/versions/" + old[0] + "/runsc"))
	if err := running.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		running.Process.Kill()
		running.Wait()
	}()

	h.setRelease("b")
	h.checkInstalled(h.install(), config, criV2)
	if got := h.versions(); len(got) != 2 {
		t.Fatalf("versions = %v, want the old and the new version", got)
	}
	if strings.Contains(h.readHost("/etc/gvisor/runsc.toml"), "/opt/gvisor/versions/"+old[0]+"/") {
		t.Errorf("runsc.toml still uses the old version")
	}

	// When no process uses the old version anymore, the next run removes it.
	running.Process.Kill()
	running.Wait()
	h.checkInstalled(h.install(), config, criV2)
	if got := h.versions(); len(got) != 1 || got[0] == old[0] {
		t.Errorf("versions = %v, want only the new version", got)
	}
}

const k3sDir = "/var/lib/rancher/k3s/agent/etc/containerd"

// newK3sHost returns a k3s host whose containerd config without a template
// is base.
func newK3sHost(t *testing.T, base string) *host {
	h := newBareHost(t)
	h.writeHost(k3sDir+"/config.toml", base)
	h.writeHost("/run/k3s/containerd/containerd.sock", "")
	baseFile := filepath.Join(t.TempDir(), "base.toml")
	if err := os.WriteFile(baseFile, []byte(base), 0644); err != nil {
		t.Fatal(err)
	}
	h.config = k3sDir + "/config.toml"
	h.env = []string{"STUB_ACTIVE_UNIT=k3s", "STUB_K3S_DIR=" + h.path(k3sDir), "STUB_K3S_BASE=" + baseFile}
	return h
}

const k3sBaseV3 = "version = 3\n\n[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]\n  runtime_type = 'io.containerd.runc.v2'\n"

func TestK3s(t *testing.T) {
	for _, tc := range []struct {
		name     string
		base     string
		template string
		plugin   string
	}{
		{
			name:     "version 2",
			base:     "version = 2\n\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc]\n  runtime_type = \"io.containerd.runc.v2\"\n",
			template: "config.toml.tmpl",
			plugin:   criV2,
		},
		{
			name:     "version 3",
			base:     k3sBaseV3,
			template: "config-v3.toml.tmpl",
			plugin:   criV3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newK3sHost(t, tc.base)
			h.checkInstalled(h.install(), tc.base, tc.plugin)
			tmpl := h.readHost(k3sDir + "/" + tc.template)
			if !strings.HasPrefix(tmpl, `{{ template "base" . }}`) || !strings.Contains(tmpl, "BEGIN gvisor-deploy") {
				t.Errorf("template:\n%s", tmpl)
			}
			if !strings.Contains(h.hostCommands(), "systemctl restart k3s") {
				t.Errorf("k3s not restarted")
			}

			if r := h.uninstall(); !r.ready {
				t.Fatalf("uninstall = %+v, want ready", r)
			}
			h.checkClean(tc.base)
			if h.exists(k3sDir + "/" + tc.template) {
				t.Errorf("template not removed")
			}
		})
	}
}

func TestK3sRollback(t *testing.T) {
	h := newK3sHost(t, k3sBaseV3)
	r := h.install("STUB_CRI_FAIL=with-block")
	if !r.ready || !strings.Contains(r.logs, "NOT INSTALLING") {
		t.Fatalf("install = %+v, want a refusal after rollback", r)
	}
	if got := h.readHost(h.config); got != k3sBaseV3 {
		t.Errorf("generated config not restored:\n got %q\nwant %q", got, k3sBaseV3)
	}
	if h.exists(k3sDir + "/config-v3.toml.tmpl") {
		t.Errorf("template not removed")
	}
	if h.restarts() != 2 {
		t.Errorf("restarts = %d, want 2 (change and rollback)", h.restarts())
	}
	h.checkNoRestartPending()
}

func TestK3sUninstallRollback(t *testing.T) {
	h := newK3sHost(t, k3sBaseV3)
	h.checkInstalled(h.install(), k3sBaseV3, criV3)
	tmpl := h.readHost(k3sDir + "/config-v3.toml.tmpl")
	generated := h.readHost(h.config)

	// containerd is not healthy without the block: the template is restored.
	r := h.uninstall("STUB_CRI_FAIL=without-block")
	if r.ready || r.exited || !strings.Contains(r.logs, "UNINSTALL FAILED") {
		t.Fatalf("uninstall = %+v, want a not-ready installer", r)
	}
	if got := h.readHost(k3sDir + "/config-v3.toml.tmpl"); got != tmpl {
		t.Errorf("template not restored:\n got %q\nwant %q", got, tmpl)
	}
	if got := h.readHost(h.config); got != generated {
		t.Errorf("generated config not restored:\n got %q\nwant %q", got, generated)
	}
	if h.restarts() != 3 {
		t.Errorf("restarts = %d, want 3 (install, change and rollback)", h.restarts())
	}
	h.checkNoRestartPending()
}

func TestK3sRollbackWhenTemplateIsNotUsed(t *testing.T) {
	// k3s restarts, but does not generate the config from the template.
	h := newK3sHost(t, k3sBaseV3)
	h.env = []string{"STUB_ACTIVE_UNIT=k3s"}
	r := h.install()
	if !r.ready || !strings.Contains(r.logs, "NOT INSTALLING") {
		t.Fatalf("install = %+v, want a refusal after rollback", r)
	}
	if h.exists(k3sDir + "/config-v3.toml.tmpl") {
		t.Errorf("template not removed")
	}
	if h.restarts() != 2 {
		t.Errorf("restarts = %d, want 2 (change and rollback)", h.restarts())
	}
	h.checkNoRestartPending()
}

func TestK3sRefusesGeneratedConfigWithHandler(t *testing.T) {
	const base = k3sBaseV3 + "[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runsc]\n"
	h := newK3sHost(t, base)
	h.wantRefusal(h.install())
	h.checkClean(base)
	if h.exists(k3sDir + "/config-v3.toml.tmpl") {
		t.Errorf("template created")
	}
}

func TestK3sRefusesTemplateWithHandler(t *testing.T) {
	const tmpl = "{{ template \"base\" . }}\n[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes]\n  runsc = { runtime_type = 'x' }\n"
	h := newK3sHost(t, k3sBaseV3)
	h.writeHost(k3sDir+"/config-v3.toml.tmpl", tmpl)
	h.wantRefusal(h.install())
	h.checkClean(k3sBaseV3)
	if got := h.readHost(k3sDir + "/config-v3.toml.tmpl"); got != tmpl {
		t.Errorf("template changed:\n%s", got)
	}
}

func TestTriggerUninstall(t *testing.T) {
	h := newBareHost(t)
	r := h.run([]string{"trigger-uninstall"}, "DAEMONSET_NAMESPACE=ns", "DAEMONSET_NAME=ds")
	if !r.exited || r.code != 0 {
		t.Fatalf("trigger-uninstall = %+v, want success", r)
	}
	h.api.mu.Lock()
	defer h.api.mu.Unlock()
	if len(h.api.dsPatches) != 1 {
		t.Fatalf("DaemonSet patches = %v, want 1", h.api.dsPatches)
	}
	got, _ := json.Marshal(h.api.dsPatches[0])
	for _, want := range []string{`"gvisor.dev/deploy-mode":"uninstall"`, `"maxUnavailable":"100%"`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("DaemonSet patch %s has no %s", got, want)
		}
	}
}

func TestProbe(t *testing.T) {
	h := newBareHost(t)
	probe := func() int {
		cmd, _ := h.command([]string{"probe"}, nil)
		err := cmd.Run()
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		return 0
	}
	os.Remove(h.readyFile)
	if code := probe(); code == 0 {
		t.Errorf("probe succeeded before the installer is ready")
	}
	if err := os.WriteFile(h.readyFile, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if code := probe(); code != 0 {
		t.Errorf("probe failed after the installer is ready: %d", code)
	}
}
