#!/bin/bash

# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Tests build-image.sh with stub curl, docker, go and kind commands. Does not
# need network access, a Docker daemon or Go. Needs tar, zstd and sha512sum.

set -euo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/build-image.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
LOG="${WORK}/log"
CTXLIST="${WORK}/context"
FIX="${WORK}/fixtures"
STUBS="${WORK}/stubs"
mkdir -p "${FIX}" "${STUBS}"
export LOG CTXLIST FIX

fail() { echo "FAIL: $*" >&2; exit 1; }

# The PATH of the script under test has only the stubs and the tools below.
for tool in bash sed mktemp cp rm mkdir od tr grep head tar zstd sha512sum dirname basename cat find sort chmod; do
  ln -s "$(command -v "${tool}")" "${STUBS}/${tool}"
done

cat >"${STUBS}/docker" <<'EOF'
#!/bin/bash
echo "docker $*" >>"${LOG}"
case "$1 ${2:-}" in
  "version -f") echo "${STUB_DOCKER_ARCH:-amd64}" ;;
  "buildx version") ;;
  "buildx build")
    ctx="${!#}"
    (cd "${ctx}" && find . \( -type f -o -type l \) | sort | while read -r f; do
      t=file; [[ -L "${f}" ]] && t=symlink
      x=; [[ -x "${f}" ]] && x=" executable"
      echo "${f} ${t}${x}"
    done) >"${CTXLIST}"
    exit "${STUB_BUILD_RC:-0}" ;;
  "push "*) exit "${STUB_PUSH_RC:-0}" ;;
esac
EOF
cat >"${STUBS}/go" <<'EOF'
#!/bin/bash
echo "go GOOS=${GOOS:-} GOARCH=${GOARCH:-} CGO_ENABLED=${CGO_ENABLED:-} GOTOOLCHAIN=${GOTOOLCHAIN:-} $*" >>"${LOG}"
while [[ $# -gt 0 ]]; do
  if [[ "$1" == -o ]]; then echo installer >"$2"; chmod +x "$2"; fi
  shift
done
EOF
cat >"${STUBS}/curl" <<'EOF'
#!/bin/bash
url="${!#}"
echo "curl ${url}" >>"${LOG}"
[[ -z "${STUB_CURL_RC:-}" ]] || exit "${STUB_CURL_RC}"
while [[ $# -gt 0 ]]; do
  if [[ "$1" == -o ]]; then cp "${FIX}/$(basename "${url}")" "$2"; fi
  shift
done
EOF
cat >"${STUBS}/kind" <<'EOF'
#!/bin/bash
echo "kind $*" >>"${LOG}"
exit "${STUB_KIND_RC:-0}"
EOF
chmod +x "${STUBS}/docker" "${STUBS}/go" "${STUBS}/curl" "${STUBS}/kind"

# make_release <dir> <ELF machine> writes a fake release: runsc starts with an
# ELF header for the given machine (62: x86-64, 183: aarch64).
make_release() {
  local dir="$1" machine="$2"
  mkdir -p "${dir}/gvisor-bin"
  {
    printf '\177ELF'
    printf '\0%.0s' $(seq 14)
    if [[ "${machine}" == 62 ]]; then printf '\076\000'; else printf '\267\000'; fi
    printf 'release-20260101.0'
  } >"${dir}/runsc"
  echo shim >"${dir}/containerd-shim-runsc-v1"
  echo sidecar >"${dir}/gvisor-bin/sidecar"
  chmod +x "${dir}/runsc" "${dir}/containerd-shim-runsc-v1"
}

# set_fixture <release dir> serves the release dir as the downloaded tarball.
set_fixture() {
  rm -f "${FIX}"/gvisor.tar.zstd*
  tar --zstd -cf "${FIX}/gvisor.tar.zstd" -C "$1" .
  (cd "${FIX}" && sha512sum gvisor.tar.zstd >gvisor.tar.zstd.sha512)
}

# run <args>: runs the script; sets RC and OUT.
run() {
  : >"${LOG}"
  rm -f "${CTXLIST}"
  set +e
  OUT="$(env -u GOTOOLCHAIN PATH="${STUBS}" bash "${SCRIPT}" "$@" 2>&1)"
  RC=$?
  set -e
}
expect_rc() { [[ "${RC}" == "$1" ]] || fail "$2: exit code ${RC}, want $1; output: ${OUT}"; }
expect_out() { grep -qF -- "$1" <<<"${OUT}" || fail "$2: output has no \"$1\"; output: ${OUT}"; }
expect_log() { grep -qF -- "$1" "${LOG}" || fail "$2: no \"$1\" in the log: $(cat "${LOG}")"; }
expect_no_log() { ! grep -qF -- "$1" "${LOG}" || fail "$2: unexpected \"$1\" in the log"; }
expect_ctx() { grep -qxF -- "$1" "${CTXLIST}" || fail "$2: no \"$1\" in the build context: $(cat "${CTXLIST}")"; }

make_release "${WORK}/x86_64" 62
make_release "${WORK}/aarch64" 183

# --release: URL, architecture mapping, build options and build context.
for pair in amd64:x86_64:aarch64 arm64:aarch64:x86_64; do
  IFS=: read -r arch release_arch other_arch <<<"${pair}"
  set_fixture "${WORK}/${release_arch}"
  run --image r/i:t --release 20261109.0 --arch "${arch}"
  expect_rc 0 "release ${arch}"
  expect_log "curl https://storage.googleapis.com/gvisor/releases/release/20261109.0/${release_arch}/gvisor.tar.zstd" "release ${arch}"
  expect_log "curl https://storage.googleapis.com/gvisor/releases/release/20261109.0/${release_arch}/gvisor.tar.zstd.sha512" "release ${arch}"
  expect_log "go GOOS=linux GOARCH=${arch} CGO_ENABLED=0 GOTOOLCHAIN=auto build" "release ${arch}"
  expect_log "--provenance=false --sbom=false --platform linux/${arch} -t r/i:t" "release ${arch}"
  expect_ctx "./gvisor/runsc file executable" "release ${arch}"
  expect_ctx "./gvisor/gvisor-bin/sidecar file" "release ${arch}"
  expect_ctx "./gvisor-installer file executable" "release ${arch}"
  expect_out "gVisor release-20260101.0" "release ${arch}"
  expect_no_log "docker push" "release ${arch}"
  expect_no_log "kind " "release ${arch}"
  # The release must match the architecture.
  set_fixture "${WORK}/${other_arch}"
  run --image r/i:t --release 20261109.0 --arch "${arch}"
  expect_rc 1 "release ${arch} with ${other_arch} binaries"
  expect_out "runsc is not for ${arch}" "release ${arch} with ${other_arch} binaries"
  expect_no_log "buildx build" "release ${arch} with ${other_arch} binaries"
done

# The default architecture is the architecture of the Docker server.
set_fixture "${WORK}/aarch64"
STUB_DOCKER_ARCH=arm64 run --image r/i:t --release latest
expect_rc 0 "default architecture"
expect_log "/release/latest/aarch64/gvisor.tar.zstd" "default architecture"
expect_log "--platform linux/arm64" "default architecture"

# A wrong checksum or a failed download stops the script before the build.
set_fixture "${WORK}/x86_64"
echo garbage >>"${FIX}/gvisor.tar.zstd"
run --image r/i:t --release latest --arch amd64
expect_rc 1 "wrong checksum"
expect_out "FAILED" "wrong checksum"
expect_out "try again later" "wrong checksum"
expect_no_log "buildx build" "wrong checksum"
set_fixture "${WORK}/x86_64"
STUB_CURL_RC=22 run --image r/i:t --release 20261109.0 --arch amd64
[[ "${RC}" != 0 ]] || fail "failed download: exit code 0"
expect_no_log "buildx build" "failed download"

# A release without runsc stops the script before the build.
mkdir -p "${WORK}/empty"
echo x >"${WORK}/empty/other"
set_fixture "${WORK}/empty"
run --image r/i:t --release latest --arch amd64
expect_rc 1 "release without runsc"
expect_out "no executable runsc" "release without runsc"

# --push and --kind-cluster run after the build, in this order.
set_fixture "${WORK}/x86_64"
run --image r/i:t --release latest --arch amd64 --push --kind-cluster k
expect_rc 0 "push and kind"
[[ "$(grep -oE '^(docker buildx build|docker push r/i:t|kind load docker-image r/i:t --name k)' "${LOG}" | tr '\n' '|')" == \
  "docker buildx build|docker push r/i:t|kind load docker-image r/i:t --name k|" ]] ||
  fail "push and kind: wrong order: $(cat "${LOG}")"
STUB_PUSH_RC=1 run --image r/i:t --release latest --arch amd64 --push
[[ "${RC}" != 0 ]] || fail "failed push: exit code 0"
! grep -qF "Built r/i:t" <<<"${OUT}" || fail "failed push: reports a built image"

# --release-dir: symlinks are copied as files; no download tools needed.
mkdir -p "${WORK}/linked"
cp -r "${WORK}/x86_64/." "${WORK}/linked/"
rm "${WORK}/linked/runsc"
ln -s "${WORK}/x86_64/runsc" "${WORK}/linked/runsc"
rm "${STUBS}/curl" "${STUBS}/zstd"
# Run from another directory: the script must not depend on it.
pushd / >/dev/null
run --image r/i:t --release-dir "${WORK}/linked" --arch amd64
popd >/dev/null
expect_rc 0 "release-dir"
expect_ctx "./gvisor/runsc file executable" "release-dir"
run --image r/i:t --release-dir "${WORK}/aarch64" --arch amd64
expect_rc 1 "release-dir for another architecture"
expect_out "runsc is not for amd64" "release-dir for another architecture"

# Argument errors.
run
expect_rc 2 "no arguments"
expect_out "Usage: build-image.sh" "no arguments"
run --image r/i:t --release-dir "${WORK}/x86_64" --bogus
expect_rc 2 "unknown flag"
run --image r/i:t
expect_rc 1 "no release"
expect_out "exactly one of --release or --release-dir" "no release"
run --image r/i:t --release latest --release-dir "${WORK}/x86_64"
expect_rc 1 "two releases"
run --image
expect_rc 1 "flag without value"
expect_out -- "--image needs a value" "flag without value"
run --image r/i:t --release-dir "${WORK}/x86_64" --arch riscv64
expect_rc 1 "unsupported architecture"
expect_out "unsupported architecture riscv64" "unsupported architecture"
run --image r/i:t --release-dir "${WORK}/missing"
expect_rc 1 "missing release dir"
rm "${STUBS}/kind"
run --image r/i:t --release-dir "${WORK}/x86_64" --kind-cluster k
expect_rc 1 "kind not installed"
expect_out "kind is not installed" "kind not installed"
run --image r/i:t --release latest
expect_rc 1 "curl not installed"
expect_out "curl is not installed" "curl not installed"

echo PASS
