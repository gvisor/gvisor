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

# Tests the installer Dockerfile: for each architecture, the image must have
# the files of that architecture, and must build without emulation. Uses stub
# files instead of real binaries. Needs Docker with Buildx.

set -euo pipefail

DOCKERFILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/Dockerfile"
fail() { echo "FAIL: $*" >&2; exit 1; }

WORK="$(mktemp -d)"
TAG="gvisor-installer-image-test-$$"
cleanup() {
  rm -rf "${WORK}"
  docker rm -f "${TAG}-c" >/dev/null 2>&1 || true
  for t in amd64 arm64; do
    docker rmi "${TAG}:${t}" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

for arch in amd64 arm64; do
  ctx="${WORK}/ctx-${arch}"
  mkdir -p "${ctx}/gvisor/gvisor-bin"
  echo "runsc-${arch}" >"${ctx}/gvisor/runsc"
  echo "shim-${arch}" >"${ctx}/gvisor/containerd-shim-runsc-v1"
  echo "sidecar-${arch}" >"${ctx}/gvisor/gvisor-bin/sidecar"
  echo "installer-${arch}" >"${ctx}/gvisor-installer"
done

# check_image <image> <arch> checks the architecture and the files.
check_image() {
  local image="$1" arch="$2"
  [[ "$(docker image inspect -f '{{.Architecture}}' "${image}")" == "${arch}" ]] ||
    fail "${image} has the wrong architecture"
  docker rm -f "${TAG}-c" >/dev/null 2>&1 || true
  docker create --platform "linux/${arch}" --name "${TAG}-c" "${image}" >/dev/null
  for f in /opt/gvisor-artifacts/runsc:runsc /opt/gvisor-artifacts/containerd-shim-runsc-v1:shim \
      /opt/gvisor-artifacts/gvisor-bin/sidecar:sidecar /usr/local/bin/gvisor-installer:installer; do
    got="$(docker cp "${TAG}-c:${f%%:*}" - | tar -xO)"
    [[ "${got}" == "${f#*:}-${arch}" ]] || fail "${f%%:*} in ${image} is ${got}"
  done
  docker cp "${TAG}-c:/bin/nsenter" - >/dev/null || fail "no nsenter in ${image}"
  docker rm -f "${TAG}-c" >/dev/null
}

for arch in amd64 arm64; do
  docker buildx build -q --load --platform "linux/${arch}" -t "${TAG}:${arch}" \
    -f "${DOCKERFILE}" "${WORK}/ctx-${arch}" >/dev/null || fail "build for ${arch}"
  check_image "${TAG}:${arch}" "${arch}"
done

echo PASS
