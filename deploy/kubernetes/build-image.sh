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

# Builds the gvisor-deploy installer image for one architecture, from a gVisor
# release and the installer source in this repository. Run it on Linux.
#
# Usage: build-image.sh --image NAME:TAG (--release RELEASE | --release-dir DIR)
#                       [--arch amd64|arm64] [--push] [--kind-cluster NAME]
#
#   --image NAME:TAG     The image to build.
#   --release RELEASE    The gVisor release to download, for example
#                        20261109.0, or "latest".
#   --release-dir DIR    A directory with the extracted contents of a release
#                        tarball, for the same architecture as the image.
#   --arch ARCH          The image architecture. The default is the
#                        architecture of the Docker server.
#   --push               Push the image after the build.
#   --kind-cluster NAME  Load the image into the kind cluster NAME.

set -euo pipefail

usage() {
  sed -n '/^# Usage:/,/^$/s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" >&2
  exit 2
}
fail() { echo "build-image.sh: $*" >&2; exit 1; }

IMAGE="" RELEASE="" RELEASE_DIR="" ARCH="" PUSH=false KIND_CLUSTER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image|--release|--release-dir|--arch|--kind-cluster)
      [[ $# -ge 2 && -n "$2" ]] || fail "$1 needs a value"
      case "$1" in
        --image) IMAGE="$2" ;;
        --release) RELEASE="$2" ;;
        --release-dir) RELEASE_DIR="$2" ;;
        --arch) ARCH="$2" ;;
        --kind-cluster) KIND_CLUSTER="$2" ;;
      esac
      shift 2
      ;;
    --push) PUSH=true; shift ;;
    *) usage ;;
  esac
done
[[ -n "${IMAGE}" ]] || usage
# True if both or neither are set.
if [[ "${RELEASE:+x}" == "${RELEASE_DIR:+x}" ]]; then
  fail "give exactly one of --release or --release-dir"
fi

need=(docker go od)
[[ -n "${RELEASE}" ]] && need+=(curl sha512sum tar zstd)
[[ -n "${KIND_CLUSTER}" ]] && need+=(kind)
for cmd in "${need[@]}"; do
  command -v "${cmd}" >/dev/null || fail "${cmd} is not installed"
done
docker buildx version >/dev/null 2>&1 || fail "docker buildx is not installed"

# By default, build for the Docker server, where kind nodes run. With a
# remote Docker server, its architecture can differ from this host.
ARCH="${ARCH:-$(docker version -f '{{.Server.Arch}}')}"
case "${ARCH}" in
  amd64) RELEASE_ARCH=x86_64 ELF_MACHINE=62 ;;
  arm64) RELEASE_ARCH=aarch64 ELF_MACHINE=183 ;;
  *) fail "unsupported architecture ${ARCH}" ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# The build context is in the repository, not in /tmp: Docker installed as a
# snap cannot read the /tmp of the host.
CTX="$(mktemp -d "${REPO_ROOT}/.build-image.XXXXXX")"
trap 'rm -rf "${CTX}"' EXIT
GVISOR="${CTX}/gvisor"
mkdir -p "${GVISOR}"

if [[ -n "${RELEASE}" ]]; then
  url="https://storage.googleapis.com/gvisor/releases/release/${RELEASE}/${RELEASE_ARCH}"
  echo "Downloading ${url}/gvisor.tar.zstd" >&2
  curl -fsSL -o "${CTX}/gvisor.tar.zstd" "${url}/gvisor.tar.zstd"
  curl -fsSL -o "${CTX}/gvisor.tar.zstd.sha512" "${url}/gvisor.tar.zstd.sha512"
  if ! (cd "${CTX}" && sha512sum -c gvisor.tar.zstd.sha512 >&2); then
    [[ "${RELEASE}" != latest ]] ||
      echo "If a release was just published, try again later, or give a dated release." >&2
    fail "the checksum of the release tarball is wrong"
  fi
  tar --zstd -xf "${CTX}/gvisor.tar.zstd" -C "${GVISOR}"
  rm -f "${CTX}/gvisor.tar.zstd" "${CTX}/gvisor.tar.zstd.sha512"
else
  [[ -d "${RELEASE_DIR}" ]] || fail "${RELEASE_DIR} is not a directory"
  # Copy the files that symlinks point to: the image must contain them.
  cp -rL "${RELEASE_DIR}/." "${GVISOR}/"
fi

# Check the release before the build: runsc must be an executable for ARCH
# (the ELF e_machine field, at offset 18).
[[ -f "${GVISOR}/runsc" && -x "${GVISOR}/runsc" ]] || fail "the release has no executable runsc"
machine="$(od -An -tu2 -j18 -N2 "${GVISOR}/runsc" | tr -d ' ')"
[[ "${machine}" == "${ELF_MACHINE}" ]] || fail "runsc is not for ${ARCH} (ELF machine ${machine})"
version="$(grep -a -o -m1 'release-[0-9]\{8\}\.[0-9]\{1,\}' "${GVISOR}/runsc" | head -1 || true)"
echo "gVisor ${version:-version unknown}" >&2

# GOTOOLCHAIN=auto lets Go download the version that go.mod needs, also where
# the distribution sets GOTOOLCHAIN=local.
(cd "${REPO_ROOT}" && GOTOOLCHAIN="${GOTOOLCHAIN:-auto}" CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" \
  go build -o "${CTX}/gvisor-installer" ./deploy/kubernetes/installer)

# Attestations break `kind load docker-image` with the containerd image store
# of Docker (kind issue 3795).
docker buildx build -q --load --provenance=false --sbom=false --platform "linux/${ARCH}" \
  -t "${IMAGE}" -f "${REPO_ROOT}/deploy/kubernetes/Dockerfile" "${CTX}" >/dev/null

if [[ "${PUSH}" == true ]]; then
  docker push "${IMAGE}"
fi
if [[ -n "${KIND_CLUSTER}" ]]; then
  kind load docker-image "${IMAGE}" --name "${KIND_CLUSTER}" >&2
fi
echo "Built ${IMAGE} (linux/${ARCH})" >&2
