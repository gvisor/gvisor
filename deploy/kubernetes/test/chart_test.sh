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

# Tests the gvisor-deploy chart templates. Needs helm; does not need a
# cluster.

set -euo pipefail

CHART="$(cd "$(dirname "${BASH_SOURCE[0]}")/../chart/gvisor-deploy" && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }

render() { helm template t "${CHART}" "$@"; }

# expect_images <rendered> <image> <pull policy> [count]
#
# count is the number of pods that use the image: the DaemonSet and the
# cleanup Job by default.
expect_images() {
  local out="$1" image="$2" policy="$3" count="${4:-2}"
  [[ "$(sed 's/^ *//' <<<"${out}" | grep -cxF "image: ${image}")" == "${count}" ]] ||
    fail "want image ${image} ${count} times"
  [[ "$(sed 's/^ *//' <<<"${out}" | grep -cxF "imagePullPolicy: ${policy}")" == "${count}" ]] ||
    fail "want imagePullPolicy ${policy} ${count} times"
}

helm lint "${CHART}" >/dev/null || fail "helm lint"

app_version="$(sed -n 's/^appVersion: "\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "${CHART}/Chart.yaml")"
[[ -n "${app_version}" ]] || fail "no appVersion in Chart.yaml"

IMAGE=ghcr.io/gvisor/gvisor-installer

# The default repository is the one that the release workflow pushes.
WORKFLOW="$(dirname "${CHART}")/../../../.github/workflows/gvisor_deploy.yml"
grep -qx "      IMAGE: ${IMAGE}" "${WORKFLOW}" || fail "the release workflow does not push ${IMAGE}"
grep -qx "  repository: ${IMAGE}" "${CHART}/values.yaml" || fail "image.repository is not ${IMAGE}"

# Defaults: the tag from appVersion ("latest" in the repository), which is
# pulled each time.
[[ "${app_version}" == latest ]] || fail "appVersion is ${app_version}, want latest"
expect_images "$(render)" "${IMAGE}:latest" Always
expect_images "$(render --set-string image.tag=)" "${IMAGE}:latest" Always

# A published chart, packaged as the release workflow does: the release is
# the tag, which is pulled only if it is not present.
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
helm package "${CHART}" --version 20261116.0.0 --app-version 20261116.0 -d "${tmp}" >/dev/null
expect_images "$(helm template t "${tmp}/gvisor-deploy-20261116.0.0.tgz")" "${IMAGE}:20261116.0" IfNotPresent
expect_images "$(helm template t "${tmp}/gvisor-deploy-20261116.0.0.tgz" --set-string image.tag=latest)" "${IMAGE}:latest" Always

# Without the cleanup Job, only the DaemonSet uses the image.
expect_images "$(render --set cleanupOnUninstall=false)" "${IMAGE}:latest" Always 1

# Overrides.
expect_images "$(render --set image.repository=r/i --set-string image.tag=dev --set image.pullPolicy=Never)" "r/i:dev" Never
# An explicit pull policy wins over the "latest" rule.
expect_images "$(render --set image.pullPolicy=IfNotPresent)" "${IMAGE}:latest" IfNotPresent
# A numeric tag stays a string.
expect_images "$(render --set image.repository=r/i --set-string image.tag=20261121092102)" "r/i:20261121092102" IfNotPresent
expect_images "$(render --set image.repository=r/i --set image.tag=20261121092102)" "r/i:20261121092102" IfNotPresent

# daemonset and job print the DaemonSet and the cleanup Job of a render.
daemonset() { sed -n '/^kind: DaemonSet$/,/^---$/p' <<<"$1"; }
job() { sed -n '/^kind: Job$/,$p' <<<"$1"; }

# The DaemonSet and the cleanup Job run only on Linux amd64 and arm64 nodes
# (the architectures of the published image), by default on all of them.
want_affinity='affinity:
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/os
              operator: In
              values: ["linux"]
            - key: kubernetes.io/arch
              operator: In
              values: ["amd64", "arm64"]'
out="$(render)"
for part in "$(daemonset "${out}")" "$(job "${out}")"; do
  got="$(grep -A10 '^ *affinity:$' <<<"${part}" | sed 's/^      //')"
  [[ "${got}" == "${want_affinity}" ]] || fail "unexpected affinity: ${got}"
  ! grep -q '^ *nodeSelector:$' <<<"${part}" || fail "default render has a nodeSelector"
done

# nodeSelector applies to the DaemonSet. The cleanup Job takes only the
# architecture from it, so it runs where a single-architecture image can run,
# and tolerates the same taints as the DaemonSet, so it can run when the
# selected nodes are a tainted pool.
out="$(render --set nodeSelector.pool=sandbox --set 'nodeSelector.kubernetes\.io/arch=arm64')"
grep -qF 'pool: sandbox' <<<"$(daemonset "${out}")" || fail "DaemonSet does not use nodeSelector"
! grep -qF 'pool: sandbox' <<<"$(job "${out}")" || fail "cleanup Job uses all of nodeSelector"
grep -qF 'kubernetes.io/arch: "arm64"' <<<"$(job "${out}")" || fail "cleanup Job has no architecture selector"
grep -qF 'operator: Exists' <<<"$(job "${out}")" || fail "cleanup Job has no tolerations"
render --set nodeSelector=null >/dev/null || fail "nodeSelector=null does not render"

# The RuntimeClass schedules pods only on nodes where the install finished.
out="$(render)"
grep -q "^handler: runsc$" <<<"${out}" || fail "want RuntimeClass handler runsc"
grep -q "gvisor.dev/runsc: installed" <<<"${out}" || fail "want RuntimeClass node selector"
[[ "$(render --set runtimeClass.create=false | grep -c '^kind: RuntimeClass$' || true)" == 0 ]] ||
  fail "runtimeClass.create=false still renders a RuntimeClass"

# Invalid handler names fail at render time.
if render --set runtimeHandler='bad name' >/dev/null 2>&1; then
  fail "invalid runtimeHandler accepted"
fi

echo PASS
