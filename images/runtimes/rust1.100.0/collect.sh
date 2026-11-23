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

# Copies the test binaries that cargo built in the cargo build directory
# $1 to $2/libtest (binaries that use the libtest harness) and $2/standalone
# (binaries that do not). Each binary is named after its crate, and after its
# target if it is an integration test or a benchmark. Benchmark binaries that
# do not use libtest only measure performance, so they are not copied.
#
# The script depends on the layout of the cargo build directory and on the
# format of the cargo dependency files of the pinned Rust version. It fails if
# it finds a test binary that it cannot name, or no libtest binary.

set -euo pipefail

build_dir="$1"
out_dir="$2"
mkdir -p "${out_dir}/libtest" "${out_dir}/standalone"

for dep in "${build_dir}"/*/*/out/*.d; do
  bin="${dep%.d}"
  if [[ ! -f "${bin}" || ! -x "${bin}" ]]; then
    continue
  fi
  crate="$(basename "$(dirname "$(dirname "$(dirname "${dep}")")")")"
  target="$(basename "${bin}")"
  target="${target%-*}"
  # The first prerequisite in the dependency file is the root source file.
  src="$(sed -n '1s/^[^:]*: *\([^ ]*\).*/\1/p' "${dep}")"
  # Make relative paths start with "/", so that one pattern matches both forms.
  src="/${src#/}"
  case "${src}" in
    */${crate}/tests/* | */${crate}/benches/*) name="${crate}-${target}" ;;
    */${crate}/lib.rs | */${crate}/src/lib.rs) name="${crate}" ;;
    *) echo "unknown test root ${src} for ${bin}" >&2; exit 1 ;;
  esac
  # Every libtest binary has the help text of the --include-ignored flag.
  if grep -q -a -F "Run ignored and not ignored tests" "${bin}"; then
    dest="${out_dir}/libtest/${name}"
  elif [[ "${src}" == */${crate}/benches/* ]]; then
    continue
  else
    dest="${out_dir}/standalone/${name}"
  fi
  if [[ -e "${out_dir}/libtest/${name}" || -e "${out_dir}/standalone/${name}" ]]; then
    echo "duplicate test binary name ${name} for ${bin}" >&2
    exit 1
  fi
  cp "${bin}" "${dest}"
done

if [[ -z "$(ls -A "${out_dir}/libtest")" ]]; then
  echo "no libtest binaries in ${build_dir}" >&2
  exit 1
fi
