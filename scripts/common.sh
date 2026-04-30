#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PRELIB_DIR="${ROOT_DIR}/crx1/preLibrary"
BUILD_DIR_NAME="${BUILD_DIR_NAME:-build-review}"

choose_cxx() {
  if [[ -n "${CXX:-}" ]]; then
    command -v "${CXX}" >/dev/null 2>&1 || {
      echo "CXX=${CXX} was requested but is not available." >&2
      exit 1
    }
    command -v "${CXX}"
    return
  fi

  for compiler in g++-12 g++-11 clang++; do
    if command -v "${compiler}" >/dev/null 2>&1; then
      command -v "${compiler}"
      return
    fi
  done

  echo "No C++20 compiler found. Please install g++-11 or newer." >&2
  exit 1
}

export CXX="$(choose_cxx)"
export LD_LIBRARY_PATH="${PRELIB_DIR}/lib:${LD_LIBRARY_PATH:-}"

build_protocol() {
  local rel="$1"
  local src="${ROOT_DIR}/${rel}"
  local build="${src}/${BUILD_DIR_NAME}"

  cmake -S "${src}" -B "${build}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER="${CXX}" \
    -DBUILD_TESTING=OFF \
    -DBINFUSE_TEST=OFF \
    -DBINFUSE_BENCH=OFF
  cmake --build "${build}" --parallel "${BUILD_JOBS:-$(nproc)}"
}

binary_path() {
  local rel="$1"
  local exe="${2:-PSI}"
  printf '%s/%s/%s/%s\n' "${ROOT_DIR}" "${rel}" "${BUILD_DIR_NAME}" "${exe}"
}

ensure_binary() {
  local rel="$1"
  local exe="${2:-PSI}"
  local bin
  bin="$(binary_path "${rel}" "${exe}")"
  if [[ ! -x "${bin}" ]]; then
    build_protocol "${rel}"
  fi
}
