#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

protocols=(
  "new"
  "hepsi-1"
  "hepsi-2"
  "crx1/HEPSI-1"
  "crx1/HEPSI-2"
)

echo "Repository: ${ROOT_DIR}"
echo "Compiler:   ${CXX}"
echo "Build dir:  ${BUILD_DIR_NAME}"

for protocol in "${protocols[@]}"; do
  echo
  echo "== Building ${protocol} =="
  build_protocol "${protocol}"
done

echo
echo "All reviewer protocol builds completed."
