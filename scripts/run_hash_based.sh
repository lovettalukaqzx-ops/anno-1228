#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

set_log="${1:-10}"
mode="${2:-vole}"
port="${3:-12345}"

ensure_binary "new" "PSI"
bin="$(binary_path "new" "PSI")"

echo "Running hash-based PSI: log2(n)=${set_log}, mode=${mode}, port=${port}"
"${bin}" "${set_log}" "${mode}" "${port}"
