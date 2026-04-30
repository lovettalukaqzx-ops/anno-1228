#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

recv_log="${1:-6}"
send_log="${2:-6}"
block_size="${3:-512}"
port="${4:-12346}"

ensure_binary "hepsi-1" "PSI"
bin="$(binary_path "hepsi-1" "PSI")"

echo "Running HE-based-1 PSI: receiver=2^${recv_log}, sender=2^${send_log}, block=${block_size}, port=${port}"
"${bin}" "${recv_log}" "${send_log}" "${block_size}" "${port}"
