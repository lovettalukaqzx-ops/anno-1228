#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

recv_log="${1:-6}"
send_log="${2:-6}"
block_size="${3:-512}"
port="${4:-12347}"
exe="${5:-PSI_v}"

ensure_binary "hepsi-2" "${exe}"
bin="$(binary_path "hepsi-2" "${exe}")"

echo "Running HE-based-2 PSI (${exe}): receiver=2^${recv_log}, sender=2^${send_log}, block=${block_size}, port=${port}"
"${bin}" "${recv_log}" "${send_log}" "${block_size}" "${port}"
