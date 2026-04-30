#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

sender_log="${1:-0}"
receiver_log="${2:-20}"

ensure_binary "crx1/HEPSI-2" "PSI"
bin="$(binary_path "crx1/HEPSI-2" "PSI")"

echo "Running VOKVS-based RBOKVS PSI: sender=2^${sender_log}, receiver=2^${receiver_log}"
printf '%s\n%s\n' "${sender_log}" "${receiver_log}" | "${bin}"
