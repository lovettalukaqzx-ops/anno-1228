#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

ensure_binary "hepsi-1" "PSI_batch_stats"
cd "${ROOT_DIR}/hepsi-1/${BUILD_DIR_NAME}"

if [[ ${EUID} -ne 0 ]]; then
  echo "LAN/WAN emulation uses tc on loopback and may ask for sudo." >&2
fi

sudo tc qdisc del dev lo root 2>/dev/null || true
cleanup() {
  sudo tc qdisc del dev lo root 2>/dev/null || true
}
trap cleanup EXIT

sudo tc qdisc replace dev lo root handle 1: htb default 10
sudo tc class replace dev lo parent 1: classid 1:10 htb rate 400mbit ceil 400mbit
sudo tc qdisc replace dev lo parent 1:10 handle 10: netem delay 40ms

./PSI_batch_stats "$@"
