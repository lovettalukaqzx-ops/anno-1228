#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "== Hash-based PSI smoke test =="
"${SCRIPT_DIR}/run_hash_based.sh" 10 vole 12445

echo
echo "== HE-based-1 smoke test =="
"${SCRIPT_DIR}/run_he_based_1.sh" 6 6 512 12446

echo
echo "== HE-based-2 smoke test =="
"${SCRIPT_DIR}/run_he_based_2.sh" 6 6 512 12447 PSI_v

echo
echo "== VOKVS PaXoS smoke test =="
"${SCRIPT_DIR}/run_vokvs_paxos.sh" 0 20

echo
echo "== VOKVS RBOKVS smoke test =="
"${SCRIPT_DIR}/run_vokvs_rbokvs.sh" 0 20

echo
echo "All smoke tests completed."
