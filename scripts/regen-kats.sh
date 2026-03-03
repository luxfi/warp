#!/usr/bin/env bash
# regen-kats.sh — deterministic regeneration + verification of every
# Warp 2.0 envelope KAT consumed by cross-language ports.
#
# Outputs:
#   scripts/kat/envelope_kat.json   — RLP-framed EnvelopeV2 vectors
#                                     (4 entries spanning Pulse/Cert
#                                     presence × signer-set sizes)
#
# Also runs the in-tree envelope tests so a ports change that breaks
# the v1↔v2 round-trip surfaces in the same script the manifest does.

set -euo pipefail

WARP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KAT_DIR="${WARP_DIR}/scripts/kat"
MANIFEST="${WARP_DIR}/scripts/regen-kats.manifest.sha256"

VERIFY=0
if [[ "${1:-}" == "--verify" ]]; then
  VERIFY=1
fi

cd "${WARP_DIR}"
mkdir -p "${KAT_DIR}"

echo "[1/3] envelope_kat_oracle → ${KAT_DIR}/envelope_kat.json"
WARP_ENVELOPE_KAT_PATH="${KAT_DIR}/envelope_kat.json" \
  go run ./cmd/envelope_kat_oracle >/dev/null

echo "[2/3] in-tree envelope round-trip tests"
go test -count=1 -run "TestEnvelopeV2" ./ >/dev/null

echo "[3/3] in-tree warp/pulsar threshold tests"
go test -count=1 ./pulsar >/dev/null

# Build sha256 manifest deterministically.
TMP_MANIFEST="$(mktemp)"
trap 'rm -f "${TMP_MANIFEST}"' EXIT

find "${KAT_DIR}" -maxdepth 1 -name "*.json" -type f | sort | while read -r f; do
  rel="${f#${WARP_DIR}/}"
  shasum -a 256 "$f" | awk -v p="${rel}" '{print $1"  "p}'
done > "${TMP_MANIFEST}"

if [[ "${VERIFY}" == "1" ]]; then
  if [[ ! -f "${MANIFEST}" ]]; then
    echo "ERROR: --verify requested but no prior manifest at ${MANIFEST}"
    exit 2
  fi
  if ! diff -u "${MANIFEST}" "${TMP_MANIFEST}"; then
    echo "FAIL: manifest mismatch — Warp KAT regeneration is non-deterministic" >&2
    exit 3
  fi
  echo "OK: Warp KAT regeneration is byte-equal across runs ($(wc -l < "${MANIFEST}") files)"
else
  cp "${TMP_MANIFEST}" "${MANIFEST}"
  echo "wrote manifest: ${MANIFEST}"
  cat "${MANIFEST}"
fi
