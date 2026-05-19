# TRUSTED-COMPUTING-BASE — Warp 2.0 TCB Inventory

> **What you must trust below the warp implementation.**
> Companion document to `SUBMISSION.md`, `PROOF-CLAIMS.md`, and
> `CRYPTOGRAPHER-SIGN-OFF.md`.

The Warp 2.0 envelope soundness claim (`PROOF-CLAIMS.md` §1)
rests on three layered trust bases:

1. **Cryptographic primitives** — separately audited modules.
2. **Implementation TCB** — the runtime + standard library + build tooling.
3. **Operational TCB** — the operator's environment + key custody.

If any element of the TCB is compromised, warp's soundness claim is
unsound regardless of how well-implemented the envelope verifier is.

## §1 Cryptographic primitive TCB

| Primitive | Module | What you trust | Audit ref |
|---|---|---|---|
| BLS12-381 aggregate (Beam) | `github.com/luxfi/crypto/bls` | `supranational/blst` constant-time correctness; co-CDH hardness | blst upstream audit + LP-075 |
| ML-DSA-65 single-party | `github.com/luxfi/crypto/mldsa` (Cloudflare CIRCL backend) | NIST FIPS 204 spec text; CIRCL implementation correctness; MLWE / MSIS hardness | NIST FIPS 204 (August 2024) + CIRCL audit |
| SLH-DSA single-party | `github.com/luxfi/crypto/slhdsa` (Cloudflare CIRCL backend) | NIST FIPS 205 spec text; CIRCL implementation correctness; hash-function security | NIST FIPS 205 + CIRCL audit |
| Pulsar threshold (R-LWE) | `github.com/luxfi/pulsar` | Pulsar Class N1 byte-equality theorem; R-LWE / Ring-SIS hardness; jasmin-ct constant-time | `~/work/lux/pulsar/CRYPTOGRAPHER-SIGN-OFF.md` |
| Corona threshold (R-LWE) | `github.com/luxfi/corona` | Corona implementation correctness; R-LWE hardness; dudect constant-time | `~/work/lux/corona/CRYPTOGRAPHER-SIGN-OFF.md` |
| SHA-256 (envelope IDs) | `crypto/sha256` (Go stdlib) | Go stdlib SHA-256 correctness; standard SHA-256 second-preimage resistance | NIST FIPS 180-4 |
| SHA3-256 / Keccak (hash suite) | `crypto/sha3` (Go x/crypto) | Go x/crypto SHA-3 correctness; standard Keccak preimage resistance | NIST FIPS 202 |

## §2 Implementation TCB

| Layer | What you trust | Reproducibility |
|---|---|---|
| **Go toolchain** | Go 1.26.3 compiler + runtime; `crypto/rand` randomness quality | Version pinned in `go.mod` (`go 1.26.3`) |
| **`luxfi/geth/rlp`** | RLP encoder / decoder correctness; bounded recursion; refuses oversized inputs | go-ethereum upstream RLP; reviewed |
| **`luxfi/codec`** | Codec versioning + length-prefix correctness for v1 Message wire format | Reviewed; KAT-locked |
| **`luxfi/ids`** | 32-byte ID type + SHAKE-256 derivation | Reviewed; pinned by FIPS 202 |
| **`luxfi/log`** | Structured-log emission (no secret material) | Reviewed; warp emits only public envelope metadata |
| **`luxfi/pq`** | The single posture gate `pq.ValidateMode` + `pq.Mode` enum | This module; the entire gate is 16 lines (`gate.go`) |
| **`luxfi/lattice`** | R-LWE polynomial arithmetic backend for Pulse byte layout | Reviewed (`lattigo` fork) |

The implementation TCB is intentionally small. Warp's root package
imports no networking, no consensus, no chain state. The
verification path is a pure function of (envelope bytes,
validator-set snapshot, mode) → (nil | error).

## §3 Build TCB

| Layer | What you trust | Reproducibility |
|---|---|---|
| **`go.mod` dependency pins** | Every transitive dep is pinned by hash in `go.sum` | `GOWORK=off go mod verify` runs clean |
| **`scripts/kat/envelope_kat.json`** | KAT vectors regenerate deterministically from `cmd/envelope_kat_oracle/` | `GOWORK=off go run ./cmd/envelope_kat_oracle/` produces byte-identical JSON across hosts |
| **`Makefile`** | Build orchestrator's correctness — reproducible across hosts | Reviewed; no host-specific paths |
| **CI** | GitHub Actions runs the test suite + KAT regen on every PR | Pinned action versions in `.github/workflows/` |

## §4 Operational TCB

| Layer | What you trust | Mitigations |
|---|---|---|
| **Validator key custody** | Operator's HSM / KMS for BLS / ML-DSA / threshold-share material | Not warp's responsibility; operator runbook in `DEPLOYMENT-RUNBOOK.md` |
| **Source-chain validator set integrity** | Source chain's consensus protocol + slashing rules | Inherited from `luxfi/consensus`; out of scope for warp |
| **Destination-chain validator-set registry** | Destination chain's record of source-chain GroupKey lineage | Implemented as a contract; `pulsar.GroupKeyResolver` interface |
| **Time / timestamp source** | Source chain's wall-clock for replay-window decisions | Out of scope; warp's replay protection is content-addressed (`UnsignedMessage.ID()`) |
| **Network transport** | ZAP (or other transporter) integrity / authenticity guarantees | See `TRANSPORT.md`; ZAP carries warp envelopes verbatim |

## §5 Out-of-scope (NOT in the warp TCB)

| Item | Why excluded |
|---|---|
| **Bridge-quorum compromise** | A compromised source-chain validator set produces valid envelopes; warp can't detect that. Verifier's responsibility (TOFU / slashing / multi-source quorum). |
| **HSM / KMS provider correctness** | Operator's choice; outside the protocol. |
| **Operator OS kernel / CPU** | Standard for any cryptographic implementation. |
| **Network DDoS / partitioning** | Liveness, not soundness; warp is content-addressed and replay-safe regardless of network state. |
| **Compiler trust** ("Reflections on Trusting Trust") | Cannot be eliminated; partial mitigation via reproducible builds. |

## §6 TCB minimization principles

Warp's wire-format and posture-gate code is intentionally TCB-
minimizing:

1. **No background goroutines** in the verification path —
   verification is a pure function of input bytes.

2. **No mutable global state** in the warp root package —
   `EnvelopeV2` is a value type; the registry is constructed per
   caller; the posture gate is a stateless function.

3. **Single sentinel error** for the strict-PQ refusal
   (`pq.ErrClassicalAuthForbidden`) — audit pipelines grep ONE
   identifier across every refusal site.

4. **Domain-separation tags pinned in source** — three constants
   (`"WARP-PULSAR-ENVELOPE-v1"`, `"lux-warp-cross-chain-v1"`,
   `"QUASAR-PULSAR-BUNDLE-v1"`) live in three named-and-tested
   places; the tags are wire-stable across versions.

5. **Fuzz-tested decoders** — `FuzzWarpEnvelopeV2`,
   `FuzzSignatureSchemeLegParser`, `FuzzCorruptedMLDSACertSet`,
   and `FuzzBLSAggregateCert` exercise the byte-input surface.

6. **No reflection-driven serialization** — RLP framing is
   explicit (`EncodeRLP` / `DecodeRLP` methods) so the field
   count and order are wire-stable across Go reflection changes.

## §7 What an auditor mapping the warp TCB should do

1. **Verify** every primitive module in §1 has its own
   CRYPTOGRAPHER-SIGN-OFF.md (or equivalent audit ref). Warp
   inherits trust; it does not re-prove primitives.

2. **Verify** the implementation TCB §2 packages are at the exact
   versions pinned in `go.mod`. Re-run `GOWORK=off go mod verify`
   to confirm hash integrity.

3. **Regenerate** the KAT manifest §3 and diff byte-by-byte. Any
   drift indicates a build-tool divergence.

4. **Read** `DEPLOYMENT-RUNBOOK.md` for the operational TCB §4
   responsibilities. Confirm operators implement the runbook.

5. **Confirm** the §5 out-of-scope items are explicitly addressed
   by separate audits (bridge-quorum, HSM, etc.) before relying
   on warp for production traffic.

---

**Document metadata**

- Name: `TRUSTED-COMPUTING-BASE.md`
- Version: v1.0 (Tier A)
- Date: 2026-05-18
