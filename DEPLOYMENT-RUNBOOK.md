# DEPLOYMENT-RUNBOOK — Operator-Facing

> Operational guide for deploying Lux Warp 2.0 as the cross-chain
> messaging layer of a chain in the Lux ecosystem. Companion to
> `SUBMISSION.md`, `PQ_PROFILES.md`, and `LEGACY-CLASSICAL.md`.

## 1. Decisions every operator makes

### 1.1 Pick a PQ posture (`pq.Mode`)

| Mode | When |
|---|---|
| `classical` | Legacy chain with no ML-DSA validator material yet generated. **Discouraged** for new deployments. |
| `hybrid` | Migration middle. Chain validators sign both BLS Beam AND MLDSACertSet; verifier accepts either path. **Default for non-strict-PQ Lux primary network deployments.** |
| `strict-pq` | Pure post-quantum. Classical envelopes refused at the verifier boundary. **Canonical default for strict Lux + Zoo deployments.** |

The posture is pinned at **genesis** of the destination chain and
flipped only by a hard fork (never at runtime). Pin it in the
chain config under `warpProfile` (string field, one of
`classical` / `hybrid` / `strict-pq`).

### 1.2 Decide whether to enable classical primitives

If the chain is `classical` or `hybrid`, set
`Config.LegacyClassicalEnabled = true` when constructing the
warp signature registry:

```go
import "github.com/luxfi/warp/crypto/signature"

cfg := signature.Config{
    LegacyClassicalEnabled: true, // hybrid/classical only
    PreferredScheme:        signature.SchemeMLDSA65,
}
reg := signature.NewRegistryFromConfig(cfg)
```

If the chain is `strict-pq`, use the canonical default:

```go
reg := signature.NewPQNativeRegistry()
```

See `LEGACY-CLASSICAL.md` for the policy.

### 1.3 Decide which lanes the chain produces

A source-chain validator can produce up to three lanes per envelope:

- **Beam** (BLS aggregate) — always produced (the v1 Message lives
  inside the EnvelopeV2 carrier even on strict-PQ chains; the
  bytes are "echo only" under strict-PQ).
- **Pulse** (Pulsar / Corona R-LWE threshold) — produced when the
  source chain runs the Pulsar consensus protocol.
- **MLDSACertSet** (FIPS 204 ML-DSA-65 per-validator attestations)
  — produced when each validator has ML-DSA-65 key material
  loaded.

For a strict-PQ destination, the source chain MUST produce at
least the MLDSACertSet lane. Operators of source chains preparing
to send messages to strict-PQ destinations MUST ensure their
validators have ML-DSA-65 keys provisioned. See §3 below for the
key-material rollout schedule.

## 2. Boot-time configuration

### 2.1 Chain config

Add the following to the destination chain's config JSON:

```json
{
  "warpProfile": "strict-pq",
  "warpVerifier": {
    "requireMLDSACertSet": true,
    "requirePulse": false,
    "hashSuiteID": "Pulsar-SHA3"
  }
}
```

| Field | Meaning |
|---|---|
| `warpProfile` | `"classical"` / `"hybrid"` / `"strict-pq"` |
| `requireMLDSACertSet` | If true, envelope is refused without an MLDSACertSet lane |
| `requirePulse` | If true, envelope is refused without a Pulsar Pulse lane |
| `hashSuiteID` | Pinned hash suite; default `"Pulsar-SHA3"` if empty |

On strict-PQ chains, `requireMLDSACertSet=true` is recommended.
On hybrid chains, leave both Require* false — the verifier
accepts either path.

### 2.2 Validator-set registry

The destination chain MUST know the source chain's validator set
to verify the Beam, plus the source chain's Pulsar GroupKey lineage
to verify the Pulse, plus the source chain's per-validator
ML-DSA-65 public keys to verify the MLDSACertSet.

These come from one of:

1. **TOFU snapshot** at chain genesis (acceptable for low-trust
   bridges).
2. **On-chain registry contract** that records the source chain's
   key material lineage over time (recommended for production).
3. **External authority** (e.g. a notary chain) that signs over
   the source's current validator set.

The `pulsar.GroupKeyResolver` interface lets the destination chain
implement any of these models. See `pulsar/pulsar.go:91` for the
interface contract.

### 2.3 Hash-suite consistency

Both source and destination MUST agree on the hash suite. The
canonical default is `"Pulsar-SHA3"`. A source that signs under
`"Pulsar-SHAKE"` must NOT be paired with a destination expecting
`"Pulsar-SHA3"` — the Pulse will verify-reject with
`ErrSuiteMismatch`.

Operators check the agreed suite in the chain config and in the
source-chain's validator-set registry. Mismatches surface at chain
boot, not at runtime.

## 3. Key material rollout

### 3.1 ML-DSA-65 validator keys

Per-validator ML-DSA-65 keys are required for MLDSACertSet
production. Generate via the validator's key-management service
(`~/work/lux/kms` or operator's HSM):

```
lux-kms keygen --scheme ml-dsa-65 --validator-id <node-id>
```

Public key registration on the destination chain's registry uses
the same flow as BLS public key registration today.

### 3.2 Pulsar threshold shares

A source chain producing the Pulse lane must run the Pulsar DKG
ceremony at genesis (or as a Reanchor event for existing chains).
See `~/work/lux/pulsar/DEPLOYMENT-RUNBOOK.md` for the DKG
procedure.

### 3.3 Key rotation schedule

Rotate per-validator ML-DSA-65 keys on the same schedule as BLS
keys (every N epochs). The Pulsar GroupKey rotates via a Reshare
ceremony at a slower cadence (proactive secret sharing over
committee changes).

The destination chain's registry contract tracks each key era's
validity window; old envelopes signed under the previous era still
verify because the era ID is bound into the transcript.

## 4. Production checklist

Before a chain goes live on a strict-PQ profile:

- [ ] `warpProfile: "strict-pq"` in chain config.
- [ ] `requireMLDSACertSet: true` in chain config.
- [ ] Source-chain validator set registered on destination.
- [ ] Source-chain GroupKey lineage registered on destination.
- [ ] Per-validator ML-DSA-65 public keys registered on destination.
- [ ] `hashSuiteID` agreed between source and destination
      (default `"Pulsar-SHA3"`).
- [ ] Signature registry uses `signature.NewPQNativeRegistry()`
      (NOT `NewRegistry()` with classical schemes wired in).
- [ ] Validator's key-management service can produce ML-DSA-65
      signatures over the warp envelope transcript.
- [ ] Signature-aggregator service emits EnvelopeV2 bytes that
      pass `warp.ParseEnvelopeV2` + `pq.ValidateMode(strict-pq, env, verify)`.
- [ ] KAT regression test passes on the destination chain's
      verifier (run `cmd/envelope_kat_oracle/` and check the
      destination's parser agrees byte-for-byte).
- [ ] Transport layer carries envelope bytes verbatim (see
      `TRANSPORT.md`).

## 5. Common failure modes

### 5.1 `signature.ErrClassicalRequiresOptIn` at chain boot

Cause: chain is `classical` or `hybrid` but boot code calls
`signature.NewPQNativeRegistry()` and tries to register a
classical scheme.

Fix: switch to `signature.NewRegistryFromConfig(signature.Config
{LegacyClassicalEnabled: true})`.

### 5.2 `pq.ErrClassicalAuthForbidden` at envelope verification

Cause: chain is `strict-pq` but the envelope arrived without an
MLDSACertSet.

Fix: investigate the source chain — its validators may not have
ML-DSA-65 keys provisioned. Until they do, the source chain
cannot produce envelopes acceptable to the strict-PQ destination.
Short-term workaround: flip the destination to `hybrid` until
the source migration completes. Long-term: complete the source's
ML-DSA-65 key rollout.

### 5.3 `ErrSuiteMismatch` at Pulse verification

Cause: source signed under one hash suite, destination expected
another.

Fix: align the `hashSuiteID` field in both chains' configs.

### 5.4 `ErrEnvelopeTooLarge` at parse

Cause: envelope exceeds `MaxEnvelopeV2Size` (4 × 256 KiB = 1 MiB).

Fix: the source chain is producing an envelope with an unusually
large Pulse or MLDSACertSet. Investigate the validator set size
— with a very large committee, the MLDSACertSet grows linearly.
Consider Z-Chain Groth16 rollup (LP-307) to compress
verification cost (note: the rollup primitive is itself
classical — see `pulsar/classification.go`).

### 5.5 `ErrUnknownEnvelopeVersion` at parse

Cause: incoming bytes have a leading byte that is neither 0x02
(EnvelopeV2) nor an RLP-list prefix.

Fix: investigate the transport layer. The bytes have been
corrupted in transit or the source produced a non-standard
envelope. Compare against the KAT manifest in
`scripts/kat/envelope_kat.json`.

## 6. Monitoring

Metrics the operator should track:

| Metric | Alert threshold |
|---|---|
| `warp_envelope_verify_total{result="ok"}` | Steady-state baseline |
| `warp_envelope_verify_total{result="classical_refused"}` | Spike on strict-PQ chain ⇒ source not producing MLDSACertSet |
| `warp_envelope_verify_total{result="suite_mismatch"}` | Any non-zero ⇒ config drift |
| `warp_envelope_parse_errors_total` | Spike ⇒ transport corruption |
| `warp_pulse_verify_failures_total` | Any non-zero ⇒ source's Pulsar lineage may be unregistered |
| `warp_mldsa_certset_verify_failures_total` | Any non-zero ⇒ per-validator ML-DSA-65 key may be unregistered |

## 7. References

- `SUBMISSION.md` — cover sheet.
- `PROOF-CLAIMS.md` — honest scope.
- `TRUSTED-COMPUTING-BASE.md` — TCB.
- `SPECIFICATION.md` — wire format.
- `PQ_PROFILES.md` — posture taxonomy.
- `LEGACY-CLASSICAL.md` — classical opt-in policy.
- `TRANSPORT.md` — transport-layer notes.
- `CRYPTOGRAPHER-SIGN-OFF.md` — verdict + gates.

---

**Document metadata**

- Name: `DEPLOYMENT-RUNBOOK.md`
- Version: v1.0 (Tier A)
- Date: 2026-05-18
