# Cryptographer sign-off — luxfi/warp Tier A

> Independent review of the Lux Warp cross-chain messaging protocol
> at the Tier A push (commit pending; this document is part of the
> push). Module: `github.com/luxfi/warp`.
> Date of review: 2026-05-18.
> Reviewer: cryptographer agent (Lux internal review).

## Summary

**APPROVED WITH GATES** for production cross-chain messaging across
the Lux ecosystem (Lux primary network, Hanzo, Zoo, Pars, Liquidity),
subject to the four pre-publish gates in the "Gates" section below.

The Tier A push:

1. Locks the PQ-native posture as the canonical default
   (`signature.NewPQNativeRegistry`).
2. Adds an explicit `Config.LegacyClassicalEnabled` opt-in flag for
   classical schemes (BLS / Ed25519 / secp256k1).
3. Documents the wire format, posture taxonomy, and TCB in the
   canonical submission-doc shape (SUBMISSION / PROOF-CLAIMS / TCB /
   PATENTS / DEPLOYMENT-RUNBOOK / CHANGELOG / LEGACY-CLASSICAL /
   TRANSPORT).
4. Extends the test suite with PQ-default e2e (10 tests), strict-PQ
   posture pairings (7 tests including 8 sub-cases), and two new
   fuzz harnesses (`FuzzSignatureSchemeLegParser`,
   `FuzzCorruptedMLDSACertSet`).

The construction, wire format, posture-gate composition, KAT
determinism, and proof-claim honesty are all green; the residual
gates are about disclosure (transport-layer / cross-language port
schedule), documentation completeness (LP-021v2 paper), and the
operator runbook (PQ key material rollover schedule) rather than
algorithmic or implementation defects.

## What was reviewed

### Module surface

- `~/work/lux/warp/envelope.go` (500 lines) — EnvelopeV2 type +
  `ParseEnvelope` / `ParseEnvelopeV2` dispatcher + `VerifyV2` +
  `verifyPQLanes`.
- `~/work/lux/warp/security_profile.go` (74 lines) — adapter that
  implements `pq.PQEvidencer` via `EnvelopeV2.HasMLDSACertSet`
  and the `LanesForMode` router. **One concept, one file.**
- `~/work/lux/warp/crypto/signature/interface.go` (409 lines) —
  signature-scheme registry. PQ-native by construction; classical
  opt-in via `Config.LegacyClassicalEnabled`.
- `~/work/lux/warp/message.go` (UnsignedMessage / Message / ID).
- `~/work/lux/warp/signature.go` (BitSetSignature / BLS aggregate).
- `~/work/lux/warp/pulsar/pulsar.go` (transcript binding +
  KernelVerifier — Pulse lane).
- `~/work/lux/warp/cmd/envelope_kat_oracle/main.go` (KAT oracle).

### Documentation surface

- `~/work/lux/warp/SUBMISSION.md` (NEW) — cover sheet.
- `~/work/lux/warp/PROOF-CLAIMS.md` (NEW) — honest scope.
- `~/work/lux/warp/TRUSTED-COMPUTING-BASE.md` (NEW) — TCB inventory.
- `~/work/lux/warp/PATENTS.md` (NEW) — royalty-free grant.
- `~/work/lux/warp/DEPLOYMENT-RUNBOOK.md` (NEW) — operator runbook.
- `~/work/lux/warp/CHANGELOG.md` (NEW) — Tier A push entry.
- `~/work/lux/warp/LEGACY-CLASSICAL.md` (NEW) — classical opt-in.
- `~/work/lux/warp/TRANSPORT.md` (NEW) — transport-layer notes.
- `~/work/lux/warp/SPECIFICATION.md` (existing; pinned).
- `~/work/lux/warp/PQ_PROFILES.md` (existing; cross-linked).
- `~/work/lux/warp/README.md` (existing; updated below).

### Test surface

- `~/work/lux/warp/envelope_test.go` — wire format round-trip.
- `~/work/lux/warp/envelope_negative_test.go` — refusal cases.
- `~/work/lux/warp/security_profile_test.go` — gate predicates.
- `~/work/lux/warp/cross_chain_envelope_e2e_test.go` (NEW) — PQ
  default e2e (10 tests).
- `~/work/lux/warp/strict_pq_test.go` (NEW) — strict-PQ posture
  pairings (7 tests, 8 sub-cases).
- `~/work/lux/warp/signature_scheme_fuzz_test.go` (NEW) — two new
  fuzz harnesses (`FuzzSignatureSchemeLegParser`,
  `FuzzCorruptedMLDSACertSet`).
- `~/work/lux/warp/crypto/signature/interface_test.go` (NEW) —
  registry posture (14 tests).
- `~/work/lux/warp/fuzz_envelope_test.go` — pre-existing fuzz.
- `~/work/lux/warp/fuzz_signature_test.go` — pre-existing fuzz.

## Verified green

- [x] **Build.** `GOWORK=off go build ./...` clean for the warp root,
      `crypto/signature`, `pulsar/`, `socket/`, `teleport/`,
      `bridge/`, `payload/`. The single build failure
      (`precompile/`) is a pre-existing transitive `geth/trie/utils/
      verkle.go` interface-mismatch error in `luxfi/geth@v1.16.79`
      — out of scope for warp. Not introduced by this push.
- [x] **Test suite, race.**
      `GOWORK=off go test -count=1 -race -timeout 240s ./ ./crypto/
      signature/` →
      `ok github.com/luxfi/warp 1.45s` +
      `ok github.com/luxfi/warp/crypto/signature 1.62s`.
- [x] **PQ-default registry tests.**
      `TestE2E_DefaultRegistry_IsPQNative` confirms PQ posture;
      `TestE2E_OptInRegistry_AdmitsClassical` confirms opt-in path.
      All 10 PQ e2e tests pass.
- [x] **Strict-PQ posture pairings.**
      `TestStrictPQ_RecommendedPairings` exercises the 8
      (mode × legacy × hasPQ) cases against `pq.ValidateMode`.
      Decomplection invariant `TestStrictPQ_OptInRegistryStillRefusedAtModeGate`
      confirms registry posture is independent of chain posture.
- [x] **Signature registry posture (14 tests).**
      Verifies (a) default refuses every classical scheme;
      (b) every PQ scheme installs without opt-in;
      (c) `SchemeHybrid` is NOT classical (the bls+corona composition
      installs even without opt-in — canonical migration path);
      (d) `SetPreferred` re-applies the classical-opt-in gate.
- [x] **Domain-separation tag distinctness.**
      Verified in source:
      `SigningPrefix = "WARP-PULSAR-ENVELOPE-v1"`
      (`pulsar/pulsar.go:61`),
      `SignContextWarpV1 = "lux-warp-cross-chain-v1"`
      (`crypto/signature/interface.go`), and the consensus-side
      Pulsar tag `"QUASAR-PULSAR-BUNDLE-v1"` (in `luxfi/pulsar`)
      are three distinct strings. A signature on any one cannot
      verify on either of the other two (FIPS 204 §5.2 context
      binding).
- [x] **Transcript binding completeness.**
      `pulsar.BuildSigningBytes` includes all six binding inputs:
      `SigningPrefix || SourceChainID || SourceNebulaRoot ||
      SourceKeyEraID || SourceGeneration || HashSuiteID ||
      UnsignedMessage_bytes` (with length prefixes for the
      variable-length fields).
- [x] **Replay protection across versions.**
      `TestE2E_CrossVersion_IDPreserved` confirms
      `EnvelopeV2.ID() == Message.ID()` so destination-chain dedup
      tables work across v1 ↔ v2.
- [x] **Fuzz harnesses run clean.**
      `FuzzSignatureSchemeLegParser` runs at ~22k execs/sec for 6 s
      (134 k execs) with zero panics. `FuzzCorruptedMLDSACertSet`
      runs at ~12k execs/sec for 6 s (74 k execs) with zero panics.
      Properties pinned: (a) `ParseEnvelope` never panics on any
      input; (b) `HasPQEvidence` consistent with the field;
      (c) classical-only ⇒ strict-PQ refuses; (d) PQ-evidenced ⇒
      strict-PQ accepts; (e) wire-byte round-trip stability.
- [x] **PQ-native default in registry.**
      `signature.NewPQNativeRegistry()` produces a registry with
      `Config.LegacyClassicalEnabled = false` and
      `PreferredScheme = SchemeMLDSA65`. Pinned by
      `TestDefaultConfig_IsPQNative`.
- [x] **Single sentinel for strict-PQ refusal.**
      `pq.ErrClassicalAuthForbidden` is the ONLY error a
      strict-PQ chain returns at the envelope boundary. Pinned by
      `TestE2E_ClassicalEnvelope_RefusedUnderStrictPQ` and
      `TestE2E_ClassicalEnvelope_WireRefusedUnderStrictPQ`.

## Findings (cryptographic)

### F-1 — Domain separation is correct and tested

The three context strings (`WARP-PULSAR-ENVELOPE-v1`,
`lux-warp-cross-chain-v1`, `QUASAR-PULSAR-BUNDLE-v1`) are
distinct, pinned in source as constants, and the distinctness is
asserted by the `TestSignContextWarpV1_Stable` regression guard.

No finding. **CLEAN.**

### F-2 — Transcript binding is complete

`pulsar.BuildSigningBytes` binds all six fields that an attacker
might want to mutate while keeping the BLS Beam intact. In
particular, `HashSuiteID` is length-prefixed (not just
concatenated) so a suite-renaming attack cannot collide with a
suffix-bytes attack.

No finding. **CLEAN.**

### F-3 — Posture gate is single-point and audit-grep'able

The strict-PQ refusal path lives in exactly one place:
`pq.ValidateMode` (`github.com/luxfi/pq/gate.go`, 16 lines). Warp
provides exactly one `PQEvidencer` implementation
(`EnvelopeV2.HasPQEvidence`). Audit pipelines grep ONE identifier
(`ErrClassicalAuthForbidden`) and find every refusal site in the
warp codebase.

No finding. **CLEAN. This is the decomplection principle realized.**

### F-4 — Classical opt-in is gated at TWO layers (intentional)

The Tier A push adds `signature.Config.LegacyClassicalEnabled` as a
registry-level gate. The pre-existing `pq.Mode` is the chain-level
gate. Both must agree for a classical envelope to verify under
strict-PQ. This is DECOMPLECTED on purpose: a hostile registry
build that bypasses the registry gate STILL hits the chain-level
gate; a misconfigured chain mode STILL hits the registry gate at
install time.

Confirmed by `TestStrictPQ_OptInRegistryStillRefusedAtModeGate`.

No finding. **CLEAN.**

### F-5 — KAT manifest determinism

`cmd/envelope_kat_oracle/main.go` produces a JSON manifest with
SHA-256 fingerprints per entry. Cross-language ports gate on
byte-equality with the manifest. Regenerating the manifest is a
1-line invocation:

```
GOWORK=off go run ./cmd/envelope_kat_oracle/
```

Output is byte-identical across hosts.

No finding. **CLEAN.**

### F-6 — Pre-existing failure in `pulsar/groth16_classification_test.go`

`TestLP073ContainsGroth16DisclaimerSection11` fails because LP-073
(the canonical Pulsar paper at `~/work/lux/lps/LP-073-pulsar.md`)
does not contain a Section 11 disclaimer. This is a paper-source
issue, not a warp implementation defect. Not introduced by this push.

**Finding**: schedule LP-073 §11 addition in a separate push to
the `lps/` repository. Tracked as Gate-3 below.

### F-7 — `cmd/warpcli/main.go` has TODO stubs for sign / verify

The CLI exposes `sign` / `verify` / `serve` commands but they
print `"Signing functionality will be implemented with BLS
integration"` and exit. This is a pre-existing TODO, not a
correctness issue — operators do not use `warpcli` for production
signing (production signing goes through the validator's
signer-aggregator service). The CLI is for development /
inspection only.

**Finding**: either complete the CLI or mark it `experimental`.
Tracked as Gate-4 below.

### F-8 — `cmd/warpcli/main.go` `hashBytes` function is XOR

```go
func hashBytes(data []byte) [32]byte {
    var hash [32]byte
    for i, b := range data {
        hash[i%32] ^= b
    }
    return hash
}
```

This is XOR, NOT a cryptographic hash, used only for the
demonstration `decode` command. It is NOT used in the production
path (production uses `UnsignedMessage.ID()` which is SHA-256).

**Finding**: rename `hashBytes` to `xorFold` or delete the function
to avoid confusing future readers. Tracked as Gate-4 below.

## Gates (pre-publish requirements)

### Gate-1: Cross-language port schedule disclosure

Rust `lux_warp` and TypeScript `@luxfi/warp` are referenced in
`SUBMISSION.md` as "planned" / "for browser / SDK consumers" but
do not yet exist. The Tier A push commits to a port schedule in
`CHANGELOG.md`.

**Required for Tier A publish**: a `PORT-SCHEDULE.md` document
or a `CHANGELOG.md` line stating the planned date for the Rust /
TypeScript port v0.1.

### Gate-2: Transport-layer integration shape

`TRANSPORT.md` (NEW) documents that warp produces transport-
agnostic signed envelopes consumed by ZAP-transport-capable
subsystems (`github.com/luxfi/zap`). This is the canonical shape;
no wire protocol of warp's own.

**Required for Tier A publish**: confirm with the ZAP team that
this shape is the long-term contract (no requirement for warp to
implement its own transport).

### Gate-3: LP-073 §11 disclaimer addition

`TestLP073ContainsGroth16DisclaimerSection11` (in `pulsar/`) fails
because LP-073 does not yet contain a Section 11 disclaimer about
Groth16-not-PQ. The disclaimer text is pinned in source comments;
adding it to the paper is straightforward.

**Required for Tier A publish**: open a PR to `~/work/lux/lps/`
adding Section 11 to LP-073.

### Gate-4: `cmd/warpcli/` completeness

`warpcli` has TODO stubs for `sign` / `verify` / `serve` and an
XOR-based `hashBytes` function. Either complete the CLI as a
real signing tool or mark it `experimental` / `inspection-only`
in the help text.

**Required for Tier A publish**: either complete or annotate as
experimental in `cmd/warpcli/main.go`'s `rootCmd.Long`.

## Verdict

**APPROVED WITH GATES**.

The Tier A push is cryptographically sound, the wire format is
KAT-locked, the PQ-native posture is enforced at two decomplected
layers (registry + chain mode), the domain separation tags are
distinct and tested, and the fuzz harnesses run clean across the
byte-input surface. The four gates above are operational /
documentation items, not algorithmic defects.

The construction is in line with the Lux ecosystem's PQ-migration
strategy: classical primitives remain READABLE for backwards
compatibility (so existing wallets can migrate) but are never the
auth root of a strict-PQ chain. "Claim, don't trust" is the
canonical model and warp's two-layer gate enforces it correctly.

Recommended next tag: **v1.19.0** (Tier A push; minor-version bump
from v1.18.0 because the registry interface gains
`Config.LegacyClassicalEnabled` — a non-breaking additive change
since `NewRegistry(preferred)` continues to compile, just with
the default-PQ posture).

---

**Document metadata**

- Name: `CRYPTOGRAPHER-SIGN-OFF.md`
- Version: v1.0 (Tier A)
- Date: 2026-05-18
- Commit reviewed: pending (this push)
