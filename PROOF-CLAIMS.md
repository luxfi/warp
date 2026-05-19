# PROOF-CLAIMS — Warp 2.0 Envelope Soundness

> **What warp proves — and what it does NOT.**
> Companion document to `SUBMISSION.md` (cover sheet),
> `TRUSTED-COMPUTING-BASE.md` (TCB), `SPECIFICATION.md` (wire),
> `PQ_PROFILES.md` (posture taxonomy), and
> `CRYPTOGRAPHER-SIGN-OFF.md` (verdict + gates).
>
> Read this before reading the verifier code. The framing matters
> as much as the bytes.

## §1 The narrow claim

The strongest precise statement supported by the warp v2.0
implementation:

> **Warp 2.0 envelope soundness (operational).** Under the trusted-
> computing base in `TRUSTED-COMPUTING-BASE.md` and the residual
> assumptions enumerated in §3 below, every byte stream `b` for
> which `warp.ParseEnvelope(b)` returns `env, nil` AND
> `pq.ValidateMode(mode, env, verify)` returns `nil` for some
> non-`classical` `mode` carries cryptographic evidence that:
>
> 1. The source-chain validator set (at the time of signing)
>    attested to the embedded `UnsignedMessage` bytes, AND
> 2. The attestation binds to all six of: `SourceChainID`,
>    `SourceNebulaRoot`, `SourceKeyEraID`, `SourceGeneration`,
>    `HashSuiteID`, `UnsignedMessage.Bytes()`, AND
> 3. Under `mode == strict-pq`, the attestation is produced under
>    a NIST PQ-standardized algorithm (FIPS 204 ML-DSA-65) or a
>    Lux R-LWE threshold signature (Pulsar / Corona).

This is the **operational soundness** claim. It is implementation-
level (in the spirit of TLS 1.3 RFC 8446 §A — operational rules)
rather than reduction-level (in the spirit of Bellare-Rogaway
authenticated encryption). The corresponding reduction-level claim
(soundness in the random-oracle model + co-CDH assumption for BLS
+ MLWE/MSIS for ML-DSA + RLWE for Pulsar) inherits FROM the
primitive analyses (FIPS 204, FIPS 205, LP-073, LP-075).

## §2 What is established

| Aspect | Status |
|---|---|
| Wire format byte-stability across Go / Rust / TS | ✅ KAT manifest committed; cross-language ports gated on byte-equality |
| RLP encode / decode round-trip | ✅ `TestEnvelopeV2RoundTrip` + fuzzer (`FuzzWarpEnvelopeV2` ≥ 100k execs/run) |
| Cross-version dispatch (v1 ↔ v2) | ✅ `ParseEnvelope` accepts both; v1-lifted yields v2 with empty PQ lanes |
| Domain-separation tag distinctness | ✅ `WARP-PULSAR-ENVELOPE-v1` ≠ `QUASAR-PULSAR-BUNDLE-v1` ≠ `lux-warp-cross-chain-v1` |
| Transcript-binding completeness | ✅ All six fields go into `pulsar.BuildSigningBytes` |
| Posture gate's monotonicity | ✅ `pq.ValidateMode` returns the SAME error for all classical envelopes under strict-PQ (`pq.ErrClassicalAuthForbidden`) |
| Registry's classical opt-in gate | ✅ `TestRegister_Classical_Refused` / `TestRegister_Classical_OptIn` |
| Replay protection across versions | ✅ `TestE2E_CrossVersion_IDPreserved` |
| Decoder panic-freedom | ✅ `FuzzWarpEnvelopeV2` + `FuzzSignatureSchemeLegParser` + `FuzzCorruptedMLDSACertSet` (≥ 100k execs/run) |
| BLS12-381 aggregate verify | ✅ Inherited from `luxfi/crypto/bls` (audited primitive) |
| ML-DSA-65 single-party verify | ⚠ Inherited from `luxfi/crypto/mldsa` (Cloudflare CIRCL backend) |
| Pulsar / Corona threshold verify | ⚠ Inherited from `luxfi/pulsar` / `luxfi/corona` (Lux primitives) |
| Bridge-quorum trust inheritance | ❌ Out of scope — verifier's responsibility |
| ML-DSA aggregation primitive | ❌ NOT present in FIPS 204 — see §3.3 |
| Network-layer transport security | ❌ Out of scope — see `TRANSPORT.md` |

Legend: ✅ established here; ⚠ inherited from a separately-audited module; ❌ explicitly out of scope.

## §3 What is NOT proved (and why)

### §3.1 NOT proved: lattice-hardness of ML-DSA / R-LWE

Warp says nothing about the post-quantum hardness of ML-DSA or
R-LWE. ML-DSA's security rests on Module-LWE and Module-SIS
hardness assumptions (NIST FIPS 204 analysis); R-LWE threshold
rests on Ring-LWE hardness (Pulsar / Corona analysis). Warp
inherits these assumptions; it does not prove them.

**The defensible PQ-safety claim**:

> Warp 2.0 binds NIST-standardized post-quantum signatures (FIPS 204
> ML-DSA-65) and Lux R-LWE threshold signatures to the same
> transcript that the classical BLS aggregate signs. Under
> `pq.ModeStrictPQ` the verifier REFUSES envelopes lacking PQ
> evidence, so a chain pinned strict-PQ cannot accept a classical-
> only message.

**NOT defensible**:

> Warp is proved post-quantum secure.

### §3.2 NOT proved: bridge-quorum trust inheritance

Warp's envelope verifier validates the source-chain's signature
material under the source-chain's validator set + quorum. A
compromised source-chain validator set produces valid-but-malicious
envelopes that warp cannot detect. Bridge-level trust is the
verifier's responsibility, not warp's.

**Concretely**: if 67% of the source chain's BLS / ML-DSA key
material is exfiltrated, an adversary can forge a Warp envelope
that verifies. The destination chain SHOULD use a trust-on-first-
use (TOFU) snapshot of the source chain's validator set, validator
slashing for double-signing, and / or a multi-source-chain quorum
override — none of these are warp's responsibility.

### §3.3 NOT proved: ML-DSA aggregation

FIPS 204 has no native aggregation primitive. Warp's `MLDSACertSet`
is N independent per-validator attestations; the wire-byte cost
scales linearly with N. The verification cost is reducible via
Z-Chain Groth16 rollup (LP-307) but that compresses the
**classical** verification cost — the resulting succinct proof is
itself a classical primitive (Groth16 over BN254 — Shor-vulnerable).

This is the disclaimer pinned in `pulsar/classification.go` and
`pulsar/groth16_classification_test.go` Gates 6A / 6B:

> A Groth16 wrapping of ML-DSA cert-set verification is a CLASSICAL
> succinct proof of post-quantum signature verification. The
> aggregated verification cost is succinct; the underlying
> attestations are PQ; but the aggregation primitive is classical
> and Shor-vulnerable.

True PQ aggregation requires either a Falcon-style native
aggregation or a STARK-wrapped ML-DSA — both are research
directions, not production primitives.

### §3.4 NOT proved: side-channel safety in this module

Warp's contribution is wire-format + posture-gate logic; the
cryptographic primitives live in `luxfi/crypto/bls`, `luxfi/crypto/
mldsa`, `luxfi/pulsar`, `luxfi/corona`. Constant-time analysis of
those primitives lives in their respective TCB documents:

- BLS12-381: `blst` upstream constant-time; reviewed.
- ML-DSA-65: Cloudflare CIRCL backend; reviewed.
- Pulsar threshold: jasmin-ct gated 3/3 in `~/work/lux/pulsar/ct/`.
- Corona threshold: dudect harness in `~/work/lux/corona/ct/`.

Warp's wire-format code paths are NOT secret-dependent (the
envelope contents are public-by-construction — they are
cross-chain *messages*), so warp itself does not need
constant-time analysis at the wire-format layer.

### §3.5 NOT proved: network-layer integrity / liveness

Warp produces and verifies signed envelopes. Transport-layer
integrity (encryption, replay window, congestion control,
DDoS resistance) is the responsibility of the transporter.

In the Lux ecosystem, inter-node carriers use
`github.com/luxfi/zap` for transport — see `TRANSPORT.md` for
the integration shape. Warp envelopes are carried verbatim by
ZAP (no transformation); ZAP provides the transport-layer
properties (TLS 1.3 with hybrid X25519 + ML-KEM-768 key
exchange when configured).

### §3.6 NOT proved: validator-key custody

Warp consumes per-validator BLS / ML-DSA / threshold-share key
material. Custody of that material (HSM integration, key rotation,
deletion on validator exit) is the operator's responsibility. The
`signer/` and `signature-aggregator/` subpackages provide the API
surface; the custody implementation lives in operator-specific
deployments (e.g. `~/work/lux/operator`).

## §4 The honest one-paragraph version

> Warp 2.0 is a transport-agnostic, wire-stable, PQ-native
> cross-chain envelope format. Its contribution is (a) the
> EnvelopeV2 binary layout with a leading 0x02 version byte and
> RLP-framed PQ lanes, (b) the canonical PQ-native registry
> (`signature.NewPQNativeRegistry`) which refuses classical
> primitives without an explicit `LegacyClassicalEnabled` opt-in,
> (c) the single-function posture gate (`pq.ValidateMode`) that
> dispatches the chain's mode (classical / hybrid / strict-pq) to
> the right verifier path, and (d) the domain-separation tags
> `WARP-PULSAR-ENVELOPE-v1` and `lux-warp-cross-chain-v1` that
> prevent cross-context signature replay. The underlying
> primitive hardness (BLS / ML-DSA / R-LWE) is inherited from
> their respective audited modules; the bridge-quorum trust model
> is the verifier's responsibility; the transport-layer integrity
> is ZAP's responsibility. Warp's narrow operational soundness
> claim is implementation-level wire-and-posture correctness, NOT
> a reduction-style cryptographic-security proof.

## §5 Refinement chain (what's connected to what)

```
EnvelopeV2 wire bytes
       parses to (RLP decoder, structural Verify)
EnvelopeV2 in-memory struct
       routed by pq.ValidateMode(mode, env, verify)
{ Beam ∨ Pulse ∨ MLDSACertSet } lane
       verified by the lane's primitive verifier
{ BLS12-381 aggregate ∨ Pulsar R-LWE threshold ∨ ML-DSA-65 single-party }
       primitive correctness inherits from
{ LP-075 ∨ LP-073 ∨ FIPS 204 }
```

Each arrow is a single function in a single file. Each primitive
correctness claim lives in the primitive's own module — warp does
NOT re-prove what it inherits.

## §6 What an auditor verifying this protocol should do

1. **Read** `SUBMISSION.md` for context and scope.
2. **Read** `TRUSTED-COMPUTING-BASE.md` for the TCB inventory.
3. **Read** `SPECIFICATION.md` for the wire format byte-by-byte.
4. **Read** `PQ_PROFILES.md` for the posture taxonomy.
5. **Read** `LEGACY-CLASSICAL.md` for the classical-opt-in policy.
6. **Run** the test suite:
   ```
   cd ~/work/lux/warp
   GOWORK=off go test -count=1 -race -timeout 240s ./ ./crypto/signature/...
   ```
   Expect: root warp package green; signature registry green.
7. **Run** the fuzz harnesses for ≥ 60 s each:
   ```
   GOWORK=off go test -fuzz=FuzzWarpEnvelopeV2 -fuzztime=60s ./
   GOWORK=off go test -fuzz=FuzzSignatureSchemeLegParser -fuzztime=60s ./
   GOWORK=off go test -fuzz=FuzzCorruptedMLDSACertSet -fuzztime=60s ./
   ```
   Expect: zero panics, zero new corpus crashes.
8. **Regenerate** the KAT manifest:
   ```
   GOWORK=off go run ./cmd/envelope_kat_oracle/
   ```
   Diff against committed `scripts/kat/envelope_kat.json` — MUST
   be byte-identical.
9. **Read** `CRYPTOGRAPHER-SIGN-OFF.md` for the verdict and gates.

---

**Document metadata**

- Name: `PROOF-CLAIMS.md`
- Version: v1.0 (Tier A)
- Date: 2026-05-18
