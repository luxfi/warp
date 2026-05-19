# CHANGELOG — Lux Warp Cross-Chain Messaging

All notable wire-format-affecting and posture-affecting changes
to `github.com/luxfi/warp` are documented in this file.

The format is based on Keep a Changelog. Lux Warp follows
semantic versioning at the **wire format** level: a major-version
bump (e.g. v1.x → v2.x) indicates a non-byte-equivalent wire
format change; a minor-version bump (e.g. v1.18.x → v1.19.x)
indicates a new API surface or posture knob that does not break
existing wire-format consumers; a patch-version bump
(e.g. v1.19.0 → v1.19.1) is a bug fix.

## [v1.19.0] — 2026-05-18 — Tier A push

### Added

- **PQ-native signature registry constructor.**
  `signature.NewPQNativeRegistry()` returns the canonical
  PQ-native registry: `Config.LegacyClassicalEnabled = false`,
  `PreferredScheme = SchemeMLDSA65`, classical primitives refused
  at install time with `ErrClassicalRequiresOptIn`.

- **Explicit classical opt-in flag.**
  `signature.Config.LegacyClassicalEnabled` (default `false`).
  Operators that want classical schemes available MUST set this
  flag explicitly. See `LEGACY-CLASSICAL.md`.

- **PQ scheme identifiers.** `signature.SchemeMLDSA65`,
  `signature.SchemePulsar`, `signature.SchemeCorona`,
  `signature.SchemeSLHDSA`. Pre-existing `SchemeBLS`,
  `SchemeEd25519`, `SchemeSecp256k1`, `SchemeHybrid` are
  preserved.

- **Domain-separation context tag.** `signature.SignContextWarpV1
  = "lux-warp-cross-chain-v1"`. FIPS 204 §5.2 / FIPS 205 §10.2
  context-string bound into every ML-DSA-65 / SLH-DSA signature
  produced for a Warp 2.0 envelope.

- **PQ-vs-classical predicates.** `signature.IsPQ(scheme)`,
  `signature.IsClassical(scheme)`. Used by the chain-mode gate
  to distinguish classical envelopes from PQ ones.

- **Deterministic scheme audit ordering.** `Registry.Schemes()`
  returns schemes in `PQSchemes ∪ ClassicalSchemes ∪
  {SchemeHybrid}` order — PQ first, then classical, then hybrid.
  Audit tools can diff against a declared config.

- **SUBMISSION.md, PROOF-CLAIMS.md, TRUSTED-COMPUTING-BASE.md,
  PATENTS.md, CRYPTOGRAPHER-SIGN-OFF.md, DEPLOYMENT-RUNBOOK.md,
  TRANSPORT.md, LEGACY-CLASSICAL.md, CHANGELOG.md.**
  Tier A submission documentation pack.

### Tests added

- `crypto/signature/interface_test.go` — 14 tests pinning the
  PQ-native default posture, classical opt-in gate, PQ
  classification predicates, and audit ordering.

- `cross_chain_envelope_e2e_test.go` — 10 e2e tests covering
  PQ-default registry behaviour, posture-gate verification
  under every `pq.Mode`, cross-version (v1 ↔ v2) round-trip,
  and KAT wire-stability.

- `strict_pq_test.go` — 7 tests (with 8 sub-cases) covering the
  cross-product of (mode × `LegacyClassicalEnabled` ×
  PQ-evidence-present).

- `signature_scheme_fuzz_test.go` — 2 new fuzz harnesses
  (`FuzzSignatureSchemeLegParser`, `FuzzCorruptedMLDSACertSet`)
  exercising decoder panic-freedom plus `HasPQEvidence`
  consistency under arbitrary byte input.

### Changed

- `Registry.NewRegistry(preferred)` continues to work — it now
  internally wires `DefaultConfig()` with the supplied preferred
  scheme. Existing callers compile without changes; the default
  classical opt-in is `false` for callers that previously passed
  `SchemeBLS` as preferred (those callers will fail at
  `Register(SchemeBLS, ...)` with `ErrClassicalRequiresOptIn` —
  this is the intended Tier A migration signal).

- `Register` now returns `ErrClassicalRequiresOptIn`
  (was: generic "scheme mismatch" prefix) and `ErrUnknownScheme`
  (was: generic "unknown signature scheme").

### Deprecated

- Classical primitives (`SchemeBLS`, `SchemeEd25519`,
  `SchemeSecp256k1`) on `strict-pq` chains. Target removal:
  2027-Q4 (Phase 3 of the deprecation timeline). See
  `LEGACY-CLASSICAL.md`.

### Wire format

- **Unchanged.** EnvelopeV2 wire bytes remain byte-stable. The
  Tier A push affects API ergonomics and documentation, NOT the
  bytes on the wire. KAT manifest at
  `scripts/kat/envelope_kat.json` regenerates byte-identical.

### Migration

- Callers of `signature.NewRegistry(SchemeBLS)` whose chain is
  `classical` or `hybrid`: switch to
  `signature.NewRegistryFromConfig(signature.Config{
  LegacyClassicalEnabled: true, PreferredScheme: SchemeBLS})`.
- Callers of `signature.NewRegistry(SchemeBLS)` whose chain is
  `strict-pq`: this is the intended migration error — pin the
  chain to a PQ preferred scheme
  (`signature.NewPQNativeRegistry()`).

## [v1.18.0] — pre-2026-05-18

See git history (`git log --oneline`). Highlights:

- `Verifier` interface added.
- EnvelopeV2 Tier B push.
- Pulsar Pulse lane wired through `pulsar.KernelVerifier`.

## [v1.17.0]

- L1 validator registration payloads added.

## [v1.16.0]

- Enhanced signature aggregation API.

## [Warp 1.x]

- BLS12-381 aggregate (Beam) only. No PQ posture. Byte-equal to
  Avalanche Subnet Warp Messaging upstream.

---

**Document metadata**

- Name: `CHANGELOG.md`
- Version: v1.0 (Tier A)
- Date: 2026-05-18
