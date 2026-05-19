# LEGACY-CLASSICAL — Operator-Facing Opt-In Policy

> This document explains the `signature.Config.LegacyClassicalEnabled`
> flag, why it exists, what it permits, and the deprecation
> timeline for classical primitives on the Lux network.

## Why this flag exists

Lux Warp is **PQ-native by default**. The canonical signature
registry constructor

```go
r := signature.NewPQNativeRegistry()
```

returns a registry where:

- The preferred scheme is `signature.SchemeMLDSA65` (FIPS 204
  ML-DSA-65, NIST security level 3).
- Classical primitives (`SchemeBLS`, `SchemeEd25519`,
  `SchemeSecp256k1`) **cannot be installed** without an explicit
  opt-in. Attempting `r.Register(SchemeBLS, ...)` returns
  `signature.ErrClassicalRequiresOptIn`.

A chain that wants classical primitives available MUST opt in:

```go
cfg := signature.Config{
    LegacyClassicalEnabled: true,
}
r := signature.NewRegistryFromConfig(cfg)
r.Register(signature.SchemeBLS, ...)         // OK
r.Register(signature.SchemeEd25519, ...)     // OK
r.Register(signature.SchemeSecp256k1, ...)   // OK
```

The flag is **explicit** and **audit-grep'able**: every chain
config that wants classical fallback has `LegacyClassicalEnabled:
true` written in it. No implicit fallback is possible.

## What the flag does NOT do

The `LegacyClassicalEnabled` flag is at the **registry** layer.
It controls which schemes the registry will install.

The chain-level posture gate is `pq.Mode` (one of `classical`,
`hybrid`, `strict-pq`). These two gates are **decomplected**:

| Scenario | Registry gate | Chain gate | Outcome |
|---|---|---|---|
| Default chain, default registry | classical refused | strict-pq | classical envelope refused by both gates |
| Default chain, opt-in registry | classical admitted | strict-pq | classical envelope refused by chain gate at verification |
| Hybrid chain, opt-in registry | classical admitted | hybrid | classical envelope accepted with stale-PQ warning |
| Classical chain, opt-in registry | classical admitted | classical | classical envelope accepted as trust root |

In the second row, the registry installs BLS but the chain mode
gate STILL refuses a classical-only envelope. This is by design:
the gates are decomplected so a hostile build that bypasses one
gate STILL hits the other.

## When to set `LegacyClassicalEnabled = true`

Set the flag to `true` ONLY when ALL of the following hold:

1. The chain is pinned `pq.ModeClassical` or `pq.ModeHybrid` (not
   `strict-pq`).
2. The operator has decided to accept the Shor-vulnerability of
   classical primitives for the chain's threat model.
3. Documentation in the chain's deployment runbook explicitly
   names the classical scheme(s) the chain trusts.

Do NOT set the flag to `true` on a strict-PQ chain. The opt-in
will succeed at the registry layer, but the chain gate will still
refuse classical envelopes — the flag will be effectively a no-op
that confuses readers of the config.

## Deprecation timeline

Classical primitives on the Lux ecosystem follow a three-phase
deprecation:

### Phase 1 — Classical default (historical, pre-2025)

Lux Warp 1.x was BLS-only. Every chain implicitly trusted the BLS
aggregate as the verification root. No PQ posture existed.

This phase is over. The Tier A push deletes the implicit
classical default at the registry layer.

### Phase 2 — PQ-aware (2025 → 2026) [CURRENT]

The Tier A push (this revision, 2026-05-18):

- Adds PQ-native default at the registry layer.
- Adds explicit `LegacyClassicalEnabled` opt-in for classical.
- Keeps classical primitives **available** under opt-in so
  existing wallets can migrate.
- Liquid mainnet pinned `strict-pq`.
- Lux primary network + Hanzo + Zoo + Pars chains pinned
  `hybrid` (classical fallback during validator-key rotation).

Operators of `classical` or `hybrid` chains MUST add
`LegacyClassicalEnabled: true` to their chain config when
upgrading from Warp 1.18.x to Warp 1.19.x. Without the flag,
classical scheme installs will fail at chain boot with
`signature.ErrClassicalRequiresOptIn`. The chain will refuse to
start; the operator gets a clear error message naming the flag.

### Phase 3 — Classical refused (target 2027-Q4)

Target: 2027-Q4. By this date:

- Every Lux ecosystem chain pinned `strict-pq`.
- Classical primitives REMOVED from the registry (not just
  opt-in-gated).
- Classical scheme identifiers reserved-but-refused on the wire
  (parsing a classical signature returns an error).
- Wallet migration completed.

The `LegacyClassicalEnabled` flag will be REMOVED in Phase 3.
Chain configs that still set the flag will fail to parse.

This timeline is contingent on:

- Hanzo, Zoo, Pars subnet validator-key rotation completing.
- PQ-TLS at JSON-RPC ingress (currently using classical TLS 1.3).
- libp2p handshake migration to PQ-aware Noise / hybrid TLS 1.3.

See `PQ_PROFILES.md` "What's needed for FULL PQ end-to-end" for
the per-layer dependency tracking.

## Migration path for operators

To migrate a chain config from Warp 1.18.x to Warp 1.19.x:

1. **Read** the current chain's `warpProfile` (one of
   `classical`, `hybrid`, `strict-pq`).
2. **Decide** whether the chain still needs classical primitives.
   For most strict-PQ chains, the answer is NO.
3. **If classical is no longer needed** (target state for strict-pq):
   - Remove any `signature.Config{...}` construction that sets
     `LegacyClassicalEnabled: true`.
   - Use `signature.NewPQNativeRegistry()` instead.
4. **If classical is still needed** (transitional state for
   hybrid / classical):
   - Add `LegacyClassicalEnabled: true` to the `Config` literal.
   - Document the rationale in the chain's deployment runbook.
   - Schedule a follow-up to remove the flag once validator-key
     rotation completes.

## API surface

The opt-in flag is defined in
`github.com/luxfi/warp/crypto/signature/interface.go`:

```go
// Config is the operator-facing posture knob for the signature
// registry.
type Config struct {
    LegacyClassicalEnabled bool
    PreferredScheme        Scheme
}

// DefaultConfig is the canonical PQ-native default.
func DefaultConfig() Config {
    return Config{
        LegacyClassicalEnabled: false,
        PreferredScheme:        SchemeMLDSA65,
    }
}

// NewPQNativeRegistry returns the canonical PQ-native registry.
func NewPQNativeRegistry() *Registry

// NewRegistryFromConfig returns a registry pinned to the given Config.
func NewRegistryFromConfig(cfg Config) *Registry
```

## Frequently asked

### Q. Why a flag instead of a separate constructor like `NewLegacyRegistry`?

A flag on `Config` makes the chain's posture greppable across
the codebase. An operator's chain config has the literal text
`LegacyClassicalEnabled: true` next to its other knobs — easier to
audit than tracking which constructor was called.

### Q. Does the flag affect runtime performance?

No. The flag is checked at `Register` time and at `SetPreferred`
time, not on every signature verification. Steady-state
verification cost is unchanged.

### Q. Why is `SchemeHybrid` not affected by the flag?

`SchemeHybrid` composes BLS + Corona over the same transcript;
both lanes verify. It is the canonical migration path. A chain
pinned `hybrid` mode needs `SchemeHybrid` installable WITHOUT the
opt-in flag, otherwise migration is blocked. The registry treats
hybrid as PQ-aware (not classical) and admits it under the
default config.

### Q. What about `SchemeMLDSA44` / `SchemeMLDSA87`?

Not currently registered. ML-DSA-65 (NIST level 3) is the canonical
Warp default; ML-DSA-44 (level 2) and ML-DSA-87 (level 5) can be
added in future revisions if a downstream chain requests them.
Adding them would NOT require a flag change since they are PQ
schemes.

---

**Document metadata**

- Name: `LEGACY-CLASSICAL.md`
- Version: v1.0 (Tier A)
- Date: 2026-05-18
