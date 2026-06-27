# Warp Security Profiles — Classical, Hybrid, Strict-PQ

A Liquid / Lux / Zoo chain pins one of three Warp security profiles
at genesis. The profile decides which lane(s) of an Envelope the
verifier MUST validate, and which lanes are best-effort or
forbidden.

**Two layers gate classical primitives.** Tier A introduces a
second, decomplected gate at the **registry** layer in addition
to the existing chain-mode gate. Both must agree for a classical
envelope to verify:

| Gate | Where | What |
|---|---|---|
| Registry | `signature.Config.LegacyClassicalEnabled` | Controls which schemes the registry will install. Default `false` = PQ-only. |
| Chain mode | `pq.Mode` (one of `classical` / `hybrid` / `strict-pq`) | Controls which schemes the chain trusts as the verification root. Default for new strict deployments = `strict-pq`. |

See `LEGACY-CLASSICAL.md` for the operator-facing flag documentation.

## The three profiles

| profile      | BLS Beam               | MLDSACertSet               | use case                                                            |
|--------------|------------------------|----------------------------|---------------------------------------------------------------------|
| `classical`  | required (trust root)  | ignored                    | legacy chain, no ML-DSA validator material yet                      |
| `hybrid`     | best-effort fallback   | validated WHEN present     | migration middle — flip on PQ validation without breaking in-flight |
| `strict-pq`  | best-effort (echo only)| **required** (trust root)  | pure post-quantum — Liquid default, Zoo strict, Lux strict          |

`IsPostQuantum()` returns `true` only for `strict-pq`. Hybrid is
`IsPQAware()` (validates the MLDSACertSet when present) but not
strict-PQ (allows fall-back to classical).

## Migration flow (classical → hybrid → strict-pq)

1. **Classical** — current state. Every envelope verifies under BLS
   Beam. MLDSACertSet field exists in the wire format but is
   ignored. No ML-DSA validator material required.

2. **Hybrid** — validators start signing the MLDSACertSet lane.
   Chain pins `hybrid`. A verifier sees an MLDSACertSet and
   validates it; sees a classical-only envelope and falls back to
   BLS Beam with a stale-PQ warning event. No envelopes refused —
   the migration window stays open as long as the operator wants.

3. **Strict-PQ** — operator flips the chain to `strict-pq`. Any
   envelope without an MLDSACertSet refuses with
   `ErrClassicalAuthForbidden`. BLS Beam still serializes so the
   chain can echo to a classical peer across a bridge, but the
   Beam bytes are never the verification root.

## What's needed for FULL PQ end-to-end (Lux/Zoo cross-chain)

This document focuses on Warp. The other strict-PQ layers
(validator identity, EVM, DEX, FHE, X-Chain UTXO) are tracked
in their own packages:

| layer                          | status                                                       |
|--------------------------------|--------------------------------------------------------------|
| Validator identity (sig)       | **DONE** ML-DSA-65 via `luxfi/node` + `luxfi/ids` v1.2.10    |
| Handshake KEM                  | **DONE** ML-KEM-768 keys loaded; consumer wiring open        |
| NodeID derivation              | **DONE** SHAKE256-384, wire scheme byte 0x42                 |
| EVM precompiles                | **DONE** AllForbidden gate, ecrecover + classical refused    |
| EVM tx envelope                | **DONE** MLDSATxType (0x42) + MLDSASigner in `luxfi/geth`    |
| EVM tx-pool admission          | **DONE** refuses classical types under ActivePQProfile       |
| DEX SignedOrder                | **DONE** SignedOrderPQ in `lx/dex`                           |
| FHE parameters                 | **DONE** PN9QP27_STD128Q via `DefaultParamsForProfile`       |
| X-Chain UTXO Fx                | **DONE** `lux/utxo/mldsafx` + XVM registration               |
| Warp envelope gate             | **DONE** this file's gate (classical/hybrid/strict-pq)       |
| Pulsar Pulse PQ                | **TODO** Pulsar threshold sig classification under strict-PQ |
| ML-DSA aggregation             | **TODO** N independent ML-DSA sigs today (no aggregation primitive in FIPS 204). True PQ aggregation needs research — Falcon-based, or ML-DSA via SNARK proof of N sigs |
| libp2p handshake               | **TODO** classical TLS 1.3 still used; ML-KEM keys loaded but not yet consumed in handshake. Needs hybrid TLS 1.3 (X25519+ML-KEM-768 KEX, ML-DSA cert sigs) or a Noise-style PQ handshake |
| JSON-RPC TLS                   | **TODO** `eth_sendRawTransaction` over classical TLS termination. Needs PQ TLS at ingress (oqs-provider or similar)                                                                  |
| Trading SDKs                   | **TODO** `lx-trading-go` + JS bindings need to default to ML-DSA-65 signing under strict-PQ chains                                                                                  |

## Hybrid is the safe migration path

A chain that flips classical → strict-pq in one step strands every
envelope already in flight: peers that haven't yet generated
ML-DSA validator material can't produce an MLDSACertSet, so their
envelopes get refused at the gate. The chain stops processing
inbound cross-chain messages from those peers.

Hybrid lets the operator turn on PQ validation TODAY (chain
verifies MLDSACertSet when present, validators start producing
it) and turn off classical trust LATER (chain flips to strict-pq
once enough peers carry the PQ lane).

## Adopting Warp profile in a downstream package

```go
import "github.com/luxfi/warp"

// At chain boot, read the operator config:
profile, err := warp.ProfileFromString(chainCfg.WarpProfile) // "classical" | "hybrid" | "strict-pq"
if err != nil { return err }

// At every envelope verification:
if err := warp.RequireMLDSACertSetForProfile(profile, env); err != nil {
    return err // refuses on strict-pq + missing MLDSACertSet
}

// Pick the lane to validate:
switch warp.LanesForProfile(profile, env.HasMLDSACertSet()) {
case warp.LanePQ:
    // validate MLDSACertSet via ML-DSA-65
case warp.LaneClassical:
    // validate BLS Beam
}
```

One JSON config field (`warpProfile`) on each chain. One library
call per verification. The same naming convention as
`lx/dex.SecurityProfile`, `lux/fhe.SecurityProfile`, and
`luxfi/evm`'s `PQProfile` gate — `ProfileFromPQFlag`,
`IsPostQuantum`, `ErrClassicalAuthForbidden` exist on every layer.

## Classical primitives are NEVER trusted under strict-PQ

Lux/Zoo/Liquidity keep classical primitives **available** so users
can claim pre-PQ balances and migrate addresses. But:

- Strict-PQ profile **refuses** classical primitives at the
  verification boundary (precompile / tx-pool / order verify /
  envelope gate).
- Classical-compat code paths are guarded by
  `LUX_CLASSICAL_COMPAT_UNSAFE` and never enabled by default.
- A strict-PQ binary build can include the classical types for
  serialization compatibility but the verification side is a
  no-op refusal — classical bytes go in, `ErrClassicalAuthForbidden`
  comes out.

This is the "claim, don't trust" model: classical material remains
readable for backwards compatibility (so existing wallets can
migrate) but is never the auth root of a strict-PQ chain.
