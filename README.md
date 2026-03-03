# Lux Warp — Cross-Chain Messaging

> Lux is not merely adding post-quantum signatures to a chain; it defines a hybrid finality architecture for DAG-native consensus, with protocol-agnostic threshold lifecycle, post-quantum threshold sealing, and cross-chain propagation of Horizon finality.

See [LP-105 §Claims and evidence](https://github.com/luxfi/lps/blob/main/LP-105-lux-stack-lexicon.md#claims-and-evidence) for the canonical claims/evidence table and the ten architectural commitments — single source of truth.

Cross-chain messaging protocol for the Lux Network. Source-chain
validators sign an outbound message; the destination chain verifies
the signature against the source's registered validator set.

## Versions

| Version | Lanes | Status | Source |
|---|---|---|---|
| **Warp 1.x** | Beam (BLS aggregate) | shipping | `message.go`, `signature.go` |
| **Warp 2.0** | Beam + ML-DSA cert set + Pulse (Pulsar threshold) | shipping | `envelope.go`, `pulsar/` |
| **Warp Private** | FHE ciphertext + Pulse | production-research | LP-021v2 (forthcoming) |

Warp 1.x is the byte-equal fast classical path: a single BLS12-381
aggregate plus a signer bitmap (LP-075). Warp 2.0 is the Prism-bound
hybrid envelope — it carries the Warp 1.x message intact alongside
the Pulsar threshold pulse and the per-validator ML-DSA attestation
set, all bound to a common source-chain transcript (LP-105
§"Warp evolution"). Warp Private adds Z-Chain FHE ciphertext semantics
on top.

## Architecture

```
github.com/luxfi/warp
├── message.go         UnsignedMessage, Message — Warp 1.x core types
├── signature.go       BitSetSignature, BLS signing functions
├── validator.go       Validator, CanonicalValidatorSet, ValidatorState
├── envelope.go        EnvelopeV2 — Warp 2.0 envelope + dispatcher
├── verifier.go        Verifier interface
├── handler.go         P2P Handler interface
├── pulsar/            Warp 2.0 Pulse path (KernelVerifier, BuildSigningBytes)
├── payload/           Payload types (AddressedCall, Hash, ...)
├── backend/           Backend, MemoryBackend, ChainBackend
├── signer/            Signer interface (LocalSigner, RemoteSigner)
├── signature-aggregator/  Signature aggregation API
├── relayer/           Message relaying
├── precompile/        EVM precompile integration
├── docs/              Fumadocs documentation site
└── cmd/               CLI tools
```

The `pulsar/` subpackage is split out so the root `warp` package does
not import the Pulsar kernel directly — the dispatch surface is the
small `PulseVerifier` interface; the concrete kernel-driven verifier
lives in `pulsar/`.

## Wire format dispatch

```
            +-----------------------+
incoming -> | first byte == 0x02?   |
            +-----------------------+
                 |yes        |no
                 v           v
         ParseEnvelopeV2   ParseMessage  (Warp 1.x bare RLP message)
                 |           |
                 v           v
            EnvelopeV2 (PQ lanes populated when present)
```

Use `warp.ParseEnvelope(b)` for receivers that want forward compatibility
across both versions; it returns a v2 envelope in both cases (with PQ
lanes empty on v1 inputs).

## Compatibility properties

* **Forward (v2 receiver, v1 bytes)**: `ParseEnvelope` decodes a v1
  message into an `EnvelopeV2` with only the Beam lane populated. PQ
  fields are zero-valued; `HasPulse()` and `HasMLDSACertSet()` return
  false.
* **Backward (v1 receiver, v2 bytes)**: a v1 receiver calling
  `ParseMessage` directly on v2 wire bytes rejects them — the leading
  `0x02` is not a valid RLP-list prefix. This is the correct refusal:
  a v1 verifier cannot validate v2 transcript binding. Senders that
  must reach v1-only verifiers emit Warp 1.x bytes on the v1 channel;
  the same `UnsignedMessage` may be embedded in a v2 envelope on the
  v2 channel without re-signing the Beam.
* **Embedding stability**: `EnvelopeV2.ID()` returns the same hash as
  the embedded `Message.ID()`, so destination-chain replay protection
  is uniform across versions.

## Verifying a Warp 2.0 envelope

The standard verification chain (`warp.VerifyV2`) checks lanes in
order:

1. Structural envelope invariants.
2. Hash-suite consistency (when caller pins `HashSuiteID`).
3. Beam lane: BLS aggregate vs the source-chain validator set + quorum.
4. ML-DSA cert set lane (when configured / required).
5. Pulsar Pulse lane (when configured / required).

A receiver that has already validated the Beam through a separate
code path can call `warp.VerifyPQLanes` to layer in PQ-lane checks
without re-running BLS aggregate verification.

## Pulse path (`warp/pulsar`)

The Pulse component binds to the source-chain Pulsar lineage. The
canonical signing bytes are produced by `pulsar.BuildSigningBytes`:

```
WARP-PULSAR-ENVELOPE-v1 ||
    source_chain_id      || (32 bytes)
    source_nebula_root   || (32 bytes)
    source_key_era_id    || (8 bytes BE)
    source_generation    || (8 bytes BE)
    hash_suite_id_len    || hash_suite_id
    unsigned_message_len || unsigned_message_bytes
```

The destination chain implements the `pulsar.GroupKeyResolver`
interface against its source-chain key registry — a contract that
records the source's GroupKey lineage as it evolves through Bootstrap,
Reshare, and Reanchor events (LP-073 §"Key-Era Lifecycle").

## Usage (Warp 1.x)

```go
import "github.com/luxfi/warp"

unsigned, _ := warp.NewUnsignedMessage(networkID, sourceChainID, payload)
msg, _ := warp.SignMessage(unsigned, signers, validators)
err := warp.VerifyMessage(msg, networkID, validatorState, 2, 3)
```

## Usage (Warp 2.0)

```go
import (
    "github.com/luxfi/warp"
    warppulsar "github.com/luxfi/warp/pulsar"
)

env := &warp.EnvelopeV2{
    Message:          v1Msg,                  // signed Warp 1.x message
    SourceNebulaRoot: nebulaRoot,
    SourceKeyEraID:   eraID,
    SourceGeneration: generation,
    HashSuiteID:      warp.DefaultHashSuiteID,
    PulsarPulse:      pulseBytes,             // optional
    MLDSACertSet:     certSetBytes,           // optional
}
wire, _ := env.Bytes()

// Receiver:
parsed, _ := warp.ParseEnvelope(wire)
err := warp.VerifyV2(parsed, warp.VerifyV2Options{
    NetworkID:      networkID,
    ValidatorState: validatorState,
    QuorumNum:      2,
    QuorumDen:      3,
    Pulse:          warppulsar.NewKernelVerifier(myResolver),
    RequirePulse:   true,
})
```

## References

* LP-021 — Warp 1.x classical Beam-only cross-chain messaging.
* LP-021v2 — Warp 2.0 hybrid envelope (this implementation; spec doc
  forthcoming, vocabulary stub in LP-105 §"Warp evolution").
* LP-073 — Pulsar lattice threshold kernel.
* LP-075 — BLS aggregate (Beam).
* LP-105 — Lux Stack Lexicon (Beam, Pulse, Prism, Horizon, etc.).

## Module path

`github.com/luxfi/warp`. Build & test with `GOWORK=off go test ./...`.
