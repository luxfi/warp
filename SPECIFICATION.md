# Warp Message Format Specification

This document is the normative wire-format spec for Warp 1.x and
Warp 2.0. The Go canonical at this commit is the byte oracle; ports
to other languages MUST produce byte-equal serialisation.

**Posture default**: PQ-native. The reference signature registry
(`signature.NewPQNativeRegistry`) is the canonical entrypoint
and refuses classical primitives without an explicit
`Config.LegacyClassicalEnabled` opt-in. See `LEGACY-CLASSICAL.md`
for the policy and `PQ_PROFILES.md` for the chain-level posture
taxonomy.

## Table of versions

| Version | Envelope | Lanes | Status |
|---|---|---|---|
| 1.x | bare RLP `Message` | Beam (BLS aggregate) | shipping |
| 2.0 | `0x02` + RLP `EnvelopeV2` | Beam + ML-DSA cert set + Pulse | shipping (Tier A) |
| Private | `0x02` + envelope w/ FHE payload | FHE ciphertext + Pulse | production-research |

## Common types

### UnsignedMessage

```
UnsignedMessage = [
    NetworkID      uint32,
    SourceChainID  ids.ID (32 bytes),
    Payload        bytes
]
```

`MaxMessageSize` is 256 KiB — the marshalled `UnsignedMessage` MUST
fit in this bound. `UnsignedMessage.ID()` is `SHA-256(Marshal(self))`
truncated to 32 bytes; this ID is the destination-chain replay-
protection key, identical across Warp 1.x and Warp 2.0 wrappings of
the same message.

### BitSetSignature

```
BitSetSignature = [
    Signers     Bits (variable-length packed bitmap),
    Signature   [96]byte (BLS12-381 aggregate)
]
```

`Bits` is a packed little-endian bitmap with no length prefix
(receivers infer length from the RLP framing).

## Warp 1.x envelope

```
Message (Warp 1.x) = RLP[
    UnsignedMessage,
    SignatureType uint8 (always 0 for BitSetSignature),
    BitSetSignature
]
```

`Message.Bytes()` is the canonical wire form. Verification (per
`VerifyMessage`):

1. Marshal-roundtrip the unsigned portion; reject if size >
   `MaxMessageSize`.
2. Resolve `(SourceChainID, currentHeight)` to a canonical validator
   set + total weight.
3. Compute signed weight from `Signers` over the canonical set.
4. Reject unless `signedWeight / totalWeight >= QuorumNum / QuorumDen`.
5. Aggregate the public keys of the bit-set signers, verify the BLS
   aggregate against `Message.UnsignedMessage.Bytes()`.

## Warp 2.0 envelope

```
v2 wire = 0x02 || RLP[
    Message,                          // v1 Beam carrier (unchanged)
    SourceNebulaRoot   [32]byte,
    SourceKeyEraID     uint64,
    SourceGeneration   uint64,
    HashSuiteID        string,
    PulsarPulse        bytes (optional; zero-length when absent),
    MLDSACertSet       bytes (optional; zero-length when absent)
]
```

The leading `0x02` byte is the version discriminator. RLP lists in
the wild start at `0xc0` or higher, so a single-byte test is
unambiguous. Senders MUST emit `0x02` before the RLP body; receivers
MUST reject any version byte they do not recognise.

`HashSuiteID` defaults to `"Pulsar-SHA3"` when empty. The empty value
on the wire is the canonical indicator of the default suite — senders
MAY omit it, receivers MUST treat it as the default.

Optional lanes (`PulsarPulse`, `MLDSACertSet`) are zero-length byte
slices when absent. The field count in the RLP list is fixed at 7;
forward compatibility is achieved through the version byte and a
future `0x03` envelope, not through trailing-field tolerance.

### Transcript binding (Pulse)

The Pulsar Pulse signs the byte stream produced by
`pulsar.BuildSigningBytes`:

```
signing_bytes =
    "WARP-PULSAR-ENVELOPE-v1"            ||
    SourceChainID            (32 bytes)  ||
    SourceNebulaRoot         (32 bytes)  ||
    SourceKeyEraID           (8 bytes BE) ||
    SourceGeneration         (8 bytes BE) ||
    uint32-BE(len(HashSuiteID))          ||
    HashSuiteID                          ||
    uint32-BE(len(UnsignedMessage_bytes)) ||
    UnsignedMessage_bytes
```

`UnsignedMessage_bytes` is `env.Message.UnsignedMessage.Bytes()` — the
unsigned portion only, NOT the BLS signature. The Beam is verified
independently and does not contaminate the PQ transcript.

The `WARP-PULSAR-ENVELOPE-v1` prefix is distinct from any Pulsar
consensus-side prefix (`QUASAR-PULSAR-BUNDLE-v1`, etc., see LP-073
§"Domain-separated message prefixes"). Re-using a prefix across
domains would let a Pulse over a Quasar bundle root be replayed as a
Pulse over a Warp envelope — explicitly rejected.

### MLDSACertSet context binding

When the source chain produces the `MLDSACertSet` lane, every
per-validator ML-DSA-65 (FIPS 204) signature MUST be produced
under the canonical context string:

```
ctx = "lux-warp-cross-chain-v1"
```

This corresponds to `signature.SignContextWarpV1` in the Go
reference. The context binding follows FIPS 204 §5.2: the
signer's `Sign(sk, M, ctx)` call uses `ctx` as the context-string
argument, not as part of the message `M`. A signature produced
under any other context (including an empty context) is REFUSED
by the destination's verifier as a domain-separation violation.

The same rule applies to SLH-DSA (FIPS 205) signatures per
FIPS 205 §10.2.

This tag is DISTINCT from the Pulse lane's `SigningPrefix`
(`"WARP-PULSAR-ENVELOPE-v1"`) and from the Pulsar consensus-side
prefix (`"QUASAR-PULSAR-BUNDLE-v1"`). The three tags partition the
signature domain into:

- ML-DSA-65 cross-chain envelope attestations (this tag).
- Pulsar R-LWE threshold pulses (WARP-PULSAR-ENVELOPE-v1).
- Pulsar consensus-bundle pulses (QUASAR-PULSAR-BUNDLE-v1).

A signature on any of these contexts cannot replay as a
signature on either of the other two.

### PulsarPulse byte format

The `PulsarPulse` field carries the concatenation of three length-
prefixed lattice-signature components:

```
PulsarPulse =
    uint32 LE(len(C_bytes))         || C_bytes
    uint32 LE(len(Z_bytes))         || Z_bytes
    uint32 LE(len(Delta_bytes))     || Delta_bytes
```

where `C_bytes`, `Z_bytes`, `Delta_bytes` are the lattigo `WriteTo`
streams of the kernel `Signature`'s `C` (`ring.Poly`), `Z`
(`structs.Vector[ring.Poly]`), and `Delta`
(`structs.Vector[ring.Poly]`) fields — see LP-073 §5 for the lattice
serialisation. The 12 bytes of length prefixes are the only delta
versus a raw concatenation.

### Verification order (Warp 2.0)

`VerifyV2` checks lanes in order:

1. `EnvelopeV2.Verify()` — embedded v1 message present + well-formed,
   optional-lane bytes within `MaxEnvelopeV2Size`.
2. Hash-suite consistency (when caller pins `HashSuiteID` in opts).
3. Beam: same v1 verification path as Warp 1.x.
4. ML-DSA cert set: `MLDSACertSetVerifier.VerifyCertSet`, when
   configured.
5. Pulsar Pulse: `PulseVerifier.VerifyPulse`, when configured.

Required-but-absent lanes return an error. A lane present without a
configured verifier is accepted (the caller chose to ignore that
lane).

## Compatibility

| Sender → Receiver | Behaviour |
|---|---|
| v1 → v1 | Standard Warp 1.x. |
| v1 → v2 | `ParseEnvelope` decodes; lifts to `EnvelopeV2` with PQ lanes empty. |
| v2 → v1 | v1 receiver rejects (leading `0x02` is not RLP). Senders MUST emit Warp 1.x bytes for v1-only verifiers. |
| v2 → v2 | Standard Warp 2.0. |

Replay protection is uniform: `EnvelopeV2.ID() == Message.ID()` for
the same `UnsignedMessage`. Destination-chain dedup tables work
across versions.

## Encoding

Both envelopes use the existing RLP codec (`Codec`,
`github.com/luxfi/geth/rlp`). All multi-byte ints are big-endian
inside RLP; lattigo `WriteTo` streams (Pulse interior) are
little-endian per LP-073 §5. The 12-byte length prefixes inside
`PulsarPulse` are little-endian to keep the Pulse interior uniform.

## Constants

| Name | Value | Purpose |
|---|---|---|
| `MaxMessageSize` | 256 KiB | Per-`UnsignedMessage` bound |
| `MaxEnvelopeV2Size` | 4 × 256 KiB | Per-envelope bound (room for Pulse + cert set) |
| `EnvelopeVersion1` | 0x01 | Documentary (no on-wire byte for Warp 1.x) |
| `EnvelopeVersion2` | 0x02 | Leading byte for Warp 2.0 |
| `DefaultHashSuiteID` | `"Pulsar-SHA3"` | Default when `HashSuiteID` is empty |
| `SigningPrefix` | `"WARP-PULSAR-ENVELOPE-v1"` | Pulse domain-separation tag |

## Reference implementation

* Go (canonical): `github.com/luxfi/warp` (this module).
* Rust port: planned at `lux_warp` after the Go canonical's KAT
  manifest is pinned.
* TypeScript port: `@luxfi/warp` for browser / SDK consumers; Beam
  verification first, Pulse verification follows the kernel WASM port.

## References

* LP-021 — Warp 1.x classical messaging.
* LP-021v2 — Warp 2.0 hybrid envelope (this spec).
* LP-073 — Pulsar lattice threshold kernel.
* LP-075 — BLS aggregate (Beam).
* LP-105 §"Warp evolution" — vocabulary and lane composition.
