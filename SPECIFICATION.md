# Warp ZAP Message Format Specification

This document is the normative wire-format spec for Lux Warp. The Go
canonical at this commit is the byte oracle; ports to other languages
MUST produce byte-equal serialisation.

There is exactly ONE codec (the ZAP canonical-TLV profile), exactly
ONE signing digest (`D`), and exactly ONE envelope (`Envelope`). No
RLP, no codec version, no `v1`/`v2` split, no cross-version
dispatcher. ZAP replaces the legacy RLP `UnsignedMessage` / `Message`
/ `EnvelopeV2` layering of the Avalanche Subnet Warp Messaging
lineage (see "Legacy" below); the legacy bytes are rejected, not
parsed.

**Posture default**: PQ-native. The reference signature registry
(`signature.NewPQNativeRegistry`) is the canonical entrypoint
and refuses classical primitives without an explicit
`Config.LegacyClassicalEnabled` opt-in. See `LEGACY-CLASSICAL.md`
for the policy and `PQ_PROFILES.md` for the chain-level posture
taxonomy.

## The two types

| Type | Role | Constructor / parser | Canonical bytes |
|---|---|---|---|
| `Message` | the signed subject — the value whose digest `D` validators sign | `NewMessage` / `ParseMessage` | `Message.Bytes()` (= `zap_c14n(Message)`) |
| `Envelope` | the complete signed wire object — a `Message` plus its three signature lanes | `NewEnvelope` / `ParseEnvelope` | `Envelope.Bytes()` |

`Message` folds the former `UnsignedMessage` body (NetworkID,
SourceChainID, Payload) together with the Pulsar PQ lineage
(SourceNebulaRoot, SourceKeyEraID, SourceGeneration, HashSuiteID)
that the legacy design carried only on the envelope. Folding the
lineage into the signed subject means EVERY lane — the classical BLS
Beam included — authenticates it via `D`. Under the legacy split the
Beam signed only the unsigned body and the lineage was
Beam-unauthenticated.

## The ZAP canonical profile

ZAP is a total-order canonical TLV codec: a given struct value has
exactly one byte encoding, and decode rejects any byte stream that is
not in canonical form. That property is what makes the encoding safe
to use as a signing domain — every byte is committed and there is no
malleability lane (no pointers, padding, flags, varints, or maps).

Canonicality rules (enforced by `zap.go`):

1. Integers are fixed-width big-endian (`u8`/`u16`/`u32`/`u64`). No varints.
2. Every variable-length field is framed with a `u32` big-endian length
   prefix followed by exactly that many bytes.
3. Fixed-width arrays (`[20]`/`[32]`/`[96]`) are written raw, with no length.
4. Every field is always present. An absent optional lane is the
   `u32(0)` empty frame, never an omitted field.
5. Booleans are exactly `0x00` or `0x01`; any other byte is rejected.
6. The Signers bitset is trim-canonical: no trailing zero byte. A
   bitset whose final byte is zero is non-canonical (two encodings for
   one set) — trimmed on encode, rejected on decode.
7. Decode rejects trailing bytes: the cursor MUST land exactly on the
   end of the buffer (`offset == len`).
8. The envelope wire stream begins with the 5-byte magic
   `"LWZP"‖0x01`. Legacy RLP bytes (lead `0xc0..0xff`) and the legacy
   `0x02` envelope byte are rejected at the magic check; ZAP bytes are
   rejected by an RLP decoder (`'L'` = `0x4c` is below RLP's `0xc0`
   list floor).

## Common types

### Message

The `Message` canonical encoding (`Message.Bytes()` == `zap_c14n`):

```
Message c14n =
    Kind             u8  (0x01)            // ZAP message kind
    NetworkID        u32 big-endian
    SourceChainID    [32] raw
    SourceNebulaRoot [32] raw
    SourceKeyEraID   u64 big-endian
    SourceGeneration u64 big-endian
    HashSuiteID      u32-len ‖ utf8
    Payload          u32-len ‖ bytes
```

`MaxMessageSize` is 256 KiB — the marshalled `Message` MUST fit in
this bound. There is NO sign-time defaulting inside the codec: a
`Message`'s `HashSuiteID` MUST be resolved to a concrete value
(`DefaultHashSuiteID` = `"Pulsar-SHA3"`) before it is marshaled or
signed. `Message.Bytes()` is total-order canonical, so re-marshaling
a decoded `Message` reproduces the exact bytes.

### The digest D

`D` is the single signed digest (the "Prism" transcript): the
`Message` ID, the destination-chain replay-protection key, and the
on-chain `messageHash`, all at once.

```
D = keccak256( "LUX-WARP-ZAP-CORE-v1" ‖ zap_c14n(Message) )
```

`Message.ID()` returns `D`. `Envelope.ID()` returns the SAME `D`
(recomputed from the embedded `Message`, never sliced out of the
wire). The domain tag `"LUX-WARP-ZAP-CORE-v1"` is a FROZEN wire
constant: the type is named `Message`, but the v1 domain tag retains
the word `CORE`.

`keccak256` is Ethereum's keccak256 —
`golang.org/x/crypto/sha3.NewLegacyKeccak256` (Keccak padding
`0x01`), NOT NIST SHA3-256 (pad `0x06`) and NOT `crypto/sha256`. The
on-chain `keccak256` opcode computes exactly this, so `D` matches
byte-for-byte between Go and Solidity.

Because `D` is computed over the full `Message` c14n — including
SourceNebulaRoot, SourceKeyEraID, SourceGeneration, and the
length-prefixed HashSuiteID — every transcript field is bound into
`D`, and therefore into every lane that signs `D`. A suite-renaming
attack cannot collide with a suffix-bytes attack: `HashSuiteID` is
length-prefixed, not merely concatenated.

### Per-lane signing bytes

Each lane signs the SAME `D` under its OWN domain-separation tag, so
a signature in one lane can never be replayed into another (BLS
objects vs lattice objects are already non-interchangeable; the
distinct tags close the door regardless):

```
BeamSigningBytes(D)  = "LUX-WARP-ZAP-BEAM-v1"  ‖ D
PulseSigningBytes(D) = "LUX-WARP-ZAP-PULSE-v1" ‖ D
MLDSASigningBytes(D) = "LUX-WARP-ZAP-MLDSA-v1" ‖ D
```

A validator signs e.g. `BeamSigningBytes(D)`; the verifier recomputes
`D` from the `Message` and checks the signature over the same bytes.

### BitSetSignature (the Beam lane)

```
BitSetSignature =
    Signers     u32-len ‖ trim-canonical bitset bytes
    Signature   [96] raw (BLS12-381 aggregate)
```

The bitset selects, by canonical validator index, the public keys
that aggregate to `Signature`. The Beam verifies over
`BeamSigningBytes(D)`, so it authenticates the entire `Message`
(including the PQ lineage), not just the message body.

## Envelope wire format

```
Envelope wire =
    Magic         "LWZP" ‖ 0x01        (5 bytes)
    Kind          u8 (0x02)            // ZAP envelope kind
    Message       <Message c14n>       // begins with its own 0x01 kind byte
    Beam          <BitSetSignature>
    PulseSig      u32-len ‖ bytes      // empty u32(0) frame when absent
    MLDSACertSet  u32-len ‖ bytes      // empty u32(0) frame when absent
```

All four lanes are ALWAYS present on the wire. Absence of a PQ lane
is the empty `u32(0)` frame, not an omitted field — the field count
is fixed. `Envelope.Bytes()` is the canonical wire form; the total
size MUST stay within `MaxEnvelopeSize` (4 × 256 KiB, leaving room
for the Pulse and the ML-DSA cert set alongside the message and
Beam).

`ParseEnvelope` rejects: a bad/absent magic, the wrong kind byte, a
non-canonical (trailing-zero) Signers bitset, a malformed `Message`,
and any trailing bytes.

### Beam lane (classical, always present)

BLS12-381 aggregate over `BeamSigningBytes(D)`. Verification (per
`VerifyEnvelope`):

1. Structural `Verify()`; reject if the message or envelope exceeds
   its size bound.
2. Reject unless `Envelope.Message.NetworkID == networkID`.
3. Resolve `Message.SourceChainID` to a canonical validator set +
   total weight.
4. Compute signed weight from `Signers` over the canonical set.
5. Reject unless `signedWeight / totalWeight >= QuorumNum / QuorumDen`.
6. Aggregate the public keys of the bit-set signers, verify the BLS
   aggregate against `BeamSigningBytes(Message.ID())`.

### Pulse lane (Pulsar / Corona R-LWE threshold, optional)

The `PulseSig` field carries a Corona/Pulsar threshold signature,
serialised as three length-prefixed lattice-signature components:

```
PulseSig =
    uint32 LE(len(C_bytes))     ‖ C_bytes
    uint32 LE(len(Z_bytes))     ‖ Z_bytes
    uint32 LE(len(Delta_bytes)) ‖ Delta_bytes
```

where `C_bytes`, `Z_bytes`, `Delta_bytes` are the lattice `WriteTo`
streams of the kernel `Signature`'s `C` (`ring.Poly`), `Z`
(`structs.Vector[ring.Poly]`), and `Delta`
(`structs.Vector[ring.Poly]`) fields — see LP-073 §5. The 12 bytes
of LE length prefixes inside `PulseSig` are the only delta versus a
raw concatenation; they are little-endian to keep the Pulse interior
uniform with the lattice `WriteTo` streams.

The Pulse is verified over `PulseSigningBytes(D)` by
`pulsar.KernelVerifier`, which implements the root package's
`PulseVerifier` interface. The verifier:

1. Confirms the envelope carries a non-empty Pulse.
2. Resolves the source-chain GroupKey + HashSuite for
   `(SourceChainID, SourceKeyEraID, SourceGeneration)` via a
   `pulsar.GroupKeyResolver` — a destination-chain contract that
   records the source's GroupKey lineage as it evolves through
   Bootstrap, Reshare, and Reanchor events (LP-073
   §"Key-Era Lifecycle").
3. Confirms the resolver-supplied suite matches the envelope's
   resolved `HashSuiteID`.
4. Recomputes `D` from the `Message` and verifies the threshold
   signature over `PulseSigningBytes(D)`.

Because `D` already folds in SourceNebulaRoot, SourceKeyEraID,
SourceGeneration, HashSuiteID, SourceChainID, NetworkID, and Payload,
verifying the Pulse over `PulseSigningBytes(D)` binds the Pulse to
every one of them — no separate transcript-binding step is required.

### MLDSACertSet lane (ML-DSA-65 attestations, optional)

The `MLDSACertSet` field carries N independent per-validator ML-DSA-65
(FIPS 204) attestations (or a Z-Chain Groth16 rollup over them). Each
attestation is produced over `MLDSASigningBytes(D)` and verified by a
caller-supplied `MLDSACertSetVerifier`.

FIPS 204 has no native aggregation primitive: the cert set is N
independent attestations and the wire-byte cost scales linearly with
N. The signature registry additionally binds the FIPS 204 §5.2
context string `SignContextWarpV1 = "lux-warp-cross-chain-v1"` into
each per-validator ML-DSA-65 / SLH-DSA signature at the scheme layer.
The same FIPS 205 §10.2 rule applies to SLH-DSA.

### Verification order

`VerifyWithOptions` checks lanes in order:

1. `Envelope.Verify()` — message well-formed; optional-lane bytes
   within `MaxEnvelopeSize`.
2. Hash-suite consistency (when the caller pins `HashSuiteID` in opts).
3. Beam: `VerifyEnvelope` (unless `SkipBeam`).
4. ML-DSA cert set: `MLDSACertSetVerifier.VerifyCertSet`, when configured.
5. Pulse: `PulseVerifier.VerifyPulse`, when configured.

`Require*` options demand a lane be present, a verifier be configured,
and verification succeed. A lane present without a configured verifier
is accepted (the caller chose to ignore that lane). `VerifyPQLanes`
runs only the PQ-lane checks (skipping the Beam), for receivers that
have already verified the Beam separately.

## Legacy

ZAP replaces the legacy RLP `UnsignedMessage` / `Message` /
`EnvelopeV2` layering inherited from the Avalanche Subnet Warp
Messaging lineage. There is NO backward compatibility and NO
cross-version dispatch:

- Legacy RLP bytes (a bare RLP list, lead `0xc0..0xff`) are rejected
  at the ZAP magic check.
- The legacy `0x02`-prefixed `EnvelopeV2` byte is rejected at the
  same check.
- Conversely, ZAP bytes (lead `'L'` = `0x4c`) are rejected by an RLP
  decoder, since `0x4c` is below RLP's `0xc0` list floor.

A sender targeting a legacy-only verifier MUST speak the legacy
protocol on a legacy channel; the ZAP wire is forward-only.

## Encoding

The codec is the in-package ZAP profile (`zap.go`); the root `warp`
package imports no RLP and no external serialization framework. All
multi-byte integers in the ZAP framing are big-endian. The lattice
`WriteTo` streams inside `PulseSig`, and the 12-byte length prefixes
that frame them, are little-endian per LP-073 §5.

## Constants

| Name | Value | Purpose |
|---|---|---|
| `wireMagic` | `"LWZP" ‖ 0x01` | 5-byte envelope wire prefix (Lux Warp Zap Protocol, format v1) |
| message kind | `0x01` | First byte of a `Message` c14n stream |
| envelope kind | `0x02` | Envelope kind byte (follows the magic) |
| `MaxMessageSize` | 256 KiB | Per-`Message` canonical-encoding bound |
| `MaxEnvelopeSize` | 4 × 256 KiB | Per-`Envelope` wire bound (room for Pulse + cert set) |
| `DefaultHashSuiteID` | `"Pulsar-SHA3"` | `HashSuiteID` resolution target (no sign-time defaulting) |
| `messageDST` | `"LUX-WARP-ZAP-CORE-v1"` | Digest `D` domain tag (FROZEN) |
| `beamDST` | `"LUX-WARP-ZAP-BEAM-v1"` | Beam lane domain tag |
| `pulseDST` | `"LUX-WARP-ZAP-PULSE-v1"` | Pulse lane domain tag |
| `mldsaDST` | `"LUX-WARP-ZAP-MLDSA-v1"` | ML-DSA cert-set lane domain tag |

## Reference implementation

* Go (canonical): `github.com/luxfi/warp` (this module). Wire codec
  in `zap.go`; domain constants + `D` construction in `codec.go`;
  `Message` in `message.go`; `Envelope` in `envelope.go`; Beam in
  `signature.go`; Pulse wiring in `pulsar/`.
* KAT oracle: `cmd/envelope_kat_oracle/` regenerates
  `scripts/kat/envelope_kat.json`; the wire-stability test
  `TestE2E_KAT_PQEnvelope_WireBytesStable` refuses any drift.
* Rust port: planned at `lux_warp` after the Go canonical's KAT
  manifest is pinned.
* TypeScript port: `@luxfi/warp` for browser / SDK consumers; Beam
  verification first, Pulse verification follows the kernel WASM port.

## References

* LP-021 — Warp classical Beam-only cross-chain messaging (legacy lineage).
* LP-021v2 — Warp hybrid envelope (this spec).
* LP-073 — Pulsar lattice threshold kernel.
* LP-075 — BLS aggregate (Beam).
* LP-105 §"Warp evolution" — vocabulary and lane composition.
