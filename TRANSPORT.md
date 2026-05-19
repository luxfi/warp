# TRANSPORT — Warp Envelope Carriage Over the Wire

> How Warp 2.0 signed envelopes are transported between chains.

## Warp produces transport-agnostic signed envelopes

Warp's contribution is the **envelope wire format** plus the
**posture gate**. Warp does NOT define its own network protocol.
A signed `EnvelopeV2` is a byte string consumed by an external
transporter that delivers the bytes to the destination chain's
verifier.

```
+-------------------+      +--------------+      +---------------------+
|  Source-chain     |      |  Transport   |      |  Destination-chain  |
|  signer-aggregator|----->|  carrier     |----->|  envelope verifier  |
|  (warp.Sign)      |      |  (verbatim)  |      |  (warp.VerifyV2)    |
+-------------------+      +--------------+      +---------------------+
       produces                  carries                 consumes
   EnvelopeV2 bytes         the same bytes,         EnvelopeV2 bytes
                            no transformation
```

The transporter:

- **Carries the envelope bytes verbatim.** No re-serialisation,
  no field truncation, no version-byte stripping.
- **Provides transport-layer properties.** Encryption, integrity,
  replay window, congestion control, DDoS resistance.
- **Hands the bytes to the verifier.** The verifier does
  `ParseEnvelope` + `pq.ValidateMode` + lane verification.

## Canonical transporter in the Lux ecosystem: ZAP

Inter-node carriage of Warp envelopes inside the Lux ecosystem
uses **`github.com/luxfi/zap`** (Zero-copy Application Protocol).
ZAP is a binary serialization protocol with optional TLS 1.3
transport security.

### Why ZAP, not gRPC / protobuf

The Lux ecosystem rule (per global CLAUDE.md):

> Inter-node: ZAP (github.com/luxfi/zap), NOT p2p or gRPC/protobuf.

The rationale is:

1. **Zero-copy reads.** ZAP messages are accessed directly from
   the underlying byte buffer without parsing or allocation —
   relevant for high-throughput cross-chain message relay.
2. **Single protocol.** Like Cap'n Proto and FlatBuffers, ZAP
   gives the ecosystem ONE binary serialization protocol; no
   gRPC-vs-protobuf-vs-something-else dispatch.
3. **PQ-TLS path.** When `NodeConfig.TLS` is set to a `*tls.Config`
   that includes hybrid X25519+ML-KEM-768 KEX, ZAP connections are
   PQ-protected at the transport layer. Warp envelopes carried over
   PQ-protected ZAP are end-to-end PQ (envelope-level PQ via
   MLDSACertSet AND transport-level PQ via TLS 1.3 hybrid).

### Integration shape

Warp envelope bytes are placed as the payload of a ZAP message:

```
ZAP message
  +------------------------+
  | ZAP header (16 bytes)  |
  | - Magic: "ZAP\x00"     |
  | - Version: 1           |
  | - Flags                |
  | - Root offset          |
  | - Size                 |
  +------------------------+
  | ZAP payload            |
  | - Warp EnvelopeV2 bytes|
  |   (starting with 0x02) |
  +------------------------+
```

The Warp envelope is the **payload** of the ZAP message, NOT the
ZAP message itself. The ZAP header is the transport-layer
framing; the warp envelope is the application-layer signed
message.

Implementation status:

- Warp envelope bytes: stable wire format (this push, Tier A).
- ZAP transport: stable wire format (`github.com/luxfi/zap` v0.x).
- Integration glue: **not in this repository**. The integration
  lives in the Lux node (`github.com/luxfi/node`) and the
  signature-aggregator service (`github.com/luxfi/signature-aggregator`).
  Warp itself does NOT import `github.com/luxfi/zap` — keeping
  the dependency direction clean.

## Other transporters

A non-Lux consumer (third-party bridge, external indexer, etc.)
may carry Warp envelope bytes over ANY transport that preserves
them verbatim. Examples that work:

- **gRPC unary call** with the envelope as a single `bytes` field.
- **HTTP POST** with the envelope as the request body.
- **Plain TCP socket** with a length-prefixed frame.
- **Kafka / NATS** with the envelope as the message payload.
- **IPFS CID** addressing the envelope bytes.

Examples that do NOT work without rework:

- **JSON-encoded re-serialization** of the envelope's fields. JSON
  is not byte-stable; re-serialising loses the canonical RLP
  byte stream and breaks `EnvelopeV2.ID()` consistency.
- **Field-level transformation** (e.g. truncating the
  `SourceNebulaRoot` for "efficiency"). Any field change breaks
  the Pulse and ML-DSA transcript bindings.
- **Re-signing** the envelope at the destination. Re-signing
  changes the byte stream, which changes the `ID()`, which breaks
  destination-chain dedup.

The rule is simple: **the envelope bytes are immutable in transit**.
Any transporter that respects this rule works.

## Where ZAP integration lives

Warp does NOT import `github.com/luxfi/zap`. The integration
lives in two places:

1. **`github.com/luxfi/node`** — the Lux node integrates warp and
   ZAP through the signature-aggregator path. The node has a
   small adapter that wraps a warp envelope in a ZAP message
   for inter-node delivery.

2. **`github.com/luxfi/signature-aggregator`** — the service
   that collects per-validator signatures and emits the final
   `EnvelopeV2`. The service uses ZAP for its API surface;
   clients call the service over ZAP and receive completed
   envelopes.

This separation keeps the warp module **transport-agnostic**:
warp can be embedded in any system that wants cross-chain signed
envelopes, not just systems that speak ZAP.

## Implications for the threat model

Because warp envelopes are transport-agnostic:

- **Confidentiality is the transporter's responsibility.** Warp
  envelopes are NOT encrypted; their contents (UnsignedMessage
  payload) are public-by-construction. Operators who need
  confidential cross-chain messages use Warp Private (LP-021v2
  forthcoming) — FHE ciphertext as the payload, with the same
  envelope format.

- **Replay protection is content-addressed.** Destination chains
  dedup by `EnvelopeV2.ID()` (= `Message.ID()` = SHA-256 of the
  unsigned message). A replay attack at the transport layer
  delivers bytes the destination already has; dedup discards them.

- **Transport-layer authenticity is independent.** A compromised
  transporter cannot forge a warp envelope (the source-chain's
  signature material is required) but CAN drop or delay
  envelopes. Liveness is the transporter's responsibility;
  warp's job is soundness.

## References

- `~/work/lux/zap/zap.go` — ZAP protocol reference implementation.
- `~/work/lux/node/` — Lux node, integrates warp + ZAP for
  inter-node delivery.
- `~/work/lux/signature-aggregator/` — Signature aggregation
  service with ZAP API surface.

---

**Document metadata**

- Name: `TRANSPORT.md`
- Version: v1.0 (Tier A)
- Date: 2026-05-18
