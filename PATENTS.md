# PATENTS — Lux Warp Cross-Chain Messaging

> **Statement of Intellectual Property and Royalty-Free Patent Grant**
> for the Lux Warp cross-chain messaging protocol.

## TL;DR

Lux Industries, Inc. ("Lux") grants a **worldwide, royalty-free,
non-exclusive, irrevocable patent license** for any implementation
of Lux Warp that conforms to the `Envelope` wire format pinned in
`SPECIFICATION.md` AND is either (a) licensed under
BSD-3-Clause-Eco, BSD-3-Clause, Apache-2.0, or a compatible
OSI-approved license, OR (b) is a port, validation, or
interoperability test of the protocol.

The grant terminates automatically and prospectively against any
party that asserts a patent claim against Lux Warp, FIPS 204
ML-DSA, FIPS 205 SLH-DSA, BLS12-381, or any conforming
implementation thereof. Defensive termination mirrors Apache-2.0 §3.

The full text of the grant is in **§3 Patent Grant** below.

## §1 Scope of the IP statement

This document covers patent rights and patent posture for:

- The **`Envelope` wire format** specified in `SPECIFICATION.md`.
- The **posture-gate composition** (`pq.ValidateMode` over
  `Envelope.HasPQEvidence`) pinned in `security_profile.go` and
  `PQ_PROFILES.md`.
- The **reference implementation** in this repository.
- The **KAT vectors** in `scripts/kat/envelope_kat.json` and the
  oracle that generates them.
- The **cross-language reference ports** (Rust `lux_warp`,
  TypeScript `@luxfi/warp`) when they conform byte-for-byte to
  the KAT manifest.

It does NOT cover, and explicitly DISCLAIMS, the following prior art:

| Component | Status |
|---|---|
| FIPS 204 ML-DSA-65 | Public domain — NIST standard. |
| FIPS 205 SLH-DSA | Public domain — NIST standard. |
| BLS12-381 pairing-friendly curve | Academic / public domain (Bowe / Boneh-Lynn-Shacham). |
| Module-Lattice (MLWE / MSIS) | Academic / public domain. |
| Ring-LWE | Academic / public domain. |
| Avalanche / Subnet Warp Messaging upstream | Apache-2.0 open-source upstream (ava-labs); Lux Warp is a PQ-native fork — no Lux patents asserted against the upstream. |
| RLP encoding | Public domain (Ethereum specification). |
| BLS aggregate signature scheme | Academic / public domain (Boneh-Drijvers-Neven). |
| SHA-256 / SHA3-256 / Keccak | Public domain — NIST standards FIPS 180-4 / FIPS 202. |
| The general concept of "cross-chain messaging with PQ migration" | Documented in academic literature and prior systems; Lux Warp's specific wire-format and posture-gate composition is the novel contribution. |

## §2 What Lux considers patentable (high level)

Subject to attorney review, Lux considers the following Lux Warp
contributions to be candidates for patent protection:

### §2.1 PQ-native envelope with classical-opt-in posture gate

The specific composition of:

- A wire format (`Envelope`) that carries a classical Beam, an
  optional Pulse (R-LWE threshold), and an optional MLDSACertSet
  (FIPS 204 per-validator attestations) over the same digest `D`;
- A posture gate (`pq.ValidateMode`) that dispatches three named
  modes (classical / hybrid / strict-pq) to the appropriate
  verifier path through a SINGLE function call;
- A signature-scheme registry (`signature.Config.LegacyClassicalEnabled`)
  whose default posture refuses classical primitives at install
  time, decomplected from the chain-level posture gate;
- The single-sentinel error model (`pq.ErrClassicalAuthForbidden`)
  used uniformly across every refusal site in the system.

### §2.2 Transcript-binding domain separation

The specific construction of the single digest
`D = keccak256("LUX-WARP-ZAP-CORE-v1" ‖ zap_c14n(Message))` — which
folds the full source-chain lineage (`NetworkID`, `SourceChainID`,
`SourceNebulaRoot`, `SourceKeyEraID`, `SourceGeneration`,
`HashSuiteID`, `Payload`) into the signed subject — together with
the per-lane domain-separation tags that each sign `tag ‖ D` and so
prevent replay across:

- The classical Beam (`"LUX-WARP-ZAP-BEAM-v1"`);
- The Pulsar / Corona Pulse (`"LUX-WARP-ZAP-PULSE-v1"`);
- The ML-DSA cert set (`"LUX-WARP-ZAP-MLDSA-v1"`);

and which are all distinct from the consensus-layer Pulsar prefix
(`"QUASAR-PULSAR-BUNDLE-v1"`). Distinct context strings per domain
are required by FIPS 204 §5.2 context-string binding; the SPECIFIC
single-digest-plus-per-lane-tag composition here is what Lux
considers novel.

### §2.3 Canonical-TLV envelope with unambiguous wire framing

The `Envelope` ZAP wire framing — a 5-byte `"LWZP"‖0x01` magic
followed by a `0x02` kind byte and a total-order canonical TLV body
— that yields a single canonical parser (`ParseEnvelope`) with no
malleability lane: every byte is committed, optional lanes are the
empty `u32(0)` frame rather than omitted fields, and decode rejects
any non-canonical or trailing bytes. The framing is unambiguously
distinguishable from — and explicitly rejects — legacy RLP bytes
(lead `0xc0..0xff`) and the legacy `0x02`-prefixed envelope, because
the ZAP lead byte `'L'` (`0x4c`) is below RLP's `0xc0` list floor.

## §3 Patent Grant

> **Lux Industries, Inc. ("Lux") hereby grants to every person and
> entity a worldwide, royalty-free, non-exclusive, irrevocable
> patent license under any Patent Claims of Lux that read on the
> Lux Warp Protocol (as defined in `SPECIFICATION.md` of this
> repository) to make, use, sell, offer for sale, import, and
> otherwise transfer the Lux Warp Protocol, IF AND ONLY IF the
> implementation EITHER:**
>
> 1. **Conforms** to the `Envelope` wire format pinned in
>    `SPECIFICATION.md` AND is licensed under BSD-3-Clause-Eco,
>    BSD-3-Clause, Apache-2.0, MIT, or another OSI-approved
>    license that grants the same rights to its recipients; **OR**
>
> 2. **Is part of** a port, validation, or interoperability test
>    of the Lux Warp Protocol that is published under an
>    OSI-approved license; **OR**
>
> 3. **Is a fork or derivative** of this repository that retains
>    the wire format byte-equality with the KAT manifest in
>    `scripts/kat/envelope_kat.json`.
>
> **"Patent Claims of Lux"** means any patent claims owned or
> controlled by Lux that would necessarily be infringed by
> implementing the Lux Warp Protocol as specified.
>
> **Defensive termination.** This grant terminates automatically
> and prospectively against any party that initiates patent
> litigation (including a cross-claim or counterclaim) against
> Lux, Lux Warp, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, BLS12-381, or
> any conforming implementation thereof, alleging infringement by
> the recipient's use of the Lux Warp Protocol. Defensive
> termination mirrors Apache-2.0 §3 and extends to all
> NIST-standardized post-quantum cryptographic primitives.
>
> **No grant for non-conforming implementations.** A modified
> wire format that breaks byte-equality with the KAT manifest is
> NOT a conforming implementation and receives no patent grant
> under this document. Forks are encouraged; wire-format breaks
> are NOT licensed under this grant.

## §4 Attribution and trademarks

"Lux Warp" and "Lux Network" are trademarks of Lux Industries, Inc.
This patent grant does not include a trademark license. Forks and
derivatives are encouraged to use distinct names for their wire-
incompatible variants.

## §5 Contact

Patent questions, royalty-free-grant applicability questions, and
attorney-prep claim drafts should be directed to the Lux
Industries patent counsel via the repository's `MAINTAINERS.md`.

---

**Document metadata**

- Name: `PATENTS.md`
- Version: v1.0 (Tier A)
- Date: 2026-05-18
