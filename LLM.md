# warp Module Documentation

Module: `github.com/luxfi/warp`
Version: v1.22.0
Status: Active development

## Overview

Lux Warp is the cross-chain messaging (XCM) protocol for Lux Network. It enables secure, verified communication between blockchains using BLS aggregation (the Beam lane) plus optional post-quantum evidence (a Pulsar/Corona R-LWE threshold Pulse and per-validator ML-DSA-65 attestations). Every lane signs a single keccak256 digest `D` over the ZAP canonical encoding of the message.

## Architecture

```
github.com/luxfi/warp
├── message.go         # Message - the signed subject (folds the PQ lineage)
├── codec.go           # ZAP domain constants (D / per-lane DST tags), digest D
├── zap.go             # ZAP canonical-TLV wire codec (the ONE codec)
├── signature.go       # BitSetSignature (Beam), BLS signing functions
├── validator.go       # Validator, CanonicalValidatorSet, ValidatorState
├── envelope.go        # Envelope - the single signed wire object + verifiers
├── security_profile.go # HasPQEvidence, LanesForMode (posture router)
├── verifier.go        # Verifier interface
├── handler.go         # P2P Handler interface
├── pulsar/            # Pulse path (KernelVerifier over PulseSigningBytes(D))
├── payload/           # Payload types (AddressedCall, Hash, L1ValidatorRegistration, etc.)
├── backend/           # Backend interface, MemoryBackend, ChainBackend
├── signer/            # Signer interface, LocalSigner, RemoteSigner, SignerBackend
├── signature-aggregator/  # Signature aggregation API
├── relayer/           # Message relaying
├── precompile/        # EVM precompile integration
├── docs/              # Fumadocs-based documentation site
└── cmd/               # CLI tools + KAT oracle
```

## Key Types

### Messages
- `Message`: NetworkID, SourceChainID, SourceNebulaRoot, SourceKeyEraID, SourceGeneration, HashSuiteID, Payload — the signed subject. `Message.ID()` returns the digest `D = keccak256("LUX-WARP-ZAP-CORE-v1" ‖ Message.Bytes())`. Constructors: `NewMessage` / `ParseMessage`.
- `Envelope`: a `Message` plus its three signature lanes (Beam, PulseSig, MLDSACertSet) — the complete signed wire object. Constructors: `NewEnvelope` / `ParseEnvelope`; `Envelope.ID() == Message.ID() == D`.

### Signatures
- `BitSetSignature` (the Beam lane): Signers bitmap + aggregated BLS12-381 signature (96 bytes), verified over `BeamSigningBytes(D)`.
- PQ lanes: `PulseSig` (Pulsar/Corona threshold over `PulseSigningBytes(D)`) and `MLDSACertSet` (ML-DSA-65 attestations over `MLDSASigningBytes(D)`).

### Validators
- `Validator`: PublicKey, PublicKeyBytes, Weight, NodeID
- `CanonicalValidatorSet`: Sorted validators with total weight
- `ValidatorState` interface: GetValidatorSet, GetCurrentHeight

### Payloads
- `AddressedCall`: Cross-VM contract calls
- `Hash`: Simple 32-byte hash
- `L1ValidatorRegistration`: Validator registration status
- `RegisterL1Validator`: Add validator to subnet
- `SubnetToL1Conversion`: Subnet conversion message
- `L1ValidatorWeight`: Validator weight update

## Dependencies

```go
require (
    github.com/luxfi/crypto v1.19.17  // BLS cryptography
    github.com/luxfi/geth v1.16.98    // EVM types (common.Hash)
    github.com/luxfi/ids v1.2.15      // ID types
    github.com/luxfi/p2p v1.21.1      // P2P networking
    github.com/luxfi/pq v1.0.3        // posture gate (pq.ValidateMode)
)
```

## Documentation Site

Built with Fumadocs (Next.js).

### Structure
```
docs/
├── app/                      # Next.js app router
│   ├── layout.tsx           # Root layout
│   ├── layout.config.tsx    # Navigation config
│   ├── page.tsx             # Redirect to /docs
│   ├── source.ts            # MDX source config
│   ├── docs/                # Docs pages
│   └── global.css           # Styles
├── content/docs/            # MDX content
│   ├── index.mdx            # Overview
│   ├── getting-started/     # Installation, Quick Start
│   ├── concepts/            # Messages, Signatures, Validators, Payloads
│   ├── api/                 # API reference
│   └── guides/              # Integration guides
├── source.config.ts         # Fumadocs MDX config
└── package.json             # Dependencies
```

### Building
```bash
cd docs
pnpm install
pnpm build   # Output to docs/out/
pnpm dev     # Development server
```

### Pages Created
- **Getting Started**: Installation, Quick Start
- **Concepts**: Messages, Signatures, Validators, Payloads
- **API Reference**: Message, Signature, Validator, Payload, Backend, Signer, Handler, Verifier
- **Guides**: Cross-Chain Messaging, Validator Integration, Precompile Integration

## Version History

- v1.22.0: ZAP canonical-TLV wire format — single `Message` + `Envelope`, digest `D` (legacy-Keccak256), per-lane DST tags; legacy RLP `UnsignedMessage`/`EnvelopeV2` retired
- v1.18.0: Verifier interface, enhanced documentation
- v1.17.0: L1 validator registration payloads
- v1.16.0: Enhanced signature aggregation

---
*Updated: 2024-12-23*
