# warp Module Documentation

Module: `github.com/luxfi/warp`
Version: v1.18.0
Status: Active development

## Overview

Lux Warp is the cross-chain messaging (XCM) protocol for Lux Network. It enables secure, verified communication between blockchains using BLS signature aggregation.

## Architecture

```
github.com/luxfi/warp
├── message.go         # UnsignedMessage, Message - core message types
├── signature.go       # BitSetSignature, BLS signing functions
├── validator.go       # Validator, CanonicalValidatorSet, ValidatorState
├── verifier.go        # Verifier interface
├── handler.go         # P2P Handler interface
├── payload/           # Payload types (AddressedCall, Hash, L1ValidatorRegistration, etc.)
├── backend/           # Backend interface, MemoryBackend, ChainBackend
├── signer/            # Signer interface, LocalSigner, RemoteSigner, SignerBackend
├── signature-aggregator/  # Signature aggregation API
├── relayer/           # Message relaying
├── precompile/        # EVM precompile integration
├── docs/              # Fumadocs-based documentation site
└── cmd/               # CLI tools
```

## Key Types

### Messages
- `UnsignedMessage`: NetworkID, SourceChainID, Payload
- `Message`: UnsignedMessage + Signature

### Signatures
- `Signature` interface: Verify, GetSignedWeight, Equal, Bytes
- `BitSetSignature`: Signers bitmap + aggregated BLS signature (96 bytes)

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
    github.com/luxfi/crypto v1.17.25  // BLS cryptography
    github.com/luxfi/geth v1.16.53    // EVM types
    github.com/luxfi/ids v1.2.4       // ID types
    github.com/luxfi/p2p v1.4.6       // P2P networking
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

- v1.18.0: Verifier interface, enhanced documentation
- v1.17.0: L1 validator registration payloads
- v1.16.0: Enhanced signature aggregation

---
*Updated: 2024-12-23*
