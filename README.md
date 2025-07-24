# Lux Warp V2 Message Format

An enhanced cross-chain messaging (XCM) format with post-quantum safety and private messaging capabilities.

## Overview

Warp V2 builds upon the original Warp protocol developed by the Avalanche team, adding post-quantum cryptography through random ringtail validation and private messaging via Z-chain FHE. It defines a message format and cryptographic standard for secure cross-chain communication that is:

- **Protocol-First**: Clean separation between protocol definitions and implementations
- **Language-Agnostic**: Core protocol can be implemented in any language (Go, Rust, C++, etc.)
- **Chain-Agnostic**: Works with EVM chains, non-EVM chains, and custom VMs
- **Modular**: Components can be used independently

## Architecture

```
warp/
├── protocol/           # Protocol definitions (protobuf)
│   ├── message.proto   # Core message types
│   ├── signature.proto # Signature types
│   └── validator.proto # Validator set definitions
├── types/              # Go type definitions
│   ├── message.go      # Message interfaces
│   ├── signature.go    # Signature interfaces
│   └── validator.go    # Validator interfaces
├── crypto/             # Cryptographic primitives
│   ├── bls/            # BLS signature implementation
│   └── hash/           # Hashing utilities
├── backend/            # Backend interface for message handling
├── handlers/           # Network request handlers
└── validators/         # Validator set management
```

## Message Format Specification

The Warp message format uses:
- **BLS Signatures**: For efficient multi-signature aggregation
- **Protobuf**: For language-agnostic message serialization
- **Content-Addressed**: Messages identified by hash
- **Standard Fields**: Source chain, destination chain, payload, and optional addressing
- **Optional Privacy**: Z-Chain FHE integration for private messages (when available)

## Adoption

Warp V2 is designed for easy adoption by any L1 blockchain:

1. **EVM Chains**: Implement a simple precompile (see `evm/precompile_example.sol`)
2. **Non-EVM Chains**: Integrate via native modules or system contracts
3. **Privacy Optional**: Z-Chain FHE features are opt-in and gracefully degrade

The core message format requires only:
- 32-byte chain IDs
- Variable-length payloads
- BLS signature verification

## Usage

### Go Implementation

```go
import "github.com/luxfi/warp"

// Create a warp message
msg := warp.NewMessage(sourceChain, destinationChain, payload)

// Sign the message
sig, err := warp.Sign(msg, privateKey)

// Verify signatures
valid := warp.Verify(msg, sig, validatorSet)
```

### Rust Implementation (Future)

```rust
use lux_warp::{Message, sign, verify};

// Create a warp message
let msg = Message::new(source_chain, dest_chain, payload);

// Sign the message
let sig = sign(&msg, &private_key)?;

// Verify signatures
let valid = verify(&msg, &sig, &validator_set)?;
```

## Design Principles

1. **Protocol Separation**: Core protocol logic is independent of implementation
2. **No Chain Dependencies**: The library doesn't depend on specific chain implementations
3. **Extensible**: New signature schemes and message types can be added
4. **Performance**: Optimized for high-throughput cross-chain messaging
5. **Security**: Follows best practices for cryptographic operations

## Integration

The library can be integrated with:
- EVM chains via precompiles
- Non-EVM chains via native modules
- Bridge services via RPC/gRPC APIs
- Off-chain services for message relaying