# Warp V2 Message Format Specification

Version: 2.0

## Abstract

Warp V2 is an enhanced cross-chain messaging (XCM) format building upon the original Warp protocol developed by the Avalanche team. This version introduces post-quantum safety through random ringtail validation and other cryptographic improvements while maintaining backward compatibility with Warp V1.

## Improvements over Warp V1

1. **Post-Quantum Safety**: Random ringtail validation provides resistance against quantum attacks
2. **Enhanced Privacy**: Ring signatures enable validator anonymity
3. **Private Messaging**: Z-chain FHE (Fully Homomorphic Encryption) enables private cross-chain messages
4. **Dynamic Validator Selection**: Random subset validation improves security and efficiency
5. **Forward Secrecy**: Ephemeral keys for message encryption
6. **Zero-Knowledge Proofs**: Optional ZK proofs for message validity without revealing content

## Message Structure

### Core Message Fields

Every Warp message MUST contain:

1. **Message ID** (32 bytes): Unique identifier computed as `hash(source_chain_id || destination_chain_id || nonce || payload)`
2. **Source Chain ID** (32 bytes): Identifier of the originating blockchain
3. **Destination Chain ID** (32 bytes): Identifier of the target blockchain
4. **Payload** (variable length): Application-specific message content

### Optional Fields

Messages MAY contain:

1. **Source Address** (variable): Originating contract/account address
2. **Destination Address** (variable): Target contract/account address
3. **Timestamp** (8 bytes): Unix timestamp of message creation
4. **Nonce** (8 bytes): Replay protection counter

## Signature Format

Warp uses BLS signatures for efficient aggregation:

1. **Signature** (96 bytes): BLS signature over message hash
2. **Signer Bitmap** (variable): Bit vector indicating which validators signed
3. **Aggregate Public Key** (48 bytes): Combined public key of signers

## Encoding

Messages are encoded using Protocol Buffers (protobuf) for:
- Language-agnostic serialization
- Compact binary representation
- Forward/backward compatibility

## Security Properties

1. **Authentication**: Messages are authenticated by validator signatures
2. **Integrity**: Message hash ensures content hasn't been modified
3. **Replay Protection**: Nonce prevents message replay
4. **Non-repudiation**: BLS signatures provide cryptographic proof

## Example Message

```
{
  "id": "0x1234...abcd",
  "source_chain_id": "0xaaaa...aaaa",
  "destination_chain_id": "0xbbbb...bbbb",
  "payload": "0xdead...beef",
  "timestamp": 1234567890,
  "nonce": 42
}
```

## Implementations

Warp message format can be implemented in any language. Reference implementations:
- Go: `github.com/luxfi/warp`
- Rust: `lux_warp` (planned)
- TypeScript: `@luxfi/warp` (planned)