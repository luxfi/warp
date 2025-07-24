// Copyright (C) 2025, Lux Industries, Inc.

// Package types defines the core interfaces for the Warp message format.
// Warp is a standardized message format for cross-chain messaging (XCM).
// These interfaces are designed to be implementation-agnostic and can
// be satisfied by different concrete types.
package types

import (
	"context"
	"time"
)

// ID represents a 32-byte identifier (chain ID, message ID, etc.)
type ID [32]byte

// Address represents a blockchain address (size may vary by chain type)
type Address []byte

// Message is the core interface for cross-chain messages
type Message interface {
	// ID returns the unique identifier for this message
	ID() ID

	// SourceChainID returns the source blockchain identifier
	SourceChainID() ID

	// DestinationChainID returns the destination blockchain identifier
	DestinationChainID() ID

	// Payload returns the message payload
	Payload() []byte

	// Serialize returns the canonical byte representation for signing
	Serialize() ([]byte, error)
}

// AddressedMessage extends Message with contract addressing information
type AddressedMessage interface {
	Message

	// SourceAddress returns the source contract address
	SourceAddress() Address

	// DestinationAddress returns the destination contract address
	DestinationAddress() Address
}

// UnsignedMessage represents a message that can be signed
type UnsignedMessage interface {
	Message

	// Timestamp returns when the message was created
	Timestamp() time.Time

	// Nonce returns the replay protection nonce
	Nonce() uint64
}

// SignedMessage represents a message with validator signatures
type SignedMessage interface {
	UnsignedMessage

	// Signature returns the aggregated BLS signature
	Signature() []byte

	// SignerBitmap indicates which validators signed
	SignerBitmap() []byte

	// Verify checks if the signatures are valid for the given validator set
	Verify(validators ValidatorSet) error
}

// MessageFactory creates messages
type MessageFactory interface {
	// NewMessage creates a new unsigned message
	NewMessage(sourceChain, destChain ID, payload []byte) UnsignedMessage

	// NewAddressedMessage creates a new addressed message
	NewAddressedMessage(sourceChain, destChain ID, sourceAddr, destAddr Address, payload []byte) AddressedMessage
}

// Signer signs messages
type Signer interface {
	// Sign creates a signature for the message
	Sign(ctx context.Context, message UnsignedMessage) ([]byte, error)
}

// Verifier verifies message signatures
type Verifier interface {
	// Verify checks if a signature is valid
	Verify(message UnsignedMessage, signature []byte, validators ValidatorSet) error
}
