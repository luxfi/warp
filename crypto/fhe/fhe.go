// Package fhe provides Fully Homomorphic Encryption interfaces for private messaging.
// This enables processing encrypted messages without decryption, preserving privacy
// across chain boundaries.
package fhe

import (
	"errors"
)

// Scheme represents an FHE encryption scheme
type Scheme interface {
	// Encrypt encrypts a plaintext message
	Encrypt(plaintext []byte, publicKey PublicKey) (Ciphertext, error)
	
	// Decrypt decrypts a ciphertext
	Decrypt(ciphertext Ciphertext, privateKey PrivateKey) ([]byte, error)
	
	// Evaluate performs homomorphic evaluation on encrypted data
	Evaluate(op Operation, ciphertexts ...Ciphertext) (Ciphertext, error)
	
	// GenerateKeys generates a new public/private key pair
	GenerateKeys() (PublicKey, PrivateKey, error)
}

// Ciphertext represents encrypted data that supports homomorphic operations
type Ciphertext interface {
	// Bytes returns the serialized ciphertext
	Bytes() []byte
	
	// Add performs homomorphic addition with another ciphertext
	Add(other Ciphertext) (Ciphertext, error)
	
	// Multiply performs homomorphic multiplication with another ciphertext
	Multiply(other Ciphertext) (Ciphertext, error)
}

// PublicKey for FHE encryption
type PublicKey interface {
	Bytes() []byte
}

// PrivateKey for FHE decryption
type PrivateKey interface {
	Bytes() []byte
}

// Operation represents a homomorphic operation
type Operation int

const (
	OpAdd Operation = iota
	OpMultiply
	OpXOR
)

// PrivateMessage represents an FHE-encrypted cross-chain message
type PrivateMessage struct {
	// Encrypted source chain ID
	SourceChain Ciphertext
	
	// Encrypted destination chain ID  
	DestChain Ciphertext
	
	// Encrypted payload
	Payload Ciphertext
	
	// Public metadata (for routing)
	Metadata []byte
}

// ErrInvalidCiphertext is returned when ciphertext is malformed
var ErrInvalidCiphertext = errors.New("invalid ciphertext")

// ErrIncompatibleCiphertexts is returned when ciphertexts can't be combined
var ErrIncompatibleCiphertexts = errors.New("incompatible ciphertexts")