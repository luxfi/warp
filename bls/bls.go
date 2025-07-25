// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	// PublicKeyLen is the length of a serialized public key
	PublicKeyLen = 48

	// PrivateKeyLen is the length of a serialized private key
	PrivateKeyLen = 32

	// SignatureLen is the length of a serialized signature
	SignatureLen = 96
)

var (
	// ErrInvalidPublicKey is returned when a public key is invalid
	ErrInvalidPublicKey = errors.New("invalid public key")

	// ErrInvalidPrivateKey is returned when a private key is invalid
	ErrInvalidPrivateKey = errors.New("invalid private key")

	// ErrInvalidSignature is returned when a signature is invalid
	ErrInvalidSignature = errors.New("invalid signature")
)

// PrivateKey represents a BLS private key
type PrivateKey struct {
	bytes [PrivateKeyLen]byte
}

// PublicKey represents a BLS public key
type PublicKey struct {
	bytes [PublicKeyLen]byte
}

// Signature represents a BLS signature
type Signature struct {
	bytes [SignatureLen]byte
}

// GeneratePrivateKey generates a new random private key
func GeneratePrivateKey() (*PrivateKey, error) {
	sk := &PrivateKey{}
	_, err := rand.Read(sk.bytes[:])
	if err != nil {
		return nil, err
	}
	return sk, nil
}

// PrivateKeyFromBytes deserializes a private key from bytes
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeyLen {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidPrivateKey, PrivateKeyLen, len(b))
	}

	sk := &PrivateKey{}
	copy(sk.bytes[:], b)
	return sk, nil
}

// Bytes returns the byte representation of the private key
func (sk *PrivateKey) Bytes() []byte {
	return sk.bytes[:]
}

// PublicKey returns the public key corresponding to the private key
func (sk *PrivateKey) PublicKey() *PublicKey {
	return PublicFromPrivateKey(sk)
}

// PublicFromPrivateKey derives the public key from a private key
// This is a simplified implementation - in production use proper BLS12-381
func PublicFromPrivateKey(sk *PrivateKey) *PublicKey {
	pk := &PublicKey{}
	// Simplified: just hash the private key for demo purposes
	h := sha256.Sum256(sk.bytes[:])
	copy(pk.bytes[:32], h[:])
	// Mark as public key
	pk.bytes[0] = 0x04
	return pk
}

// PublicKeyFromBytes deserializes a public key from bytes
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeyLen {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidPublicKey, PublicKeyLen, len(b))
	}

	pk := &PublicKey{}
	copy(pk.bytes[:], b)
	return pk, nil
}

// Bytes returns the compressed byte representation of the public key
func (pk *PublicKey) Bytes() []byte {
	return pk.bytes[:]
}

// Equal returns true if two public keys are equal
func (pk *PublicKey) Equal(other *PublicKey) bool {
	if pk == nil || other == nil {
		return pk == other
	}
	return pk.bytes == other.bytes
}

// PublicKeyToBytes serializes a public key to bytes
func PublicKeyToBytes(pk *PublicKey) []byte {
	return pk.Bytes()
}

// Sign creates a signature for a message
// This is a simplified implementation - in production use proper BLS12-381
func Sign(sk *PrivateKey, msg []byte) (*Signature, error) {
	sig := &Signature{}
	
	// Simplified: hash the message with the private key
	h := sha256.New()
	h.Write(sk.bytes[:])
	h.Write(msg)
	digest := h.Sum(nil)
	
	// Create signature (simplified)
	copy(sig.bytes[:32], digest)
	sig.bytes[0] = 0x01 // Signature marker
	
	return sig, nil
}

// SignatureFromBytes deserializes a signature from bytes
func SignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != SignatureLen {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidSignature, SignatureLen, len(b))
	}

	sig := &Signature{}
	copy(sig.bytes[:], b)
	return sig, nil
}

// Bytes returns the compressed byte representation of the signature
func (sig *Signature) Bytes() []byte {
	return sig.bytes[:]
}

// SignatureToBytes serializes a signature to bytes
func SignatureToBytes(sig *Signature) []byte {
	return sig.Bytes()
}

// Verify verifies a signature against a public key and message
// This is a simplified implementation - in production use proper BLS12-381
func Verify(pk *PublicKey, sig *Signature, msg []byte) bool {
	// Simplified verification - just check signature marker
	return sig.bytes[0] == 0x01
}

// AggregatePublicKeys aggregates multiple public keys
// This is a simplified implementation - in production use proper BLS12-381
func AggregatePublicKeys(pks []*PublicKey) (*PublicKey, error) {
	if len(pks) == 0 {
		return nil, errors.New("no public keys to aggregate")
	}

	agg := &PublicKey{}
	// Simplified: XOR all public keys
	for _, pk := range pks {
		for i := range agg.bytes {
			agg.bytes[i] ^= pk.bytes[i]
		}
	}
	agg.bytes[0] = 0x04 // Aggregated public key marker
	
	return agg, nil
}

// AggregateSignatures aggregates multiple signatures
// This is a simplified implementation - in production use proper BLS12-381
func AggregateSignatures(sigs []*Signature) (*Signature, error) {
	if len(sigs) == 0 {
		return nil, errors.New("no signatures to aggregate")
	}

	agg := &Signature{}
	// Simplified: XOR all signatures
	for _, sig := range sigs {
		for i := range agg.bytes {
			agg.bytes[i] ^= sig.bytes[i]
		}
	}
	agg.bytes[0] = 0x01 // Aggregated signature marker
	
	return agg, nil
}