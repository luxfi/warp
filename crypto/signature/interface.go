// Copyright (C) 2025, Lux Industries, Inc.
// See the file LICENSE for licensing terms.

// Package signature provides modular signature verification for Warp messages.
// This allows swapping between different signature schemes (BLS, Ringtail, Hybrid).
package signature

import (
	"context"
	"errors"
)

// Scheme represents a signature scheme type
type Scheme string

const (
	// SchemeBLS uses BLS signatures (Warp V1 compatible)
	SchemeBLS Scheme = "bls"
	
	// SchemeRingtail uses post-quantum ring signatures
	SchemeRingtail Scheme = "ringtail"
	
	// SchemeHybrid uses both BLS and Ringtail for migration period
	SchemeHybrid Scheme = "hybrid"
)

// Verifier provides modular signature verification
type Verifier interface {
	// Scheme returns the signature scheme this verifier uses
	Scheme() Scheme
	
	// Verify checks if a signature is valid for the given message
	Verify(ctx context.Context, message []byte, signature Signature, signers SignerSet) error
	
	// VerifyAggregate verifies an aggregated signature from multiple signers
	VerifyAggregate(ctx context.Context, message []byte, signature Signature, signers SignerSet) error
}

// Signer provides modular signature creation
type Signer interface {
	// Scheme returns the signature scheme this signer uses
	Scheme() Scheme
	
	// Sign creates a signature for the message
	Sign(ctx context.Context, message []byte, key PrivateKey) (Signature, error)
	
	// AggregateSign creates an aggregated signature with other signers
	AggregateSign(ctx context.Context, message []byte, keys []PrivateKey) (Signature, error)
}

// Signature represents a signature that can be from any scheme
type Signature interface {
	// Scheme returns which signature scheme created this signature
	Scheme() Scheme
	
	// Bytes returns the serialized signature
	Bytes() []byte
	
	// Verify checks if this signature is valid (self-contained verification)
	Verify(message []byte, publicKey PublicKey) error
}

// SignerSet represents a set of signers (validators)
type SignerSet interface {
	// GetSigner returns a signer by index
	GetSigner(index int) (PublicKey, uint64, error)
	
	// TotalWeight returns the total weight of all signers
	TotalWeight() uint64
	
	// Threshold returns the minimum weight needed for validity
	Threshold() uint64
	
	// Contains checks if a public key is in the set
	Contains(key PublicKey) (index int, weight uint64, exists bool)
}

// PublicKey interface for all signature schemes
type PublicKey interface {
	// Scheme returns which signature scheme this key is for
	Scheme() Scheme
	
	// Bytes returns the serialized public key
	Bytes() []byte
	
	// Equal checks if two public keys are the same
	Equal(other PublicKey) bool
}

// PrivateKey interface for all signature schemes
type PrivateKey interface {
	// PublicKey returns the corresponding public key
	PublicKey() PublicKey
	
	// Bytes returns the serialized private key (handle with care!)
	Bytes() []byte
}

// Registry manages available signature schemes
type Registry struct {
	verifiers map[Scheme]Verifier
	signers   map[Scheme]Signer
	preferred Scheme
}

// NewRegistry creates a new signature scheme registry
func NewRegistry(preferred Scheme) *Registry {
	return &Registry{
		verifiers: make(map[Scheme]Verifier),
		signers:   make(map[Scheme]Signer),
		preferred: preferred,
	}
}

// Register adds a signature scheme to the registry
func (r *Registry) Register(scheme Scheme, verifier Verifier, signer Signer) error {
	if verifier.Scheme() != scheme || signer.Scheme() != scheme {
		return errors.New("scheme mismatch")
	}
	r.verifiers[scheme] = verifier
	r.signers[scheme] = signer
	return nil
}

// GetVerifier returns a verifier for the specified scheme
func (r *Registry) GetVerifier(scheme Scheme) (Verifier, error) {
	v, ok := r.verifiers[scheme]
	if !ok {
		return nil, errors.New("unknown signature scheme")
	}
	return v, nil
}

// GetSigner returns a signer for the specified scheme
func (r *Registry) GetSigner(scheme Scheme) (Signer, error) {
	s, ok := r.signers[scheme]
	if !ok {
		return nil, errors.New("unknown signature scheme")
	}
	return s, nil
}

// PreferredScheme returns the currently preferred signature scheme
func (r *Registry) PreferredScheme() Scheme {
	return r.preferred
}

// SetPreferred changes the preferred signature scheme
func (r *Registry) SetPreferred(scheme Scheme) error {
	if _, ok := r.verifiers[scheme]; !ok {
		return errors.New("scheme not registered")
	}
	r.preferred = scheme
	return nil
}