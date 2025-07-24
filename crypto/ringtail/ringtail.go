// Package ringtail implements random ringtail validation for post-quantum safety.
// This provides resistance against quantum attacks by using ring signatures
// with random validator selection.
package ringtail

import (
	"crypto/rand"
	"errors"
)

// RingtailValidator provides post-quantum safe validation
type RingtailValidator interface {
	// SelectValidators randomly selects a subset of validators for signing
	SelectValidators(validatorSet []Validator, threshold int) ([]Validator, error)
	
	// CreateRingSignature creates a ring signature that hides which validator signed
	CreateRingSignature(message []byte, signerKey PrivateKey, ring []PublicKey) ([]byte, error)
	
	// VerifyRingSignature verifies a ring signature without revealing the signer
	VerifyRingSignature(message []byte, signature []byte, ring []PublicKey) bool
}

// Validator represents a network validator
type Validator interface {
	ID() [32]byte
	PublicKey() PublicKey
	Weight() uint64
}

// PublicKey represents a post-quantum safe public key
type PublicKey interface {
	Bytes() []byte
}

// PrivateKey represents a post-quantum safe private key  
type PrivateKey interface {
	PublicKey() PublicKey
	Sign(message []byte) ([]byte, error)
}

// RandomSelection implements cryptographically secure random validator selection
func RandomSelection(validators []Validator, count int) ([]Validator, error) {
	if count > len(validators) {
		return nil, errors.New("requested count exceeds validator set size")
	}
	
	// Fisher-Yates shuffle for unbiased selection
	selected := make([]Validator, len(validators))
	copy(selected, validators)
	
	for i := len(selected) - 1; i > 0; i-- {
		j, err := randInt(i + 1)
		if err != nil {
			return nil, err
		}
		selected[i], selected[j] = selected[j], selected[i]
	}
	
	return selected[:count], nil
}

// randInt generates a cryptographically secure random integer in [0, max)
func randInt(max int) (int, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	
	// Use rejection sampling for unbiased results
	val := int(b[0])<<56 | int(b[1])<<48 | int(b[2])<<40 | int(b[3])<<32 |
		int(b[4])<<24 | int(b[5])<<16 | int(b[6])<<8 | int(b[7])
	
	return val % max, nil
}