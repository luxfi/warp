// Copyright (C) 2025, Lux Industries, Inc.
// See the file LICENSE for licensing terms.

package types

// Validator represents a network validator
type Validator interface {
	// NodeID returns the validator's node identifier
	NodeID() ID
	
	// PublicKey returns the validator's public key
	PublicKey() []byte
	
	// Weight returns the validator's voting weight
	Weight() uint64
}

// ValidatorSet represents a set of validators at a specific height
type ValidatorSet interface {
	// GetValidator returns a validator by index
	GetValidator(index int) (Validator, error)
	
	// Validators returns all validators in the set
	Validators() []Validator
	
	// TotalWeight returns the total weight of all validators
	TotalWeight() uint64
	
	// Threshold returns the minimum weight needed for consensus
	Threshold() uint64
	
	// Height returns the blockchain height this set is valid for
	Height() uint64
	
	// Contains checks if a validator is in the set
	Contains(nodeID ID) (Validator, bool)
}