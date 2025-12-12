// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// Validator represents a validator in the network
type Validator struct {
	PublicKey      *bls.PublicKey
	PublicKeyBytes []byte
	Weight         uint64
	NodeID         ids.NodeID
}

// NewValidator creates a new validator
func NewValidator(
	publicKey *bls.PublicKey,
	publicKeyBytes []byte,
	weight uint64,
	nodeID ids.NodeID,
) *Validator {
	return &Validator{
		PublicKey:      publicKey,
		PublicKeyBytes: publicKeyBytes,
		Weight:         weight,
		NodeID:         nodeID,
	}
}

// Less returns true if this validator is less than the other
func (v *Validator) Less(other *Validator) bool {
	return bytes.Compare(v.PublicKeyBytes, other.PublicKeyBytes) < 0
}

// CanonicalValidatorSet represents the canonical ordering of validators
type CanonicalValidatorSet struct {
	validators  []*Validator
	totalWeight uint64
}

// NewCanonicalValidatorSet creates a new canonical validator set
func NewCanonicalValidatorSet(validators []*Validator) (*CanonicalValidatorSet, error) {
	if len(validators) == 0 {
		return nil, errors.New("empty validator set")
	}

	// Check for duplicates and calculate total weight
	seen := make(map[string]bool)
	var totalWeight uint64

	for _, v := range validators {
		if v == nil {
			return nil, errors.New("nil validator")
		}
		if v.Weight == 0 {
			return nil, errors.New("validator has zero weight")
		}
		if len(v.PublicKeyBytes) == 0 {
			return nil, errors.New("validator has empty public key")
		}

		key := string(v.PublicKeyBytes)
		if seen[key] {
			return nil, fmt.Errorf("duplicate validator public key: %x", v.PublicKeyBytes)
		}
		seen[key] = true

		newWeight, err := AddUint64(totalWeight, v.Weight)
		if err != nil {
			return nil, fmt.Errorf("total weight overflow: %w", err)
		}
		totalWeight = newWeight
	}

	// Sort validators by public key
	sortedValidators := make([]*Validator, len(validators))
	copy(sortedValidators, validators)
	sort.Slice(sortedValidators, func(i, j int) bool {
		return sortedValidators[i].Less(sortedValidators[j])
	})

	return &CanonicalValidatorSet{
		validators:  sortedValidators,
		totalWeight: totalWeight,
	}, nil
}

// Validators returns the validators in canonical order
func (c *CanonicalValidatorSet) Validators() []*Validator {
	return c.validators
}

// TotalWeight returns the total weight of all validators
func (c *CanonicalValidatorSet) TotalWeight() uint64 {
	return c.totalWeight
}

// GetValidator returns the validator at the given index
func (c *CanonicalValidatorSet) GetValidator(index int) (*Validator, error) {
	if index < 0 || index >= len(c.validators) {
		return nil, fmt.Errorf("validator index %d out of range [0, %d)", index, len(c.validators))
	}
	return c.validators[index], nil
}

// Len returns the number of validators
func (c *CanonicalValidatorSet) Len() int {
	return len(c.validators)
}

// ValidatorState is an interface for retrieving validator sets
type ValidatorState interface {
	// GetValidatorSet returns the validator set for a given chain ID at a given height
	GetValidatorSet(chainID ids.ID, height uint64) (map[ids.NodeID]*Validator, error)

	// GetCurrentHeight returns the current height
	GetCurrentHeight() (uint64, error)
}

// GetCanonicalValidatorSet retrieves and canonicalizes the validator set
func GetCanonicalValidatorSet(
	validatorState ValidatorState,
	chainID ids.ID,
) ([]*Validator, uint64, error) {
	height, err := validatorState.GetCurrentHeight()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get current height: %w", err)
	}

	validatorMap, err := validatorState.GetValidatorSet(chainID, height)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get validator set: %w", err)
	}

	if len(validatorMap) == 0 {
		return nil, 0, errors.New("empty validator set")
	}

	// Convert map to slice
	validators := make([]*Validator, 0, len(validatorMap))
	for _, v := range validatorMap {
		validators = append(validators, v)
	}

	// Create canonical set
	canonicalSet, err := NewCanonicalValidatorSet(validators)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create canonical validator set: %w", err)
	}

	return canonicalSet.Validators(), canonicalSet.TotalWeight(), nil
}

// ValidatorSetToMap converts a validator slice to a map keyed by node ID
func ValidatorSetToMap(validators []*Validator) map[ids.NodeID]*Validator {
	vMap := make(map[ids.NodeID]*Validator, len(validators))
	for _, v := range validators {
		vMap[v.NodeID] = v
	}
	return vMap
}

// ParsePublicKey parses a BLS public key from bytes
func ParsePublicKey(publicKeyBytes []byte) (*bls.PublicKey, error) {
	return bls.PublicKeyFromCompressedBytes(publicKeyBytes)
}

// SerializePublicKey serializes a BLS public key to bytes
func SerializePublicKey(publicKey *bls.PublicKey) []byte {
	return bls.PublicKeyToCompressedBytes(publicKey)
}

// ValidateValidatorSet performs validation on a validator set
func ValidateValidatorSet(validators []*Validator) error {
	if len(validators) == 0 {
		return errors.New("empty validator set")
	}

	seen := make(map[string]bool)
	for i, v := range validators {
		if v == nil {
			return fmt.Errorf("nil validator at index %d", i)
		}
		if v.Weight == 0 {
			return fmt.Errorf("validator at index %d has zero weight", i)
		}
		if len(v.PublicKeyBytes) == 0 {
			return fmt.Errorf("validator at index %d has empty public key", i)
		}
		if v.PublicKey == nil {
			return fmt.Errorf("validator at index %d has nil public key object", i)
		}

		key := string(v.PublicKeyBytes)
		if seen[key] {
			return fmt.Errorf("duplicate validator public key at index %d: %x", i, v.PublicKeyBytes)
		}
		seen[key] = true
	}

	return nil
}

// ChainIDToHash converts a chain ID to a common.Hash
func ChainIDToHash(chainID ids.ID) common.Hash {
	return common.BytesToHash(chainID[:])
}
