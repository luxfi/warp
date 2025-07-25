// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package payload

import (
	"errors"
	"fmt"

	"github.com/luxfi/geth/rlp"
)

// Payload types
const (
	// AddressedCall payload type ID
	AddressedCallID uint32 = 0

	// Hash payload type ID
	HashID uint32 = 1

	// L1ValidatorRegistration payload type ID
	L1ValidatorRegistrationID uint32 = 2

	// RegisterL1Validator payload type ID
	RegisterL1ValidatorID uint32 = 3

	// SubnetToL1Conversion payload type ID
	SubnetToL1ConversionID uint32 = 4

	// L1ValidatorWeight payload type ID
	L1ValidatorWeightID uint32 = 5
)

var (
	// ErrInvalidPayload is returned when a payload is invalid
	ErrInvalidPayload = errors.New("invalid payload")
)

// Payload is an interface for warp message payloads
type Payload interface {
	// Bytes returns the byte representation of the payload
	Bytes() []byte

	// Verify verifies the payload
	Verify() error
}

// ParsePayload parses a payload from bytes
func ParsePayload(bytes []byte) (Payload, error) {
	// Try to decode as each payload type
	// This is a simplified approach - in production you'd use a type registry
	var err error
	
	// Try AddressedCall
	ac := &AddressedCall{}
	if err = rlp.DecodeBytes(bytes, ac); err == nil {
		if err = ac.Verify(); err == nil {
			return ac, nil
		}
	}
	
	// Try Hash
	h := &Hash{}
	if err = rlp.DecodeBytes(bytes, h); err == nil {
		if err = h.Verify(); err == nil {
			return h, nil
		}
	}
	
	// Add other payload types as needed
	
	return nil, fmt.Errorf("%w: unable to decode payload", ErrInvalidPayload)
}

// AddressedCall is a payload for cross-VM calls
type AddressedCall struct {
	SourceAddress []byte `serialize:"true"`
	Payload       []byte `serialize:"true"`
}

// NewAddressedCall creates a new addressed call payload
func NewAddressedCall(sourceAddress []byte, payload []byte) (*AddressedCall, error) {
	ac := &AddressedCall{
		SourceAddress: sourceAddress,
		Payload:       payload,
	}
	if err := ac.Verify(); err != nil {
		return nil, err
	}
	return ac, nil
}

// Verify verifies the addressed call payload
func (a *AddressedCall) Verify() error {
	if len(a.SourceAddress) == 0 {
		return fmt.Errorf("%w: empty source address", ErrInvalidPayload)
	}
	return nil
}

// Bytes returns the byte representation of the payload
func (a *AddressedCall) Bytes() []byte {
	bytes, _ := rlp.EncodeToBytes(a)
	return bytes
}

// Hash is a simple hash payload
type Hash struct {
	Hash []byte `serialize:"true"`
}

// NewHash creates a new hash payload
func NewHash(hash []byte) (*Hash, error) {
	h := &Hash{Hash: hash}
	if err := h.Verify(); err != nil {
		return nil, err
	}
	return h, nil
}

// Verify verifies the hash payload
func (h *Hash) Verify() error {
	if len(h.Hash) != 32 {
		return fmt.Errorf("%w: hash must be 32 bytes", ErrInvalidPayload)
	}
	return nil
}

// Bytes returns the byte representation of the payload
func (h *Hash) Bytes() []byte {
	bytes, _ := rlp.EncodeToBytes(h)
	return bytes
}

// L1ValidatorRegistration represents a validator registration status
type L1ValidatorRegistration struct {
	Valid      bool   `serialize:"true"`
	Validation []byte `serialize:"true"`
}

// NewL1ValidatorRegistration creates a new L1 validator registration payload
func NewL1ValidatorRegistration(valid bool, validation []byte) (*L1ValidatorRegistration, error) {
	r := &L1ValidatorRegistration{
		Valid:      valid,
		Validation: validation,
	}
	if err := r.Verify(); err != nil {
		return nil, err
	}
	return r, nil
}

// Verify verifies the registration payload
func (r *L1ValidatorRegistration) Verify() error {
	return nil
}

// Bytes returns the byte representation of the payload
func (r *L1ValidatorRegistration) Bytes() []byte {
	bytes, _ := rlp.EncodeToBytes(r)
	return bytes
}

// RegisterL1Validator adds a validator to a subnet
type RegisterL1Validator struct {
	SubnetID        []byte `serialize:"true"`
	NodeID          []byte `serialize:"true"`
	Weight          uint64 `serialize:"true"`
	BLSPublicKey    []byte `serialize:"true"`
	RegistrationTime uint64 `serialize:"true"`
}

// NewRegisterL1Validator creates a new register L1 validator payload
func NewRegisterL1Validator(
	subnetID []byte,
	nodeID []byte,
	weight uint64,
	blsPublicKey []byte,
	registrationTime uint64,
) (*RegisterL1Validator, error) {
	r := &RegisterL1Validator{
		SubnetID:        subnetID,
		NodeID:          nodeID,
		Weight:          weight,
		BLSPublicKey:    blsPublicKey,
		RegistrationTime: registrationTime,
	}
	if err := r.Verify(); err != nil {
		return nil, err
	}
	return r, nil
}

// Verify verifies the register validator payload
func (r *RegisterL1Validator) Verify() error {
	if len(r.SubnetID) != 32 {
		return fmt.Errorf("%w: subnet ID must be 32 bytes", ErrInvalidPayload)
	}
	if len(r.NodeID) == 0 {
		return fmt.Errorf("%w: empty node ID", ErrInvalidPayload)
	}
	if r.Weight == 0 {
		return fmt.Errorf("%w: zero weight", ErrInvalidPayload)
	}
	if len(r.BLSPublicKey) == 0 {
		return fmt.Errorf("%w: empty BLS public key", ErrInvalidPayload)
	}
	return nil
}

// Bytes returns the byte representation of the payload
func (r *RegisterL1Validator) Bytes() []byte {
	bytes, _ := rlp.EncodeToBytes(r)
	return bytes
}

// SubnetToL1Conversion represents a subnet conversion message
type SubnetToL1Conversion struct {
	SubnetID []byte `serialize:"true"`
	ChainID  []byte `serialize:"true"`
	Address  []byte `serialize:"true"`
	Managers [][]byte `serialize:"true"`
}

// NewSubnetToL1Conversion creates a new subnet to L1 conversion payload
func NewSubnetToL1Conversion(
	subnetID []byte,
	chainID []byte,
	address []byte,
	managers [][]byte,
) (*SubnetToL1Conversion, error) {
	c := &SubnetToL1Conversion{
		SubnetID: subnetID,
		ChainID:  chainID,
		Address:  address,
		Managers: managers,
	}
	if err := c.Verify(); err != nil {
		return nil, err
	}
	return c, nil
}

// Verify verifies the conversion payload
func (c *SubnetToL1Conversion) Verify() error {
	if len(c.SubnetID) != 32 {
		return fmt.Errorf("%w: subnet ID must be 32 bytes", ErrInvalidPayload)
	}
	if len(c.ChainID) != 32 {
		return fmt.Errorf("%w: chain ID must be 32 bytes", ErrInvalidPayload)
	}
	return nil
}

// Bytes returns the byte representation of the payload
func (c *SubnetToL1Conversion) Bytes() []byte {
	bytes, _ := rlp.EncodeToBytes(c)
	return bytes
}

// L1ValidatorWeight represents a validator weight update
type L1ValidatorWeight struct {
	ValidationID []byte `serialize:"true"`
	Nonce        uint64 `serialize:"true"`
	Weight       uint64 `serialize:"true"`
}

// NewL1ValidatorWeight creates a new validator weight payload
func NewL1ValidatorWeight(
	validationID []byte,
	nonce uint64,
	weight uint64,
) (*L1ValidatorWeight, error) {
	w := &L1ValidatorWeight{
		ValidationID: validationID,
		Nonce:        nonce,
		Weight:       weight,
	}
	if err := w.Verify(); err != nil {
		return nil, err
	}
	return w, nil
}

// Verify verifies the weight payload
func (w *L1ValidatorWeight) Verify() error {
	if len(w.ValidationID) != 32 {
		return fmt.Errorf("%w: validation ID must be 32 bytes", ErrInvalidPayload)
	}
	return nil
}

// Bytes returns the byte representation of the payload
func (w *L1ValidatorWeight) Bytes() []byte {
	bytes, _ := rlp.EncodeToBytes(w)
	return bytes
}

// init is not needed for RLP encoding