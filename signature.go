// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"errors"
	"fmt"

	"github.com/luxfi/warp/bls"
)

// Signature is an interface for warp message signatures
type Signature interface {
	// Verify verifies the signature against the message and validator set
	Verify(msg []byte, validators []*Validator) error

	// GetSignedWeight returns the total weight of validators that signed
	GetSignedWeight(validators []*Validator) (uint64, error)

	// Equal returns true if two signatures are equal
	Equal(other Signature) bool
}

// BitSetSignature is a signature that uses a bit set to indicate which validators signed
type BitSetSignature struct {
	Signers   Bits       `serialize:"true"`
	Signature [bls.SignatureLen]byte `serialize:"true"`
}

// NewBitSetSignature creates a new bit set signature
func NewBitSetSignature(signers Bits, signature [bls.SignatureLen]byte) *BitSetSignature {
	return &BitSetSignature{
		Signers:   signers,
		Signature: signature,
	}
}

// Verify verifies the signature against the message and validator set
func (s *BitSetSignature) Verify(msg []byte, validators []*Validator) error {
	if len(s.Signers) == 0 {
		return errors.New("no signers")
	}

	if s.Signers.BitLen() > len(validators) {
		return fmt.Errorf("bit set length %d exceeds validator count %d", s.Signers.BitLen(), len(validators))
	}

	// Aggregate public keys of signers
	pks := make([]*bls.PublicKey, 0, s.Signers.Len())
	for i := 0; i < s.Signers.BitLen(); i++ {
		if !s.Signers.Contains(i) {
			continue
		}

		if i >= len(validators) {
			return fmt.Errorf("signer index %d exceeds validator count %d", i, len(validators))
		}

		pk := validators[i].PublicKey
		if pk == nil {
			return fmt.Errorf("validator %d has nil public key", i)
		}

		pks = append(pks, pk)
	}

	if len(pks) == 0 {
		return errors.New("no valid signers")
	}

	// Aggregate public keys
	aggPK, err := bls.AggregatePublicKeys(pks)
	if err != nil {
		return fmt.Errorf("failed to aggregate public keys: %w", err)
	}

	// Verify aggregated signature
	sig, err := bls.SignatureFromBytes(s.Signature[:])
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	if !bls.Verify(aggPK, sig, msg) {
		return ErrInvalidSignature
	}

	return nil
}

// GetSignedWeight returns the total weight of validators that signed
func (s *BitSetSignature) GetSignedWeight(validators []*Validator) (uint64, error) {
	if s.Signers.BitLen() > len(validators) {
		return 0, fmt.Errorf("bit set length %d exceeds validator count %d", s.Signers.BitLen(), len(validators))
	}

	var weight uint64
	for i := 0; i < s.Signers.BitLen(); i++ {
		if !s.Signers.Contains(i) {
			continue
		}

		if i >= len(validators) {
			return 0, fmt.Errorf("signer index %d exceeds validator count %d", i, len(validators))
		}

		newWeight, err := AddUint64(weight, validators[i].Weight)
		if err != nil {
			return 0, fmt.Errorf("weight overflow: %w", err)
		}
		weight = newWeight
	}

	return weight, nil
}

// Equal returns true if two signatures are equal
func (s *BitSetSignature) Equal(other Signature) bool {
	otherBitSet, ok := other.(*BitSetSignature)
	if !ok {
		return false
	}

	if !s.Signers.Equal(otherBitSet.Signers) {
		return false
	}

	return s.Signature == otherBitSet.Signature
}

// AggregateSignatures aggregates multiple signatures into one
func AggregateSignatures(signatures []*bls.Signature) (*bls.Signature, error) {
	if len(signatures) == 0 {
		return nil, errors.New("no signatures to aggregate")
	}

	return bls.AggregateSignatures(signatures)
}

// Sign creates a signature for a message using a private key
func Sign(msg []byte, sk *bls.PrivateKey) (*bls.Signature, error) {
	return bls.Sign(sk, msg)
}

// SignMessage signs a warp message with a set of signers
func SignMessage(
	msg *UnsignedMessage,
	signers []*bls.PrivateKey,
	validators []*Validator,
) (*Message, error) {
	if len(signers) == 0 {
		return nil, errors.New("no signers provided")
	}

	msgBytes := msg.Bytes()

	// Create bit set for signers
	signerBits := NewBitSet()
	signatures := make([]*bls.Signature, 0, len(signers))

	// Sign with each signer
	for _, sk := range signers {
		// Find validator index for this signer
		pk := bls.PublicFromPrivateKey(sk)
		index := -1
		for i, v := range validators {
			if v.PublicKey.Equal(pk) {
				index = i
				break
			}
		}

		if index == -1 {
			return nil, fmt.Errorf("signer not found in validator set")
		}

		// Sign the message
		sig, err := Sign(msgBytes, sk)
		if err != nil {
			return nil, fmt.Errorf("failed to sign: %w", err)
		}

		signerBits.Add(index)
		signatures = append(signatures, sig)
	}

	// Aggregate signatures
	aggSig, err := AggregateSignatures(signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate signatures: %w", err)
	}

	// Create bit set signature
	aggSigBytes := [bls.SignatureLen]byte{}
	copy(aggSigBytes[:], aggSig.Bytes())

	signature := &BitSetSignature{
		Signers:   signerBits,
		Signature: aggSigBytes,
	}

	return NewMessage(msg, signature)
}