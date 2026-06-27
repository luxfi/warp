// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
)

// BitSetSignature is the Beam lane of a Envelope: a BLS aggregate
// signature plus the bitset of validators (by canonical index) whose
// public keys aggregate to it. There is exactly one signature shape in
// Warp, so this is a concrete type, not a polymorphic interface.
//
// Wire layout inside the envelope:
//
//	Signers    u32-len ‖ trim-canonical bitset bytes
//	Signature  [96] raw BLS aggregate
//
// The Beam signs BeamSigningBytes(D) = "LUX-WARP-ZAP-BEAM-v1" ‖ D, so it
// authenticates the entire Message (including PQ lineage), not just the
// message body.
type BitSetSignature struct {
	Signers   Bits
	Signature [bls.SignatureLen]byte
}

// NewBitSetSignature creates a Beam from a signer bitset and aggregate.
func NewBitSetSignature(signers Bits, signature [bls.SignatureLen]byte) BitSetSignature {
	return BitSetSignature{Signers: signers, Signature: signature}
}

// marshalInto appends the canonical Beam encoding to dst. The Signers
// bitset is trimmed to canonical form (no trailing zero byte) so the
// encoding is unique.
func (s *BitSetSignature) marshalInto(dst []byte) []byte {
	dst = appendVar(dst, canonicalBits(s.Signers))
	dst = appendFixed(dst, s.Signature[:])
	return dst
}

// parseBeam decodes a Beam from the cursor, rejecting a non-canonical
// (trailing-zero) bitset.
func parseBeam(r *zapReader) (BitSetSignature, error) {
	var b BitSetSignature
	signers, err := r.varbytes()
	if err != nil {
		return b, fmt.Errorf("beam signers: %w", err)
	}
	if err := checkCanonicalBits(signers); err != nil {
		return b, err
	}
	b.Signers = signers
	if err := r.fixedInto(b.Signature[:]); err != nil {
		return b, fmt.Errorf("beam signature: %w", err)
	}
	return b, nil
}

// verify checks the Beam BLS aggregate against the digest D and the
// canonical validator set. It aggregates the public keys selected by the
// Signers bitset and verifies over BeamSigningBytes(d).
func (s *BitSetSignature) verify(d ids.ID, validators []*Validator) error {
	if len(s.Signers) == 0 {
		return errors.New("no signers")
	}
	if s.Signers.HighestSetBit() > len(validators) {
		return fmt.Errorf("signer index %d exceeds validator count %d", s.Signers.HighestSetBit()-1, len(validators))
	}

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

	aggPK, err := bls.AggregatePublicKeys(pks)
	if err != nil {
		return fmt.Errorf("failed to aggregate public keys: %w", err)
	}
	sig, err := bls.SignatureFromBytes(s.Signature[:])
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}
	if !bls.Verify(aggPK, sig, BeamSigningBytes(d)) {
		return ErrInvalidSignature
	}
	return nil
}

// signedWeight returns the total weight of validators in the Signers set.
func (s *BitSetSignature) signedWeight(validators []*Validator) (uint64, error) {
	if s.Signers.HighestSetBit() > len(validators) {
		return 0, fmt.Errorf("signer index %d exceeds validator count %d", s.Signers.HighestSetBit()-1, len(validators))
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

// Equal reports whether two Beams are equal (canonical bitset comparison
// plus byte-equal aggregate).
func (s *BitSetSignature) Equal(other BitSetSignature) bool {
	if !s.Signers.Equal(other.Signers) {
		return false
	}
	return s.Signature == other.Signature
}

// AggregateSignatures aggregates BLS signatures into one.
func AggregateSignatures(signatures []*bls.Signature) (*bls.Signature, error) {
	if len(signatures) == 0 {
		return nil, errors.New("no signatures to aggregate")
	}
	return bls.AggregateSignatures(signatures)
}

// Sign signs raw bytes with a secret key. Callers pass BeamSigningBytes(D)
// — the signer never signs an opaque caller-supplied digest directly.
func Sign(msg []byte, sk *bls.SecretKey) (*bls.Signature, error) {
	return sk.Sign(msg)
}

// SignMessage signs a Message over the Beam domain with a set of
// signers and assembles the Envelope. Each signer signs
// BeamSigningBytes(message.ID()); the aggregate is verifiable against the
// same bytes.
func SignMessage(message *Message, signers []*bls.SecretKey, validators []*Validator) (*Envelope, error) {
	if len(signers) == 0 {
		return nil, errors.New("no signers provided")
	}

	beamMsg := BeamSigningBytes(message.ID())

	signerBits := NewBitSet()
	signatures := make([]*bls.Signature, 0, len(signers))
	for _, sk := range signers {
		// Match by compressed public-key bytes — *bls.PublicKey pointer
		// identity is not stable across PublicKey() calls.
		pkBytes := bls.PublicKeyToCompressedBytes(sk.PublicKey())
		index := -1
		for i, v := range validators {
			if bytes.Equal(bls.PublicKeyToCompressedBytes(v.PublicKey), pkBytes) {
				index = i
				break
			}
		}
		if index == -1 {
			return nil, errors.New("signer not found in validator set")
		}
		sig, err := Sign(beamMsg, sk)
		if err != nil {
			return nil, fmt.Errorf("failed to sign: %w", err)
		}
		signerBits.Add(index)
		signatures = append(signatures, sig)
	}

	aggSig, err := AggregateSignatures(signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate signatures: %w", err)
	}

	beam := BitSetSignature{Signers: signerBits}
	copy(beam.Signature[:], bls.SignatureToBytes(aggSig))
	return NewEnvelope(message, beam, nil, nil)
}
