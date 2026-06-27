// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// envelope.go — the ONE Warp envelope. Envelope is the single signed
// message type: there is no UnsignedMessage / Message split, no V1 / V2
// envelope versions, and no cross-version dispatcher. A receiver has
// exactly one parser (ParseEnvelope) and one digest (D).

// Envelope-shape errors.
var (
	// ErrEnvelopeEmpty is returned when ParseEnvelope is given no bytes.
	ErrEnvelopeEmpty = errors.New("warp envelope is empty")

	// ErrEnvelopeTooLarge is returned when an envelope exceeds MaxEnvelopeSize.
	ErrEnvelopeTooLarge = errors.New("warp envelope exceeds maximum size")

	// ErrEnvelopeBadSuiteID is returned when the envelope's resolved
	// HashSuiteID does not match the suite the verifier expects.
	ErrEnvelopeBadSuiteID = errors.New("warp envelope hash-suite mismatch")
)

// Envelope is a complete signed Warp message:
//
//		wire: magic("LWZP"||0x01) ‖ kind(0x02) ‖ Core ‖ Beam ‖ PulseSig ‖ MLDSACertSet
//
//	  - Core         the signed subject (Core); folds PQ lineage.
//	  - Beam         the BLS aggregate over BeamSigningBytes(D).
//	  - PulseSig     optional Pulsar threshold signature bytes (u32(0) frame
//	                 when absent), verified over PulseSigningBytes(D).
//	  - MLDSACertSet optional ML-DSA cert-set bytes (or a Z-Chain Groth16
//	                 rollup), verified over MLDSASigningBytes(D).
//
// All four lanes are always present on the wire; absence of a PQ lane is
// the empty u32(0) frame, not an omitted field.
type Envelope struct {
	Core         Core
	Beam         BitSetSignature
	PulseSig     []byte
	MLDSACertSet []byte
}

// NewEnvelope assembles and structurally validates an envelope.
func NewEnvelope(core *Core, beam BitSetSignature, pulse, mldsaCertSet []byte) (*Envelope, error) {
	if core == nil {
		return nil, fmt.Errorf("%w: nil core", ErrInvalidMessage)
	}
	e := &Envelope{
		Core:         *core,
		Beam:         beam,
		PulseSig:     pulse,
		MLDSACertSet: mldsaCertSet,
	}
	if err := e.Verify(); err != nil {
		return nil, err
	}
	return e, nil
}

// Verify checks structural invariants: the core must be well-formed and
// the total PQ-lane bytes must stay under MaxEnvelopeSize.
func (e *Envelope) Verify() error {
	if e == nil {
		return ErrInvalidMessage
	}
	if err := e.Core.Verify(); err != nil {
		return err
	}
	if len(e.PulseSig)+len(e.MLDSACertSet) > MaxEnvelopeSize {
		return ErrEnvelopeTooLarge
	}
	return nil
}

// Bytes returns the canonical wire encoding of the envelope.
func (e *Envelope) Bytes() ([]byte, error) {
	if e == nil {
		return nil, ErrInvalidMessage
	}
	if err := e.Verify(); err != nil {
		return nil, err
	}
	core := e.Core.marshalZAP()
	out := make([]byte, 0, len(wireMagic)+1+len(core)+4+len(e.Beam.Signers)+SignatureLen+4+len(e.PulseSig)+4+len(e.MLDSACertSet))
	out = append(out, wireMagic[:]...)
	out = appendU8(out, kindEnvelope)
	out = append(out, core...)
	out = e.Beam.marshalInto(out)
	out = appendVar(out, e.PulseSig)
	out = appendVar(out, e.MLDSACertSet)
	if len(out) > MaxEnvelopeSize {
		return nil, ErrEnvelopeTooLarge
	}
	return out, nil
}

// ParseEnvelope decodes an envelope from its canonical wire bytes. It
// rejects: a bad/absent magic, the wrong kind byte, a non-canonical
// Signers bitset, a malformed core, and any trailing bytes.
func ParseEnvelope(b []byte) (*Envelope, error) {
	if len(b) == 0 {
		return nil, ErrEnvelopeEmpty
	}
	if len(b) > MaxEnvelopeSize {
		return nil, ErrEnvelopeTooLarge
	}

	r := newZapReader(b)
	if err := r.expectMagic(); err != nil {
		return nil, err
	}
	kind, err := r.u8()
	if err != nil {
		return nil, err
	}
	if kind != kindEnvelope {
		return nil, fmt.Errorf("%w: envelope kind 0x%02x", ErrInvalidMessage, kind)
	}

	e := &Envelope{}
	if e.Core, err = parseCore(r); err != nil {
		return nil, fmt.Errorf("failed to parse signed core: %w", err)
	}
	if e.Beam, err = parseBeam(r); err != nil {
		return nil, fmt.Errorf("failed to parse beam: %w", err)
	}
	if e.PulseSig, err = r.varbytes(); err != nil {
		return nil, fmt.Errorf("failed to parse pulse: %w", err)
	}
	if e.MLDSACertSet, err = r.varbytes(); err != nil {
		return nil, fmt.Errorf("failed to parse mldsa cert set: %w", err)
	}
	if err := r.end(); err != nil {
		return nil, err
	}
	if err := e.Verify(); err != nil {
		return nil, err
	}
	return e, nil
}

// ID returns D, the Warp message ID (recomputed from Core, not sliced
// from the wire). v1/v2 distinctions are gone: there is one ID per
// message and it is the replay key.
func (e *Envelope) ID() ids.ID { return e.Core.ID() }

// GetSourceChainID returns the source chain ID.
func (e *Envelope) GetSourceChainID() ids.ID { return e.Core.SourceChainID }

// SourceChainIDHash returns the source chain ID as a common.Hash.
func (e *Envelope) SourceChainIDHash() common.Hash {
	return common.BytesToHash(e.Core.SourceChainID[:])
}

// HashSuite returns the envelope's resolved hash suite.
func (e *Envelope) HashSuite() string { return e.Core.HashSuiteOrDefault() }

// HasPulse reports whether the envelope carries a Pulsar pulse.
func (e *Envelope) HasPulse() bool { return e != nil && len(e.PulseSig) > 0 }

// HasMLDSACertSet reports whether the envelope carries an ML-DSA cert set.
func (e *Envelope) HasMLDSACertSet() bool { return e != nil && len(e.MLDSACertSet) > 0 }

// Equal reports whether two envelopes are byte-equal under canonical
// serialization.
func (e *Envelope) Equal(other *Envelope) bool {
	if e == nil || other == nil {
		return e == other
	}
	a, errA := e.Bytes()
	b, errB := other.Bytes()
	if errA != nil || errB != nil {
		return false
	}
	return bytes.Equal(a, b)
}

// VerifyEnvelope verifies the Beam lane of an envelope against the
// source-chain validator set and quorum. This is the canonical
// classical-path verification: network-ID match, quorum weight, and BLS
// aggregate over BeamSigningBytes(D).
func VerifyEnvelope(
	e *Envelope,
	networkID uint32,
	validatorState ValidatorState,
	quorumNum uint64,
	quorumDen uint64,
) error {
	if err := e.Verify(); err != nil {
		return err
	}
	if e.Core.NetworkID != networkID {
		return fmt.Errorf("%w: expected network ID %d, got %d", ErrInvalidMessage, networkID, e.Core.NetworkID)
	}

	vdrSet, totalWeight, err := GetCanonicalValidatorSet(validatorState, e.Core.SourceChainID)
	if err != nil {
		return fmt.Errorf("failed to get validator set: %w", err)
	}

	signedWeight, err := e.Beam.signedWeight(vdrSet)
	if err != nil {
		return fmt.Errorf("failed to get signed weight: %w", err)
	}
	if err := VerifyWeight(signedWeight, totalWeight, quorumNum, quorumDen); err != nil {
		return err
	}
	return e.Beam.verify(e.Core.ID(), vdrSet)
}

// PulseVerifier verifies an envelope's Pulsar Pulse lane. The
// implementation lives in warp/pulsar (so this package does not import
// the threshold kernel). It MUST recompute D from env.Core and verify the
// Pulse over PulseSigningBytes(D), binding all of SourceChainID,
// SourceNebulaRoot, SourceKeyEraID, SourceGeneration, HashSuiteID via D.
type PulseVerifier interface {
	VerifyPulse(env *Envelope) error
}

// MLDSACertSetVerifier verifies an envelope's ML-DSA cert-set lane over
// MLDSASigningBytes(D).
type MLDSACertSetVerifier interface {
	VerifyCertSet(env *Envelope) error
}

// VerifyOptions bundles the verifications a receiver applies to an
// envelope. A nil Pulse / CertSet skips that lane; Require* demands the
// lane be present, a verifier be configured, and verification succeed.
type VerifyOptions struct {
	NetworkID      uint32
	ValidatorState ValidatorState
	QuorumNum      uint64
	QuorumDen      uint64

	Pulse          PulseVerifier
	CertSet        MLDSACertSetVerifier
	RequirePulse   bool
	RequireCertSet bool

	// HashSuiteID is the suite the receiver expects. Empty accepts
	// whatever the envelope declares (after defaulting).
	HashSuiteID string

	// SkipBeam skips BLS Beam verification. Used by receivers that have
	// already validated the Beam elsewhere, and by tests exercising the
	// PQ-lane plumbing without a full validator set.
	SkipBeam bool
}

// VerifyWithOptions verifies an envelope under opts: structural
// invariants, hash-suite consistency, the Beam lane (unless SkipBeam),
// then the ML-DSA and Pulse lanes.
func VerifyWithOptions(e *Envelope, opts VerifyOptions) error {
	if err := e.Verify(); err != nil {
		return err
	}
	if opts.HashSuiteID != "" && e.HashSuite() != opts.HashSuiteID {
		return fmt.Errorf("%w: expected %q, got %q", ErrEnvelopeBadSuiteID, opts.HashSuiteID, e.HashSuite())
	}
	if !opts.SkipBeam {
		if err := VerifyEnvelope(e, opts.NetworkID, opts.ValidatorState, opts.QuorumNum, opts.QuorumDen); err != nil {
			return err
		}
	}
	return verifyPQLanes(e, opts)
}

// VerifyPQLanes runs only the PQ-lane verifications (skipping the Beam),
// for receivers that have already verified the Beam separately.
func VerifyPQLanes(e *Envelope, opts VerifyOptions) error {
	if err := e.Verify(); err != nil {
		return err
	}
	if opts.HashSuiteID != "" && e.HashSuite() != opts.HashSuiteID {
		return fmt.Errorf("%w: expected %q, got %q", ErrEnvelopeBadSuiteID, opts.HashSuiteID, e.HashSuite())
	}
	return verifyPQLanes(e, opts)
}

func verifyPQLanes(e *Envelope, opts VerifyOptions) error {
	// ML-DSA cert-set lane.
	if e.HasMLDSACertSet() {
		if opts.CertSet == nil {
			if opts.RequireCertSet {
				return fmt.Errorf("%w: ML-DSA cert set lane required but no verifier configured", ErrInvalidMessage)
			}
		} else if err := opts.CertSet.VerifyCertSet(e); err != nil {
			return fmt.Errorf("ml-dsa cert set verify: %w", err)
		}
	} else if opts.RequireCertSet {
		return fmt.Errorf("%w: ML-DSA cert set lane required but absent from envelope", ErrInvalidMessage)
	}

	// Pulsar Pulse lane.
	if e.HasPulse() {
		if opts.Pulse == nil {
			if opts.RequirePulse {
				return fmt.Errorf("%w: Pulsar Pulse lane required but no verifier configured", ErrInvalidMessage)
			}
		} else if err := opts.Pulse.VerifyPulse(e); err != nil {
			return fmt.Errorf("pulsar pulse verify: %w", err)
		}
	} else if opts.RequirePulse {
		return fmt.Errorf("%w: Pulsar Pulse lane required but absent from envelope", ErrInvalidMessage)
	}

	return nil
}
