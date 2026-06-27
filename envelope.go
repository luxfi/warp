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

// Envelope is the Quasar finality envelope — a complete signed Warp message
// composing one or more finality-evidence lanes:
//
//		wire: magic("LWZP"||0x01) ‖ kind(0x02) ‖ Message ‖ Beam ‖ CoronaSig ‖ MLDSACertSet
//
//	  - Message      the signed subject (Message); folds PQ lineage.
//	  - Beam         the BLS aggregate over BeamSigningBytes(D)        (EvidenceBeamBLS).
//	  - CoronaSig    optional Corona Ringtail (Module-LWE) lattice threshold
//	                 signature bytes (u32(0) frame when absent), verified over
//	                 CoronaSigningBytes(D)                             (EvidenceCoronaRingtail).
//	                 (Formerly mislabeled "PulseSig" — it is the corona lane,
//	                 NOT threshold ML-DSA / Pulsar.)
//	  - MLDSACertSet optional independent per-validator ML-DSA-65 cert-set
//	                 bytes (or a Z-Chain Groth16 rollup), verified over
//	                 MLDSASigningBytes(D)                              (EvidenceMLDSACertSet).
//
// The Pulsar (threshold ML-DSA) lane has NO wire field: it is a reserved,
// fail-closed evidence KIND (see evidence.go), not a carried lane.
//
// All wire fields are always present; absence of a PQ lane is the empty
// u32(0) frame, not an omitted field.
type Envelope struct {
	Message      Message
	Beam         BitSetSignature
	CoronaSig    []byte
	MLDSACertSet []byte
}

// NewEnvelope assembles and structurally validates an envelope. The
// coronaSig argument is the Corona Ringtail lattice-threshold lane (formerly
// "pulse").
func NewEnvelope(message *Message, beam BitSetSignature, coronaSig, mldsaCertSet []byte) (*Envelope, error) {
	if message == nil {
		return nil, fmt.Errorf("%w: nil message", ErrInvalidMessage)
	}
	e := &Envelope{
		Message:      *message,
		Beam:         beam,
		CoronaSig:    coronaSig,
		MLDSACertSet: mldsaCertSet,
	}
	if err := e.Verify(); err != nil {
		return nil, err
	}
	return e, nil
}

// Verify checks structural invariants: the message must be well-formed and
// the total PQ-lane bytes must stay under MaxEnvelopeSize.
func (e *Envelope) Verify() error {
	if e == nil {
		return ErrInvalidMessage
	}
	if err := e.Message.Verify(); err != nil {
		return err
	}
	if len(e.CoronaSig)+len(e.MLDSACertSet) > MaxEnvelopeSize {
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
	message := e.Message.marshalZAP()
	out := make([]byte, 0, len(wireMagic)+1+len(message)+4+len(e.Beam.Signers)+SignatureLen+4+len(e.CoronaSig)+4+len(e.MLDSACertSet))
	out = append(out, wireMagic[:]...)
	out = appendU8(out, kindEnvelope)
	out = append(out, message...)
	out = e.Beam.marshalInto(out)
	out = appendVar(out, e.CoronaSig)
	out = appendVar(out, e.MLDSACertSet)
	if len(out) > MaxEnvelopeSize {
		return nil, ErrEnvelopeTooLarge
	}
	return out, nil
}

// ParseEnvelope decodes an envelope from its canonical wire bytes. It
// rejects: a bad/absent magic, the wrong kind byte, a non-canonical
// Signers bitset, a malformed message, and any trailing bytes.
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
	if e.Message, err = parseMessage(r); err != nil {
		return nil, fmt.Errorf("failed to parse signed message: %w", err)
	}
	if e.Beam, err = parseBeam(r); err != nil {
		return nil, fmt.Errorf("failed to parse beam: %w", err)
	}
	if e.CoronaSig, err = r.varbytes(); err != nil {
		return nil, fmt.Errorf("failed to parse corona sig: %w", err)
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

// ID returns D, the Warp message ID (recomputed from Message, not sliced
// from the wire). v1/v2 distinctions are gone: there is one ID per
// message and it is the replay key.
func (e *Envelope) ID() ids.ID { return e.Message.ID() }

// GetSourceChainID returns the source chain ID.
func (e *Envelope) GetSourceChainID() ids.ID { return e.Message.SourceChainID }

// SourceChainIDHash returns the source chain ID as a common.Hash.
func (e *Envelope) SourceChainIDHash() common.Hash {
	return common.BytesToHash(e.Message.SourceChainID[:])
}

// HashSuite returns the envelope's resolved hash suite.
func (e *Envelope) HashSuite() string { return e.Message.HashSuiteOrDefault() }

// HasCorona reports whether the envelope carries a Corona Ringtail
// lattice-threshold signature.
func (e *Envelope) HasCorona() bool { return e != nil && len(e.CoronaSig) > 0 }

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
	if e.Message.NetworkID != networkID {
		return fmt.Errorf("%w: expected network ID %d, got %d", ErrInvalidMessage, networkID, e.Message.NetworkID)
	}

	vdrSet, totalWeight, err := GetCanonicalValidatorSet(validatorState, e.Message.SourceChainID)
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
	return e.Beam.verify(e.Message.ID(), vdrSet)
}

// The subject-agnostic lane verifier interfaces (BeamVerifier, CoronaVerifier,
// MLDSACertSetVerifier, P3QRollupVerifier) are defined in evidence.go. The
// relay path below feeds them the envelope's subject D (e.Message.ID()) and the
// typed lane evidence; the corona implementation lives in warp/pulsar so this
// package does not import the corona kernel.

// VerifyOptions bundles the verifications a receiver applies to an
// envelope. A nil Corona / CertSet skips that lane; Require* demands the
// lane be present, a verifier be configured, and verification succeed.
type VerifyOptions struct {
	NetworkID      uint32
	ValidatorState ValidatorState
	QuorumNum      uint64
	QuorumDen      uint64

	Corona         CoronaVerifier
	CertSet        MLDSACertSetVerifier
	RequireCorona  bool
	RequireCertSet bool

	// HashSuiteID is the message-level c14n hash tag the receiver expects
	// (the generic Message tag, NOT a lane suite). Empty accepts whatever
	// the envelope declares (after defaulting to MessageHashProfileTag).
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
	// The warp cross-chain subject is D — recomputed from the message, framed
	// per lane by the subject-agnostic verifiers (CoronaSigningBytes /
	// MLDSASigningBytes inside the impl).
	d := e.Message.ID()
	subject := d[:]

	// ML-DSA cert-set lane.
	if e.HasMLDSACertSet() {
		if opts.CertSet == nil {
			if opts.RequireCertSet {
				return fmt.Errorf("%w: ML-DSA cert set lane required but no verifier configured", ErrInvalidMessage)
			}
		} else {
			ev := CertSetEvidence{
				ChainID:   e.Message.SourceChainID,
				EraHandle: e.Message.SourceGeneration,
				CertSet:   e.MLDSACertSet,
			}
			if err := opts.CertSet.VerifyCertSet(subject, ev); err != nil {
				return fmt.Errorf("ml-dsa cert set verify: %w", err)
			}
		}
	} else if opts.RequireCertSet {
		return fmt.Errorf("%w: ML-DSA cert set lane required but absent from envelope", ErrInvalidMessage)
	}

	// Corona Ringtail lattice-threshold lane.
	if e.HasCorona() {
		if opts.Corona == nil {
			if opts.RequireCorona {
				return fmt.Errorf("%w: Corona Ringtail lane required but no verifier configured", ErrInvalidMessage)
			}
		} else {
			ev := CoronaEvidence{
				ChainID:    e.Message.SourceChainID,
				KeyEraID:   e.Message.SourceKeyEraID,
				Generation: e.Message.SourceGeneration,
				Sig:        e.CoronaSig,
			}
			if err := opts.Corona.VerifyRingtailThreshold(subject, ev); err != nil {
				return fmt.Errorf("corona ringtail verify: %w", err)
			}
		}
	} else if opts.RequireCorona {
		return fmt.Errorf("%w: Corona Ringtail lane required but absent from envelope", ErrInvalidMessage)
	}

	return nil
}
