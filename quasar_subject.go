// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// quasar_subject.go — the consensus finality SUBJECT M.
//
// Where the warp cross-chain subject is D (the Warp Message ID), the quasar
// consensus subject is M: the digest every finality lane (Beam, Pulsar,
// Corona, P3Q) signs to attest that a block is final. Every lane verifier in
// evidence.go is subject-agnostic, so the only difference between cross-chain
// and consensus finality is which 32-byte digest is the subject.
//
//	M = keccak256( "QUASAR_FINALITY_V1" ‖ c14n(params) )
//
// The c14n follows the ZAP discipline (zap.go): fixed-width big-endian, every
// field present, total-order canonical — a given params value has exactly one
// transcript encoding, and decode reproduces it byte-for-byte. Every field is
// fixed-width, so no length prefixes are required for unambiguity; the layout
// itself is the frame.

package warp

import (
	"fmt"

	"github.com/luxfi/ids"
)

// quasarFinalitySubjectDST is the domain-separation tag folded into M. It is
// distinct from messageDST ("LUX-WARP-ZAP-CORE-v1"), so a consensus finality
// subject can never collide with a cross-chain Warp message digest even on
// identical field bytes.
const quasarFinalitySubjectDST = "QUASAR_FINALITY_V1"

// quasarFinalityTranscriptLen is the exact byte length of a canonical M
// transcript: 32 + 8 + 8 + 32 + 32 + 32 + 8 + 8 + 8 + 8.
const quasarFinalityTranscriptLen = 32 + 8 + 8 + 32 + 32 + 32 + 8 + 8 + 8 + 8

// QuasarFinalityParams are the fields that uniquely identify a finalized
// block-decision the consensus quorum attests to. M binds ALL of them, so a
// signature over M is a signature over this exact decision and nothing else.
type QuasarFinalityParams struct {
	// ChainID is the chain whose block is being finalized.
	ChainID ids.ID
	// Height is the block height.
	Height uint64
	// Round is the consensus round that decided the block.
	Round uint64
	// BlockID is the decided block's ID.
	BlockID ids.ID
	// StateRoot is the post-state root the decision commits to.
	StateRoot [32]byte
	// SignerSetID identifies the validator set / quorum authorizing finality.
	SignerSetID ids.ID
	// KeyEraID is the threshold key era in force for this decision.
	KeyEraID uint64
	// Generation is the proactive-refresh/reshare epoch WITHIN KeyEraID. Binding
	// it into M pins a signature to the exact share generation, so a signature
	// produced under one generation cannot be replayed for another within the
	// same key era.
	Generation uint64
	// PChainHeight anchors the decision to the P-chain validator-set snapshot the
	// signer set / key era was dealt over, so the subject commits to which
	// validator set authorized it.
	PChainHeight uint64
	// PolicyID identifies the finality policy/tier the decision was made under.
	// Folding it into M makes a signature commit to its tier, so a cert minted
	// under a weaker policy cannot be replayed to satisfy a stronger one
	// (cross-policy / tier-downgrade reuse fails: the subject differs).
	PolicyID uint64
}

// MarshalTranscript returns the canonical c14n bytes of the finality params —
// the preimage (after the DST) of M. Total-order canonical and fixed-length
// (quasarFinalityTranscriptLen): re-marshaling a parsed transcript reproduces
// the exact bytes.
//
// Layout (all big-endian, no length prefixes — every field is fixed width):
//
//	ChainID      [32]
//	Height       u64
//	Round        u64
//	BlockID      [32]
//	StateRoot    [32]
//	SignerSetID  [32]
//	KeyEraID     u64
//	Generation   u64
//	PChainHeight u64
//	PolicyID     u64
func (p QuasarFinalityParams) MarshalTranscript() []byte {
	out := make([]byte, 0, quasarFinalityTranscriptLen)
	out = appendFixed(out, p.ChainID[:])
	out = appendU64(out, p.Height)
	out = appendU64(out, p.Round)
	out = appendFixed(out, p.BlockID[:])
	out = appendFixed(out, p.StateRoot[:])
	out = appendFixed(out, p.SignerSetID[:])
	out = appendU64(out, p.KeyEraID)
	out = appendU64(out, p.Generation)
	out = appendU64(out, p.PChainHeight)
	out = appendU64(out, p.PolicyID)
	return out
}

// ParseQuasarFinalityTranscript decodes a canonical transcript produced by
// MarshalTranscript, rejecting any input that is not exactly
// quasarFinalityTranscriptLen bytes (a canonical-form violation).
func ParseQuasarFinalityTranscript(b []byte) (QuasarFinalityParams, error) {
	var p QuasarFinalityParams
	if len(b) != quasarFinalityTranscriptLen {
		return p, fmt.Errorf("%w: transcript must be %d bytes, got %d",
			ErrInvalidMessage, quasarFinalityTranscriptLen, len(b))
	}
	r := newZapReader(b)
	if err := r.fixedInto(p.ChainID[:]); err != nil {
		return p, err
	}
	var err error
	if p.Height, err = r.u64(); err != nil {
		return p, err
	}
	if p.Round, err = r.u64(); err != nil {
		return p, err
	}
	if err = r.fixedInto(p.BlockID[:]); err != nil {
		return p, err
	}
	if err = r.fixedInto(p.StateRoot[:]); err != nil {
		return p, err
	}
	if err = r.fixedInto(p.SignerSetID[:]); err != nil {
		return p, err
	}
	if p.KeyEraID, err = r.u64(); err != nil {
		return p, err
	}
	if p.Generation, err = r.u64(); err != nil {
		return p, err
	}
	if p.PChainHeight, err = r.u64(); err != nil {
		return p, err
	}
	if p.PolicyID, err = r.u64(); err != nil {
		return p, err
	}
	if err := r.end(); err != nil {
		return p, err
	}
	return p, nil
}

// QuasarFinalitySubject returns M = keccak256(quasarFinalitySubjectDST ‖
// MarshalTranscript()) for the given params. M is the 32-byte subject every
// consensus finality lane signs. keccak256 (not NIST SHA3) matches warp's D so
// the same on-chain keccak opcode reproduces it byte-for-byte.
func QuasarFinalitySubject(p QuasarFinalityParams) [32]byte {
	return keccak256([]byte(quasarFinalitySubjectDST), p.MarshalTranscript())
}
