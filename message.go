// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"fmt"

	"github.com/luxfi/ids"
)

// DefaultHashSuiteID is the canonical Pulsar hash profile. A Message's
// HashSuiteID MUST be resolved to a concrete value before it is marshaled
// or signed — there is NO sign-time defaulting inside the codec. This
// constant is the resolution target callers use at construction time.
const DefaultHashSuiteID = "Pulsar-SHA3"

// Message is the single signed subject of a Warp message. It folds the
// former UnsignedMessage (NetworkID, SourceChainID, Payload) together with
// the Pulsar PQ lineage (SourceNebulaRoot, SourceKeyEraID, SourceGeneration,
// HashSuiteID) that previously lived only on the v2 envelope. Folding the
// lineage into the signed subject means every lane — BLS Beam included —
// authenticates it; under the old split the Beam signed only the unsigned
// body and the lineage was Beam-unauthenticated.
//
// Canonical c14n layout (== Bytes(), the lane subject hashed into D):
//
//	zapKindMessage  u8 (0x01)
//	NetworkID          u32 big-endian
//	SourceChainID      [32] raw
//	SourceNebulaRoot   [32] raw
//	SourceKeyEraID     u64 big-endian
//	SourceGeneration   u64 big-endian
//	HashSuiteID        u32-len ‖ utf8
//	Payload            u32-len ‖ bytes
//
// The digest is D = keccak256("LUX-WARP-ZAP-CORE-v1" ‖ Bytes()).
type Message struct {
	NetworkID        uint32
	SourceChainID    ids.ID
	SourceNebulaRoot [32]byte
	SourceKeyEraID   uint64
	SourceGeneration uint64
	HashSuiteID      string
	Payload          []byte
}

// NewMessage builds a Message for a locally-originated message:
// zero PQ lineage and HashSuiteID resolved to DefaultHashSuiteID. Callers
// that bind a specific Pulsar lineage construct the struct directly with
// the resolved fields.
func NewMessage(networkID uint32, sourceChainID ids.ID, payload []byte) (*Message, error) {
	c := &Message{
		NetworkID:     networkID,
		SourceChainID: sourceChainID,
		HashSuiteID:   DefaultHashSuiteID,
		Payload:       payload,
	}
	if err := c.Verify(); err != nil {
		return nil, err
	}
	return c, nil
}

// HashSuiteOrDefault returns the resolved HashSuiteID, falling back to
// DefaultHashSuiteID for the zero value. This is a READ helper for
// downstream policy checks; it does NOT influence marshaling — Bytes()
// always encodes the field verbatim.
func (c *Message) HashSuiteOrDefault() string {
	if c == nil || c.HashSuiteID == "" {
		return DefaultHashSuiteID
	}
	return c.HashSuiteID
}

// marshalZAP returns the canonical c14n bytes of the message. This is the
// lane subject and the digest preimage; it is total-order canonical, so
// re-marshaling a decoded message reproduces the exact bytes.
func (c *Message) marshalZAP() []byte {
	out := make([]byte, 0, 1+4+32+32+8+8+4+len(c.HashSuiteID)+4+len(c.Payload))
	out = appendU8(out, zapKindMessage)
	out = appendU32(out, c.NetworkID)
	out = appendFixed(out, c.SourceChainID[:])
	out = appendFixed(out, c.SourceNebulaRoot[:])
	out = appendU64(out, c.SourceKeyEraID)
	out = appendU64(out, c.SourceGeneration)
	out = appendVar(out, []byte(c.HashSuiteID))
	out = appendVar(out, c.Payload)
	return out
}

// Verify checks the structural invariants: the canonical encoding must
// not exceed MaxMessageSize.
func (c *Message) Verify() error {
	if n := len(c.marshalZAP()); n > MaxMessageSize {
		return fmt.Errorf("%w: signed message size %d exceeds maximum %d", ErrInvalidMessage, n, MaxMessageSize)
	}
	return nil
}

// Bytes returns the canonical c14n encoding of the message (== zap_c14n).
func (c *Message) Bytes() []byte { return c.marshalZAP() }

// ID returns D, the Warp message ID: keccak256(messageDST ‖ Bytes()). It is
// the replay key and the on-chain messageHash. D is recomputed from the
// struct, never sliced out of a wire envelope.
func (c *Message) ID() ids.ID {
	return ids.ID(keccak256([]byte(messageDST), c.marshalZAP()))
}

// parseMessage decodes a Message from the cursor. It validates the
// kind byte but leaves trailing-byte / size checks to the caller.
func parseMessage(r *zapReader) (Message, error) {
	var c Message
	kind, err := r.u8()
	if err != nil {
		return c, err
	}
	if kind != zapKindMessage {
		return c, fmt.Errorf("%w: signed-message kind 0x%02x", ErrInvalidMessage, kind)
	}
	if c.NetworkID, err = r.u32(); err != nil {
		return c, err
	}
	if err = r.fixedInto(c.SourceChainID[:]); err != nil {
		return c, err
	}
	if err = r.fixedInto(c.SourceNebulaRoot[:]); err != nil {
		return c, err
	}
	if c.SourceKeyEraID, err = r.u64(); err != nil {
		return c, err
	}
	if c.SourceGeneration, err = r.u64(); err != nil {
		return c, err
	}
	suite, err := r.varbytes()
	if err != nil {
		return c, err
	}
	c.HashSuiteID = string(suite)
	if c.Payload, err = r.varbytes(); err != nil {
		return c, err
	}
	return c, nil
}

// ParseMessage decodes a standalone Message from its canonical
// c14n bytes, rejecting trailing bytes and over-size payloads.
func ParseMessage(b []byte) (*Message, error) {
	r := newZapReader(b)
	c, err := parseMessage(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed message: %w", err)
	}
	if err := r.end(); err != nil {
		return nil, err
	}
	if err := c.Verify(); err != nil {
		return nil, err
	}
	return &c, nil
}

// VerifyWeight verifies that the signed weight meets the quorum threshold:
// signedWeight / totalWeight >= quorumNum / quorumDen.
func VerifyWeight(signedWeight, totalWeight, quorumNum, quorumDen uint64) error {
	if signedWeight == 0 {
		return fmt.Errorf("%w: signed weight is 0", ErrInsufficientWeight)
	}
	if err := CheckMulDoesNotOverflow(quorumNum, totalWeight); err != nil {
		return fmt.Errorf("%w: quorumNum * totalWeight overflows", err)
	}
	if err := CheckMulDoesNotOverflow(quorumDen, signedWeight); err != nil {
		return fmt.Errorf("%w: quorumDen * signedWeight overflows", err)
	}
	if quorumNum*totalWeight > quorumDen*signedWeight {
		return fmt.Errorf("%w: signed weight %d / total weight %d < quorum %d / %d",
			ErrInsufficientWeight, signedWeight, totalWeight, quorumNum, quorumDen)
	}
	return nil
}
