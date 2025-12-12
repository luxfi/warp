// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/rlp"
	"github.com/luxfi/ids"
)

const (
	CodecVersion   = 0
	MaxMessageSize = 256 * KiB
)

var (
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrInvalidMessage     = errors.New("invalid message")
	ErrUnknownValidator   = errors.New("unknown validator")
	ErrInsufficientWeight = errors.New("insufficient weight")
)

// UnsignedMessage is an unsigned warp message
type UnsignedMessage struct {
	NetworkID     uint32 `serialize:"true"`
	SourceChainID ids.ID `serialize:"true"`
	Payload       []byte `serialize:"true"`
}

// NewUnsignedMessage creates a new unsigned message
func NewUnsignedMessage(networkID uint32, sourceChainID ids.ID, payload []byte) (*UnsignedMessage, error) {
	msg := &UnsignedMessage{
		NetworkID:     networkID,
		SourceChainID: sourceChainID,
		Payload:       payload,
	}
	if err := msg.Verify(); err != nil {
		return nil, err
	}
	return msg, nil
}

// Verify verifies the unsigned message
func (u *UnsignedMessage) Verify() error {
	b, err := Codec.Marshal(CodecVersion, u)
	if err != nil {
		return fmt.Errorf("failed to marshal unsigned message: %w", err)
	}
	if len(b) > MaxMessageSize {
		return fmt.Errorf("%w: message size %d exceeds maximum %d", ErrInvalidMessage, len(b), MaxMessageSize)
	}
	return nil
}

// Bytes returns the byte representation of the unsigned message
func (u *UnsignedMessage) Bytes() []byte {
	b, _ := Codec.Marshal(CodecVersion, u)
	return b
}

// ID returns the hash of the unsigned message
func (u *UnsignedMessage) ID() ids.ID {
	return ids.ID(ComputeHash256Array(u.Bytes()))
}

// Message is a signed warp message
type Message struct {
	UnsignedMessage *UnsignedMessage `serialize:"true"`
	Signature       Signature        `serialize:"true"`
}

// NewMessage creates a new signed message
func NewMessage(unsigned *UnsignedMessage, signature Signature) (*Message, error) {
	msg := &Message{
		UnsignedMessage: unsigned,
		Signature:       signature,
	}
	if err := msg.Verify(); err != nil {
		return nil, err
	}
	return msg, nil
}

// Verify verifies the message format
func (m *Message) Verify() error {
	if m.UnsignedMessage == nil {
		return fmt.Errorf("%w: unsigned message is nil", ErrInvalidMessage)
	}
	if err := m.UnsignedMessage.Verify(); err != nil {
		return err
	}
	if m.Signature == nil {
		return fmt.Errorf("%w: signature is nil", ErrInvalidSignature)
	}
	return nil
}

// Bytes returns the byte representation of the message
func (m *Message) Bytes() []byte {
	b, _ := Codec.Marshal(CodecVersion, m)
	return b
}

// ID returns the ID of the message (hash of unsigned message)
func (m *Message) ID() ids.ID {
	return m.UnsignedMessage.ID()
}

// GetSourceChainID returns the source chain ID
func (m *Message) GetSourceChainID() ids.ID {
	return m.UnsignedMessage.SourceChainID
}

// SourceChainIDHash returns the source chain ID as a common.Hash (for EVM compatibility)
func (m *Message) SourceChainIDHash() common.Hash {
	return common.BytesToHash(m.UnsignedMessage.SourceChainID[:])
}

// ParseMessage parses a message from bytes
func ParseMessage(b []byte) (*Message, error) {
	msg := &Message{}
	_, err := Codec.Unmarshal(b, msg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}
	if err := msg.Verify(); err != nil {
		return nil, err
	}
	return msg, nil
}

// ParseUnsignedMessage parses an unsigned message from bytes
func ParseUnsignedMessage(b []byte) (*UnsignedMessage, error) {
	msg := &UnsignedMessage{}
	_, err := Codec.Unmarshal(b, msg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal unsigned message: %w", err)
	}
	if err := msg.Verify(); err != nil {
		return nil, err
	}
	return msg, nil
}

// VerifyMessage verifies a message against a validator set
func VerifyMessage(
	msg *Message,
	networkID uint32,
	validatorState ValidatorState,
	quorumNum uint64,
	quorumDen uint64,
) error {
	if err := msg.Verify(); err != nil {
		return err
	}
	if msg.UnsignedMessage.NetworkID != networkID {
		return fmt.Errorf("%w: expected network ID %d, got %d", ErrInvalidMessage, networkID, msg.UnsignedMessage.NetworkID)
	}

	vdrSet, totalWeight, err := GetCanonicalValidatorSet(validatorState, msg.UnsignedMessage.SourceChainID)
	if err != nil {
		return fmt.Errorf("failed to get validator set: %w", err)
	}

	signedWeight, err := msg.Signature.GetSignedWeight(vdrSet)
	if err != nil {
		return fmt.Errorf("failed to get signed weight: %w", err)
	}

	if err := VerifyWeight(signedWeight, totalWeight, quorumNum, quorumDen); err != nil {
		return err
	}

	return msg.Signature.Verify(msg.UnsignedMessage.Bytes(), vdrSet)
}

// VerifyWeight verifies that the signed weight meets the quorum threshold
func VerifyWeight(signedWeight, totalWeight, quorumNum, quorumDen uint64) error {
	if signedWeight == 0 {
		return fmt.Errorf("%w: signed weight is 0", ErrInsufficientWeight)
	}

	// Verify: signedWeight / totalWeight >= quorumNum / quorumDen
	// Rearranged: quorumNum * totalWeight <= quorumDen * signedWeight
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

// Equal returns true if two messages are equal
func (m *Message) Equal(other *Message) bool {
	if m == nil || other == nil {
		return m == other
	}
	if m.UnsignedMessage == nil || other.UnsignedMessage == nil {
		return m.UnsignedMessage == other.UnsignedMessage
	}
	if m.UnsignedMessage.NetworkID != other.UnsignedMessage.NetworkID {
		return false
	}
	if m.UnsignedMessage.SourceChainID != other.UnsignedMessage.SourceChainID {
		return false
	}
	if !bytes.Equal(m.UnsignedMessage.Payload, other.UnsignedMessage.Payload) {
		return false
	}
	return m.Signature.Equal(other.Signature)
}

// EncodeRLP implements rlp.Encoder for Message
func (m *Message) EncodeRLP(w io.Writer) error {
	bitSetSig, ok := m.Signature.(*BitSetSignature)
	if !ok {
		return errors.New("unknown signature type")
	}
	return rlp.Encode(w, []interface{}{m.UnsignedMessage, uint8(0), bitSetSig})
}

// DecodeRLP implements rlp.Decoder for Message
func (m *Message) DecodeRLP(s *rlp.Stream) error {
	if _, err := s.List(); err != nil {
		return err
	}

	m.UnsignedMessage = &UnsignedMessage{}
	if err := s.Decode(m.UnsignedMessage); err != nil {
		return fmt.Errorf("failed to decode unsigned message: %w", err)
	}

	var sigType uint8
	if err := s.Decode(&sigType); err != nil {
		return fmt.Errorf("failed to decode signature type: %w", err)
	}

	switch sigType {
	case 0:
		bitSetSig := &BitSetSignature{}
		if err := s.Decode(bitSetSig); err != nil {
			return fmt.Errorf("failed to decode bit set signature: %w", err)
		}
		m.Signature = bitSetSig
	default:
		return fmt.Errorf("unknown signature type: %d", sigType)
	}

	return s.ListEnd()
}
