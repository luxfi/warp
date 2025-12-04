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
)

const (
	// CodecVersion is the current codec version
	CodecVersion = 0

	// MaxMessageSize is the maximum size of a warp message
	MaxMessageSize = 256 * KiB
)

var (
	// ErrInvalidSignature is returned when a signature is invalid
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrInvalidMessage is returned when a message is invalid
	ErrInvalidMessage = errors.New("invalid message")

	// ErrUnknownValidator is returned when a validator is not known
	ErrUnknownValidator = errors.New("unknown validator")

	// ErrInsufficientWeight is returned when signatures don't meet the threshold
	ErrInsufficientWeight = errors.New("insufficient weight")
)

// UnsignedMessage is an unsigned warp message
type UnsignedMessage struct {
	NetworkID     uint32 `serialize:"true"`
	SourceChainID []byte `serialize:"true"`
	Payload       []byte `serialize:"true"`
}

// NewUnsignedMessage creates a new unsigned message
func NewUnsignedMessage(
	networkID uint32,
	sourceChainID []byte,
	payload []byte,
) (*UnsignedMessage, error) {
	msg := &UnsignedMessage{
		NetworkID:     networkID,
		SourceChainID: sourceChainID,
		Payload:       payload,
	}

	// Verify the message is valid
	if err := msg.Verify(); err != nil {
		return nil, err
	}

	return msg, nil
}

// Verify verifies the unsigned message
func (u *UnsignedMessage) Verify() error {
	if len(u.SourceChainID) != 32 {
		return fmt.Errorf("%w: source chain ID must be 32 bytes", ErrInvalidMessage)
	}

	// Check message size
	bytes, err := Codec.Marshal(CodecVersion, u)
	if err != nil {
		return fmt.Errorf("failed to marshal unsigned message: %w", err)
	}
	if len(bytes) > MaxMessageSize {
		return fmt.Errorf("%w: message size %d exceeds maximum %d", ErrInvalidMessage, len(bytes), MaxMessageSize)
	}

	return nil
}

// Bytes returns the byte representation of the unsigned message
func (u *UnsignedMessage) Bytes() []byte {
	bytes, _ := Codec.Marshal(CodecVersion, u)
	return bytes
}

// ID returns the hash of the unsigned message
func (u *UnsignedMessage) ID() []byte {
	return ComputeHash256(u.Bytes())
}

// Message is a signed warp message
type Message struct {
	UnsignedMessage *UnsignedMessage `serialize:"true"`
	Signature       Signature        `serialize:"true"`
}

// NewMessage creates a new signed message
func NewMessage(
	unsigned *UnsignedMessage,
	signature Signature,
) (*Message, error) {
	msg := &Message{
		UnsignedMessage: unsigned,
		Signature:       signature,
	}

	// Verify the message is valid
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
	bytes, _ := Codec.Marshal(CodecVersion, m)
	return bytes
}

// ID returns the ID of the message (hash of unsigned message)
func (m *Message) ID() []byte {
	return m.UnsignedMessage.ID()
}

// SourceChainID returns the source chain ID as a common.Hash
func (m *Message) SourceChainID() common.Hash {
	return common.BytesToHash(m.UnsignedMessage.SourceChainID)
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

	// Get validator set at the time of signing
	vdrSet, totalWeight, err := GetCanonicalValidatorSet(validatorState, msg.UnsignedMessage.SourceChainID)
	if err != nil {
		return fmt.Errorf("failed to get validator set: %w", err)
	}

	// Verify signature weight meets quorum
	signedWeight, err := msg.Signature.GetSignedWeight(vdrSet)
	if err != nil {
		return fmt.Errorf("failed to get signed weight: %w", err)
	}

	if err := VerifyWeight(signedWeight, totalWeight, quorumNum, quorumDen); err != nil {
		return err
	}

	// Verify the signature
	return msg.Signature.Verify(msg.UnsignedMessage.Bytes(), vdrSet)
}

// VerifyWeight verifies that the signed weight meets the quorum threshold
func VerifyWeight(
	signedWeight uint64,
	totalWeight uint64,
	quorumNum uint64,
	quorumDen uint64,
) error {
	if signedWeight == 0 {
		return fmt.Errorf("%w: signed weight is 0", ErrInsufficientWeight)
	}

	// Verify that quorumNum * totalWeight <= quorumDen * signedWeight
	// This is equivalent to: signedWeight / totalWeight >= quorumNum / quorumDen
	if err := CheckMulDoesNotOverflow(quorumNum, totalWeight); err != nil {
		return fmt.Errorf("%w: quorumNum * totalWeight overflows", err)
	}
	lhs := quorumNum * totalWeight

	if err := CheckMulDoesNotOverflow(quorumDen, signedWeight); err != nil {
		return fmt.Errorf("%w: quorumDen * signedWeight overflows", err)
	}
	rhs := quorumDen * signedWeight

	if lhs > rhs {
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

	if !bytes.Equal(m.UnsignedMessage.SourceChainID, other.UnsignedMessage.SourceChainID) {
		return false
	}

	if !bytes.Equal(m.UnsignedMessage.Payload, other.UnsignedMessage.Payload) {
		return false
	}

	return m.Signature.Equal(other.Signature)
}

// EncodeRLP implements rlp.Encoder for Message
func (m *Message) EncodeRLP(w io.Writer) error {
	// Encode as a list of: UnsignedMessage, SignatureType, SignatureData
	sigType := uint8(0) // BitSetSignature type
	var sigData interface{}

	if bitSetSig, ok := m.Signature.(*BitSetSignature); ok {
		sigData = bitSetSig
	} else {
		return errors.New("unknown signature type")
	}

	return rlp.Encode(w, []interface{}{
		m.UnsignedMessage,
		sigType,
		sigData,
	})
}

// DecodeRLP implements rlp.Decoder for Message
func (m *Message) DecodeRLP(s *rlp.Stream) error {
	// Decode the outer list
	_, err := s.List()
	if err != nil {
		return err
	}

	// Decode UnsignedMessage
	m.UnsignedMessage = &UnsignedMessage{}
	if err := s.Decode(m.UnsignedMessage); err != nil {
		return fmt.Errorf("failed to decode unsigned message: %w", err)
	}

	// Decode signature type
	var sigType uint8
	if err := s.Decode(&sigType); err != nil {
		return fmt.Errorf("failed to decode signature type: %w", err)
	}

	// Decode signature based on type
	switch sigType {
	case 0: // BitSetSignature
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
