// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package backend

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/warp"
	"github.com/luxfi/warp/signer"
)

// Backend is the interface for warp message handling
type Backend interface {
	// AddMessage adds a message to be sent
	AddMessage(msg *warp.UnsignedMessage) error

	// GetMessage retrieves a verified message by index
	GetMessage(index uint32) (*warp.Message, error)

	// GetValidatorState returns the validator state
	GetValidatorState() warp.ValidatorState
}

// MemoryBackend is an in-memory implementation of the warp backend
type MemoryBackend struct {
	mu             sync.RWMutex
	messages       []*warp.Message
	validatorState warp.ValidatorState
	signer         signer.Signer
}

// NewMemoryBackend creates a new memory backend
func NewMemoryBackend(validatorState warp.ValidatorState, s signer.Signer) *MemoryBackend {
	return &MemoryBackend{
		messages:       make([]*warp.Message, 0),
		validatorState: validatorState,
		signer:         s,
	}
}

// AddMessage adds a message to be sent
func (b *MemoryBackend) AddMessage(unsignedMsg *warp.UnsignedMessage) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.signer == nil {
		return errors.New("no signer configured")
	}

	// Get validator set
	validators, _, err := warp.GetCanonicalValidatorSet(
		b.validatorState,
		unsignedMsg.SourceChainID,
	)
	if err != nil {
		return fmt.Errorf("failed to get validator set: %w", err)
	}

	// Sign the message
	sig, err := b.signer.Sign(unsignedMsg)
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	// Create signed message
	// For simplicity, we'll create a single-signer BitSetSignature
	// In production, this would aggregate signatures from multiple validators
	bitSet := warp.NewBitSet()
	signerPKBytes := bls.PublicKeyToCompressedBytes(b.signer.GetPublicKey())
	for i, v := range validators {
		if bytes.Equal(bls.PublicKeyToCompressedBytes(v.PublicKey), signerPKBytes) {
			bitSet.Add(i)
			break
		}
	}

	sigBytes := [warp.SignatureLen]byte{}
	copy(sigBytes[:], bls.SignatureToBytes(sig))

	bitSetSig := &warp.BitSetSignature{
		Signers:   bitSet,
		Signature: sigBytes,
	}

	msg, err := warp.NewMessage(unsignedMsg, bitSetSig)
	if err != nil {
		return fmt.Errorf("failed to create message: %w", err)
	}

	b.messages = append(b.messages, msg)
	return nil
}

// GetMessage retrieves a verified message by index
func (b *MemoryBackend) GetMessage(index uint32) (*warp.Message, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if int(index) >= len(b.messages) {
		return nil, fmt.Errorf("message index %d out of bounds", index)
	}

	return b.messages[index], nil
}

// GetValidatorState returns the validator state
func (b *MemoryBackend) GetValidatorState() warp.ValidatorState {
	return b.validatorState
}

// MockValidatorState is a mock implementation of ValidatorState
type MockValidatorState struct {
	validators map[string]*warp.Validator
	height     uint64
}

// NewMockValidatorState creates a new mock validator state
func NewMockValidatorState(validators []*warp.Validator, height uint64) *MockValidatorState {
	vMap := make(map[string]*warp.Validator)
	for _, v := range validators {
		vMap[string(v.NodeID)] = v
	}
	return &MockValidatorState{
		validators: vMap,
		height:     height,
	}
}

// GetValidatorSet returns the validator set for a given chain ID at a given height
func (m *MockValidatorState) GetValidatorSet(chainID []byte, height uint64) (map[string]*warp.Validator, error) {
	return m.validators, nil
}

// GetCurrentHeight returns the current height
func (m *MockValidatorState) GetCurrentHeight() (uint64, error) {
	return m.height, nil
}

// ChainBackend is a backend that integrates with blockchain state
type ChainBackend struct {
	mu             sync.RWMutex
	pendingMsgs    []*warp.UnsignedMessage
	verifiedMsgs   map[uint32]*warp.Message
	validatorState warp.ValidatorState
	chainID        common.Hash
}

// NewChainBackend creates a new chain backend
func NewChainBackend(validatorState warp.ValidatorState, chainID common.Hash) *ChainBackend {
	return &ChainBackend{
		pendingMsgs:    make([]*warp.UnsignedMessage, 0),
		verifiedMsgs:   make(map[uint32]*warp.Message),
		validatorState: validatorState,
		chainID:        chainID,
	}
}

// AddMessage adds a message to be sent
func (b *ChainBackend) AddMessage(msg *warp.UnsignedMessage) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.pendingMsgs = append(b.pendingMsgs, msg)
	return nil
}

// GetMessage retrieves a verified message by index
func (b *ChainBackend) GetMessage(index uint32) (*warp.Message, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	msg, ok := b.verifiedMsgs[index]
	if !ok {
		return nil, fmt.Errorf("message %d not found", index)
	}

	return msg, nil
}

// GetValidatorState returns the validator state
func (b *ChainBackend) GetValidatorState() warp.ValidatorState {
	return b.validatorState
}

// AddVerifiedMessage adds a pre-verified message
func (b *ChainBackend) AddVerifiedMessage(index uint32, msg *warp.Message) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.verifiedMsgs[index] = msg
	return nil
}

// GetPendingMessages returns all pending unsigned messages
func (b *ChainBackend) GetPendingMessages() []*warp.UnsignedMessage {
	b.mu.RLock()
	defer b.mu.RUnlock()

	msgs := make([]*warp.UnsignedMessage, len(b.pendingMsgs))
	copy(msgs, b.pendingMsgs)
	return msgs
}

// ClearPendingMessages clears all pending messages
func (b *ChainBackend) ClearPendingMessages() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.pendingMsgs = b.pendingMsgs[:0]
}
