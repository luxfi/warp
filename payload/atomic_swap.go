// Copyright (C) 2019-2025, Lux Industries Inc All rights reserved.
// See the file LICENSE for licensing terms.

package payload

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/ids"
)

// Atomic Swap Operation Types
const (
	// OpLock locks assets on source chain for atomic swap
	OpLock uint8 = iota
	// OpUnlock unlocks assets on source chain (cancellation or completion)
	OpUnlock
	// OpMint mints wrapped assets on destination chain
	OpMint
	// OpBurn burns wrapped assets to release native on source
	OpBurn
	// OpSwap executes a DEX swap on destination chain
	OpSwap
	// OpSettle confirms settlement and releases locked assets
	OpSettle
)

// AtomicSwapPayload represents a cross-chain atomic swap message
// Used for XVM (UTXO-native) ↔ C-Chain (EVM) bridges
type AtomicSwapPayload struct {
	// Version for future upgrades
	Version uint8 `serialize:"true"`
	// Operation type (Lock, Unlock, Mint, Burn, Swap, Settle)
	Operation uint8 `serialize:"true"`
	// SwapID unique identifier for this atomic swap
	SwapID [32]byte `serialize:"true"`
	// SourceChain originating chain ID
	SourceChain ids.ID `serialize:"true"`
	// DestChain target chain ID
	DestChain ids.ID `serialize:"true"`
	// Sender address on source chain (20 bytes for EVM, variable for UTXO)
	Sender []byte `serialize:"true"`
	// Recipient address on destination chain
	Recipient []byte `serialize:"true"`
	// Asset identifier (token address or asset ID)
	Asset [32]byte `serialize:"true"`
	// Amount in smallest units (6 decimals for DEX precompile)
	Amount *big.Int `serialize:"true"`
	// MinReceive minimum amount to receive (slippage protection)
	MinReceive *big.Int `serialize:"true"`
	// Deadline timestamp for swap expiry
	Deadline uint64 `serialize:"true"`
	// Nonce for replay protection
	Nonce uint64 `serialize:"true"`
	// Data additional payload for swap routing
	Data []byte `serialize:"true"`
}

// NewAtomicSwapPayload creates a new atomic swap payload
func NewAtomicSwapPayload(
	operation uint8,
	swapID [32]byte,
	sourceChain, destChain ids.ID,
	sender, recipient []byte,
	asset [32]byte,
	amount, minReceive *big.Int,
	deadline, nonce uint64,
	data []byte,
) (*AtomicSwapPayload, error) {
	if len(sender) == 0 {
		return nil, errors.New("sender address required")
	}
	if len(recipient) == 0 {
		return nil, errors.New("recipient address required")
	}
	if amount == nil || amount.Sign() <= 0 {
		return nil, errors.New("amount must be positive")
	}

	return &AtomicSwapPayload{
		Version:     1,
		Operation:   operation,
		SwapID:      swapID,
		SourceChain: sourceChain,
		DestChain:   destChain,
		Sender:      sender,
		Recipient:   recipient,
		Asset:       asset,
		Amount:      amount,
		MinReceive:  minReceive,
		Deadline:    deadline,
		Nonce:       nonce,
		Data:        data,
	}, nil
}

// Bytes serializes the atomic swap payload
func (p *AtomicSwapPayload) Bytes() []byte {
	// Calculate total size
	size := 1 + 1 + 32 + 32 + 32 + // version, op, swapID, source, dest
		4 + len(p.Sender) + 4 + len(p.Recipient) + // sender, recipient with length prefix
		32 + 32 + 32 + // asset, amount (32 bytes), minReceive (32 bytes)
		8 + 8 + // deadline, nonce
		4 + len(p.Data) // data with length prefix

	buf := make([]byte, size)
	offset := 0

	// Version and Operation
	buf[offset] = p.Version
	offset++
	buf[offset] = p.Operation
	offset++

	// SwapID
	copy(buf[offset:], p.SwapID[:])
	offset += 32

	// SourceChain and DestChain
	copy(buf[offset:], p.SourceChain[:])
	offset += 32
	copy(buf[offset:], p.DestChain[:])
	offset += 32

	// Sender with length prefix
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(p.Sender)))
	offset += 4
	copy(buf[offset:], p.Sender)
	offset += len(p.Sender)

	// Recipient with length prefix
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(p.Recipient)))
	offset += 4
	copy(buf[offset:], p.Recipient)
	offset += len(p.Recipient)

	// Asset
	copy(buf[offset:], p.Asset[:])
	offset += 32

	// Amount (padded to 32 bytes)
	amountBytes := p.Amount.Bytes()
	amountPadded := make([]byte, 32)
	copy(amountPadded[32-len(amountBytes):], amountBytes)
	copy(buf[offset:], amountPadded)
	offset += 32

	// MinReceive (padded to 32 bytes)
	minBytes := []byte{}
	if p.MinReceive != nil {
		minBytes = p.MinReceive.Bytes()
	}
	minPadded := make([]byte, 32)
	copy(minPadded[32-len(minBytes):], minBytes)
	copy(buf[offset:], minPadded)
	offset += 32

	// Deadline and Nonce
	binary.BigEndian.PutUint64(buf[offset:], p.Deadline)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], p.Nonce)
	offset += 8

	// Data with length prefix
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(p.Data)))
	offset += 4
	copy(buf[offset:], p.Data)

	return buf
}

// ParseAtomicSwapPayload deserializes an atomic swap payload
func ParseAtomicSwapPayload(data []byte) (*AtomicSwapPayload, error) {
	if len(data) < 1+1+32+32+32+4+4+32+32+32+8+8+4 {
		return nil, errors.New("payload too short")
	}

	offset := 0
	p := &AtomicSwapPayload{}

	// Version and Operation
	p.Version = data[offset]
	offset++
	if p.Version != 1 {
		return nil, fmt.Errorf("unsupported version: %d", p.Version)
	}
	p.Operation = data[offset]
	offset++

	// SwapID
	copy(p.SwapID[:], data[offset:offset+32])
	offset += 32

	// SourceChain and DestChain
	copy(p.SourceChain[:], data[offset:offset+32])
	offset += 32
	copy(p.DestChain[:], data[offset:offset+32])
	offset += 32

	// Sender
	senderLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(senderLen) > len(data) {
		return nil, errors.New("invalid sender length")
	}
	p.Sender = make([]byte, senderLen)
	copy(p.Sender, data[offset:offset+int(senderLen)])
	offset += int(senderLen)

	// Recipient
	recipientLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(recipientLen) > len(data) {
		return nil, errors.New("invalid recipient length")
	}
	p.Recipient = make([]byte, recipientLen)
	copy(p.Recipient, data[offset:offset+int(recipientLen)])
	offset += int(recipientLen)

	// Asset
	copy(p.Asset[:], data[offset:offset+32])
	offset += 32

	// Amount
	p.Amount = new(big.Int).SetBytes(data[offset : offset+32])
	offset += 32

	// MinReceive
	p.MinReceive = new(big.Int).SetBytes(data[offset : offset+32])
	offset += 32

	// Deadline and Nonce
	p.Deadline = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	p.Nonce = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Data
	if offset+4 > len(data) {
		return nil, errors.New("missing data length")
	}
	dataLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(dataLen) > len(data) {
		return nil, errors.New("invalid data length")
	}
	p.Data = make([]byte, dataLen)
	copy(p.Data, data[offset:offset+int(dataLen)])

	return p, nil
}

// SwapRoute encodes the DEX swap path
type SwapRoute struct {
	// TokenIn input token address
	TokenIn [20]byte `serialize:"true"`
	// TokenOut output token address
	TokenOut [20]byte `serialize:"true"`
	// PoolFee fee tier (100=0.01%, 500=0.05%, 3000=0.30%, 10000=1.00%)
	PoolFee uint32 `serialize:"true"`
	// TickSpacing for the pool
	TickSpacing int32 `serialize:"true"`
	// Hooks address (zero if no hooks)
	Hooks [20]byte `serialize:"true"`
}

// Bytes serializes the swap route
func (r *SwapRoute) Bytes() []byte {
	buf := make([]byte, 20+20+4+4+20)
	offset := 0
	copy(buf[offset:], r.TokenIn[:])
	offset += 20
	copy(buf[offset:], r.TokenOut[:])
	offset += 20
	binary.BigEndian.PutUint32(buf[offset:], r.PoolFee)
	offset += 4
	binary.BigEndian.PutUint32(buf[offset:], uint32(r.TickSpacing))
	offset += 4
	copy(buf[offset:], r.Hooks[:])
	return buf
}

// ParseSwapRoute deserializes a swap route
func ParseSwapRoute(data []byte) (*SwapRoute, error) {
	if len(data) < 68 {
		return nil, errors.New("swap route too short")
	}
	r := &SwapRoute{}
	offset := 0
	copy(r.TokenIn[:], data[offset:offset+20])
	offset += 20
	copy(r.TokenOut[:], data[offset:offset+20])
	offset += 20
	r.PoolFee = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	r.TickSpacing = int32(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	copy(r.Hooks[:], data[offset:offset+20])
	return r, nil
}

// MultiHopRoute encodes a multi-hop swap path
type MultiHopRoute struct {
	Hops []SwapRoute `serialize:"true"`
}

// Bytes serializes the multi-hop route
func (m *MultiHopRoute) Bytes() []byte {
	buf := make([]byte, 4+len(m.Hops)*68)
	binary.BigEndian.PutUint32(buf[0:], uint32(len(m.Hops)))
	for i, hop := range m.Hops {
		copy(buf[4+i*68:], hop.Bytes())
	}
	return buf
}

// ParseMultiHopRoute deserializes a multi-hop route
func ParseMultiHopRoute(data []byte) (*MultiHopRoute, error) {
	if len(data) < 4 {
		return nil, errors.New("multi-hop route too short")
	}
	hopCount := binary.BigEndian.Uint32(data[0:])
	if len(data) < 4+int(hopCount)*68 {
		return nil, errors.New("insufficient data for hops")
	}
	m := &MultiHopRoute{Hops: make([]SwapRoute, hopCount)}
	for i := range m.Hops {
		hop, err := ParseSwapRoute(data[4+i*68:])
		if err != nil {
			return nil, err
		}
		m.Hops[i] = *hop
	}
	return m, nil
}

// XVM (UTXO-native) specific payload for locking assets
type XVMAssetLock struct {
	// TxID of the UTXO being locked
	TxID [32]byte `serialize:"true"`
	// OutputIndex in the transaction
	OutputIndex uint32 `serialize:"true"`
	// AssetID being locked
	AssetID [32]byte `serialize:"true"`
	// Amount being locked
	Amount uint64 `serialize:"true"`
	// LockScript for the HTLC
	LockScript []byte `serialize:"true"`
	// HashLock for atomic swap
	HashLock [32]byte `serialize:"true"`
	// TimeLock expiry block/timestamp
	TimeLock uint64 `serialize:"true"`
}

// Bytes serializes the XVM asset lock
func (l *XVMAssetLock) Bytes() []byte {
	buf := make([]byte, 32+4+32+8+4+len(l.LockScript)+32+8)
	offset := 0
	copy(buf[offset:], l.TxID[:])
	offset += 32
	binary.BigEndian.PutUint32(buf[offset:], l.OutputIndex)
	offset += 4
	copy(buf[offset:], l.AssetID[:])
	offset += 32
	binary.BigEndian.PutUint64(buf[offset:], l.Amount)
	offset += 8
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(l.LockScript)))
	offset += 4
	copy(buf[offset:], l.LockScript)
	offset += len(l.LockScript)
	copy(buf[offset:], l.HashLock[:])
	offset += 32
	binary.BigEndian.PutUint64(buf[offset:], l.TimeLock)
	return buf
}

// OperationName returns human-readable operation name
func (p *AtomicSwapPayload) OperationName() string {
	switch p.Operation {
	case OpLock:
		return "Lock"
	case OpUnlock:
		return "Unlock"
	case OpMint:
		return "Mint"
	case OpBurn:
		return "Burn"
	case OpSwap:
		return "Swap"
	case OpSettle:
		return "Settle"
	default:
		return "Unknown"
	}
}

// IsValid performs basic validation
func (p *AtomicSwapPayload) IsValid() error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported version: %d", p.Version)
	}
	if p.Operation > OpSettle {
		return fmt.Errorf("invalid operation: %d", p.Operation)
	}
	if len(p.Sender) == 0 {
		return errors.New("sender required")
	}
	if len(p.Recipient) == 0 {
		return errors.New("recipient required")
	}
	if p.Amount == nil || p.Amount.Sign() <= 0 {
		return errors.New("positive amount required")
	}
	return nil
}
