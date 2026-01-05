// Copyright (C) 2019-2025, Lux Industries Inc All rights reserved.
// See the file LICENSE for licensing terms.

// Package bridge provides cross-chain atomic swap bridging using Warp messages.
// It enables asset transfers and DEX swaps between XVM (UTXO-native) and C-Chain (EVM).
package bridge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
	"github.com/luxfi/warp/backend"
	"github.com/luxfi/warp/payload"
)

// Chain IDs for the Lux network
var (
	// XVMChainID is the X-Chain (XVM) chain ID for UTXO-native assets
	XVMChainID = ids.ID{} // Set at runtime from genesis

	// CChainID is the C-Chain chain ID for EVM operations
	CChainID = ids.ID{} // Set at runtime from genesis

	// DEXPrecompileAddress is the PoolManager precompile on C-Chain
	DEXPrecompileAddress = [20]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00}
)

// SwapState tracks the state of an atomic swap
type SwapState uint8

const (
	SwapStatePending SwapState = iota
	SwapStateLocked
	SwapStateMinted
	SwapStateSwapped
	SwapStateSettled
	SwapStateCancelled
	SwapStateExpired
)

func (s SwapState) String() string {
	switch s {
	case SwapStatePending:
		return "pending"
	case SwapStateLocked:
		return "locked"
	case SwapStateMinted:
		return "minted"
	case SwapStateSwapped:
		return "swapped"
	case SwapStateSettled:
		return "settled"
	case SwapStateCancelled:
		return "canceled"
	case SwapStateExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// SwapRecord stores the full state of an atomic swap
type SwapRecord struct {
	SwapID       [32]byte
	State        SwapState
	SourceChain  ids.ID
	DestChain    ids.ID
	Sender       []byte
	Recipient    []byte
	Asset        [32]byte
	Amount       *big.Int
	MinReceive   *big.Int
	Deadline     uint64
	Nonce        uint64
	HashLock     [32]byte
	Preimage     [32]byte // Revealed on settlement
	LockTxHash   string   // Transaction hash on source chain
	MintTxHash   string   // Transaction hash on dest chain
	SwapTxHash   string   // DEX swap transaction hash
	SettleTxHash string   // Settlement confirmation hash
	SwapRoute    []payload.SwapRoute
	CreatedAt    time.Time
	UpdatedAt    time.Time
	mu           sync.RWMutex
}

// AtomicBridge manages cross-chain atomic swaps
type AtomicBridge struct {
	networkID     uint32
	sourceChainID ids.ID
	destChainID   ids.ID
	backend       backend.Backend
	swaps         map[[32]byte]*SwapRecord
	nonceCounter  uint64
	mu            sync.RWMutex

	// Callbacks for chain-specific operations
	onLock   func(ctx context.Context, swap *SwapRecord) error
	onMint   func(ctx context.Context, swap *SwapRecord) error
	onSwap   func(ctx context.Context, swap *SwapRecord) error
	onSettle func(ctx context.Context, swap *SwapRecord) error
}

// BridgeConfig configuration for the atomic bridge
type BridgeConfig struct {
	NetworkID     uint32
	SourceChainID ids.ID
	DestChainID   ids.ID
	Backend       backend.Backend
}

// NewAtomicBridge creates a new atomic swap bridge
func NewAtomicBridge(cfg *BridgeConfig) *AtomicBridge {
	return &AtomicBridge{
		networkID:     cfg.NetworkID,
		sourceChainID: cfg.SourceChainID,
		destChainID:   cfg.DestChainID,
		backend:       cfg.Backend,
		swaps:         make(map[[32]byte]*SwapRecord),
	}
}

// SetCallbacks sets the chain-specific operation callbacks
func (b *AtomicBridge) SetCallbacks(
	onLock func(ctx context.Context, swap *SwapRecord) error,
	onMint func(ctx context.Context, swap *SwapRecord) error,
	onSwap func(ctx context.Context, swap *SwapRecord) error,
	onSettle func(ctx context.Context, swap *SwapRecord) error,
) {
	b.onLock = onLock
	b.onMint = onMint
	b.onSwap = onSwap
	b.onSettle = onSettle
}

// generateSwapID creates a unique swap ID
func (b *AtomicBridge) generateSwapID() ([32]byte, error) {
	var swapID [32]byte
	_, err := rand.Read(swapID[:])
	return swapID, err
}

// generateHashLock creates a hashlock for HTLC
func generateHashLock() ([32]byte, [32]byte, error) {
	var preimage [32]byte
	_, err := rand.Read(preimage[:])
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	hashLock := sha256.Sum256(preimage[:])
	return hashLock, preimage, nil
}

// InitiateSwap starts a new atomic swap from XVM to C-Chain
func (b *AtomicBridge) InitiateSwap(
	ctx context.Context,
	sender, recipient []byte,
	asset [32]byte,
	amount, minReceive *big.Int,
	deadline uint64,
	route []payload.SwapRoute,
) (*SwapRecord, error) {
	// Generate swap ID and hashlock
	swapID, err := b.generateSwapID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate swap ID: %w", err)
	}

	hashLock, preimage, err := generateHashLock()
	if err != nil {
		return nil, fmt.Errorf("failed to generate hashlock: %w", err)
	}

	// Increment nonce
	b.mu.Lock()
	nonce := b.nonceCounter
	b.nonceCounter++
	b.mu.Unlock()

	// Create swap record
	record := &SwapRecord{
		SwapID:      swapID,
		State:       SwapStatePending,
		SourceChain: b.sourceChainID,
		DestChain:   b.destChainID,
		Sender:      sender,
		Recipient:   recipient,
		Asset:       asset,
		Amount:      amount,
		MinReceive:  minReceive,
		Deadline:    deadline,
		Nonce:       nonce,
		HashLock:    hashLock,
		Preimage:    preimage,
		SwapRoute:   route,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Store the record
	b.mu.Lock()
	b.swaps[swapID] = record
	b.mu.Unlock()

	// Step 1: Lock assets on source chain (XVM)
	if err := b.lockAssets(ctx, record); err != nil {
		record.State = SwapStateCancelled
		return record, fmt.Errorf("failed to lock assets: %w", err)
	}

	return record, nil
}

// lockAssets locks assets on the source chain and sends Warp message
func (b *AtomicBridge) lockAssets(ctx context.Context, record *SwapRecord) error {
	record.mu.Lock()
	defer record.mu.Unlock()

	// Call the lock callback if set
	if b.onLock != nil {
		if err := b.onLock(ctx, record); err != nil {
			return err
		}
	}

	// Create the lock payload for Warp message
	swapPayload, err := payload.NewAtomicSwapPayload(
		payload.OpLock,
		record.SwapID,
		record.SourceChain,
		record.DestChain,
		record.Sender,
		record.Recipient,
		record.Asset,
		record.Amount,
		record.MinReceive,
		record.Deadline,
		record.Nonce,
		record.HashLock[:], // Include hashlock in data
	)
	if err != nil {
		return err
	}

	// Create Warp message with the lock payload
	addressedCall, err := payload.NewAddressedCall(record.Sender, swapPayload.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create addressed call: %w", err)
	}

	unsignedMsg, err := warp.NewUnsignedMessage(
		b.networkID,
		b.sourceChainID,
		addressedCall.Bytes(),
	)
	if err != nil {
		return fmt.Errorf("failed to create unsigned message: %w", err)
	}

	// Submit to backend for signing
	if b.backend != nil {
		if err := b.backend.AddMessage(unsignedMsg); err != nil {
			return fmt.Errorf("failed to submit message: %w", err)
		}
	}

	record.State = SwapStateLocked
	record.UpdatedAt = time.Now()
	return nil
}

// ProcessLockMessage processes an incoming lock message on dest chain
func (b *AtomicBridge) ProcessLockMessage(ctx context.Context, msg *warp.Message) error {
	// Parse the payload
	addressedCall, err := payload.ParseAddressedCall(msg.UnsignedMessage.Payload)
	if err != nil {
		return fmt.Errorf("invalid addressed call: %w", err)
	}

	swapPayload, err := payload.ParseAtomicSwapPayload(addressedCall.Payload)
	if err != nil {
		return fmt.Errorf("invalid swap payload: %w", err)
	}

	if swapPayload.Operation != payload.OpLock {
		return fmt.Errorf("expected Lock operation, got %s", swapPayload.OperationName())
	}

	// Verify the message source
	if msg.UnsignedMessage.SourceChainID != swapPayload.SourceChain {
		return errors.New("source chain mismatch")
	}

	// Get or create swap record
	b.mu.Lock()
	record, exists := b.swaps[swapPayload.SwapID]
	if !exists {
		record = &SwapRecord{
			SwapID:      swapPayload.SwapID,
			State:       SwapStateLocked,
			SourceChain: swapPayload.SourceChain,
			DestChain:   swapPayload.DestChain,
			Sender:      swapPayload.Sender,
			Recipient:   swapPayload.Recipient,
			Asset:       swapPayload.Asset,
			Amount:      swapPayload.Amount,
			MinReceive:  swapPayload.MinReceive,
			Deadline:    swapPayload.Deadline,
			Nonce:       swapPayload.Nonce,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		// Extract hashlock from data
		if len(swapPayload.Data) >= 32 {
			copy(record.HashLock[:], swapPayload.Data[:32])
		}
		b.swaps[swapPayload.SwapID] = record
	}
	b.mu.Unlock()

	// Step 2: Mint wrapped assets on destination chain
	if err := b.mintAssets(ctx, record); err != nil {
		return fmt.Errorf("failed to mint assets: %w", err)
	}

	return nil
}

// mintAssets mints wrapped assets on the destination chain
func (b *AtomicBridge) mintAssets(ctx context.Context, record *SwapRecord) error {
	record.mu.Lock()
	defer record.mu.Unlock()

	// Call the mint callback if set
	if b.onMint != nil {
		if err := b.onMint(ctx, record); err != nil {
			return err
		}
	}

	record.State = SwapStateMinted
	record.UpdatedAt = time.Now()

	// Step 3: Execute DEX swap if route is specified
	if len(record.SwapRoute) > 0 {
		record.mu.Unlock() // Unlock before calling swap
		if err := b.executeSwap(ctx, record); err != nil {
			record.mu.Lock()
			return err
		}
		record.mu.Lock()
	}

	return nil
}

// executeSwap executes a DEX swap on C-Chain using the DEX precompile
func (b *AtomicBridge) executeSwap(ctx context.Context, record *SwapRecord) error {
	record.mu.Lock()
	defer record.mu.Unlock()

	// Call the swap callback if set
	if b.onSwap != nil {
		if err := b.onSwap(ctx, record); err != nil {
			return err
		}
	}

	// Create swap message for confirmation
	swapPayload, err := payload.NewAtomicSwapPayload(
		payload.OpSwap,
		record.SwapID,
		record.SourceChain,
		record.DestChain,
		record.Sender,
		record.Recipient,
		record.Asset,
		record.Amount,
		record.MinReceive,
		record.Deadline,
		record.Nonce,
		nil,
	)
	if err != nil {
		return err
	}

	// Create Warp message for swap confirmation
	addressedCall, err := payload.NewAddressedCall(record.Recipient, swapPayload.Bytes())
	if err != nil {
		return err
	}

	unsignedMsg, err := warp.NewUnsignedMessage(
		b.networkID,
		b.destChainID,
		addressedCall.Bytes(),
	)
	if err != nil {
		return err
	}

	if b.backend != nil {
		if err := b.backend.AddMessage(unsignedMsg); err != nil {
			return err
		}
	}

	record.State = SwapStateSwapped
	record.UpdatedAt = time.Now()
	return nil
}

// SettleSwap completes the atomic swap by revealing the preimage
func (b *AtomicBridge) SettleSwap(ctx context.Context, swapID [32]byte, preimage [32]byte) error {
	b.mu.RLock()
	record, exists := b.swaps[swapID]
	b.mu.RUnlock()

	if !exists {
		return errors.New("swap not found")
	}

	// Verify preimage
	hashLock := sha256.Sum256(preimage[:])
	record.mu.Lock()
	if hashLock != record.HashLock {
		record.mu.Unlock()
		return errors.New("invalid preimage")
	}
	record.Preimage = preimage
	record.mu.Unlock()

	// Call settle callback
	if b.onSettle != nil {
		if err := b.onSettle(ctx, record); err != nil {
			return err
		}
	}

	// Create settlement message
	record.mu.Lock()
	swapPayload, err := payload.NewAtomicSwapPayload(
		payload.OpSettle,
		record.SwapID,
		record.SourceChain,
		record.DestChain,
		record.Sender,
		record.Recipient,
		record.Asset,
		record.Amount,
		record.MinReceive,
		record.Deadline,
		record.Nonce,
		preimage[:],
	)
	if err != nil {
		record.mu.Unlock()
		return err
	}

	addressedCall, err := payload.NewAddressedCall(record.Recipient, swapPayload.Bytes())
	if err != nil {
		record.mu.Unlock()
		return err
	}

	unsignedMsg, err := warp.NewUnsignedMessage(
		b.networkID,
		b.destChainID,
		addressedCall.Bytes(),
	)
	if err != nil {
		record.mu.Unlock()
		return err
	}

	if b.backend != nil {
		if err := b.backend.AddMessage(unsignedMsg); err != nil {
			record.mu.Unlock()
			return err
		}
	}

	record.State = SwapStateSettled
	record.UpdatedAt = time.Now()
	record.mu.Unlock()

	return nil
}

// CancelSwap cancels a swap that hasn't been settled (after deadline)
func (b *AtomicBridge) CancelSwap(ctx context.Context, swapID [32]byte) error {
	b.mu.RLock()
	record, exists := b.swaps[swapID]
	b.mu.RUnlock()

	if !exists {
		return errors.New("swap not found")
	}

	record.mu.Lock()
	defer record.mu.Unlock()

	// Check if deadline has passed
	if uint64(time.Now().Unix()) < record.Deadline {
		return errors.New("deadline not reached")
	}

	// Only locked or minted swaps can be canceled
	if record.State != SwapStateLocked && record.State != SwapStateMinted {
		return fmt.Errorf("cannot cancel swap in state: %s", record.State)
	}

	// Create unlock message to release locked assets
	unlockPayload, err := payload.NewAtomicSwapPayload(
		payload.OpUnlock,
		record.SwapID,
		record.SourceChain,
		record.DestChain,
		record.Sender,
		record.Recipient,
		record.Asset,
		record.Amount,
		record.MinReceive,
		record.Deadline,
		record.Nonce,
		nil,
	)
	if err != nil {
		return err
	}

	addressedCall, err := payload.NewAddressedCall(record.Sender, unlockPayload.Bytes())
	if err != nil {
		return err
	}

	unsignedMsg, err := warp.NewUnsignedMessage(
		b.networkID,
		b.destChainID,
		addressedCall.Bytes(),
	)
	if err != nil {
		return err
	}

	if b.backend != nil {
		if err := b.backend.AddMessage(unsignedMsg); err != nil {
			return err
		}
	}

	record.State = SwapStateCancelled
	record.UpdatedAt = time.Now()
	return nil
}

// GetSwap returns a swap record by ID
func (b *AtomicBridge) GetSwap(swapID [32]byte) (*SwapRecord, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	record, exists := b.swaps[swapID]
	if !exists {
		return nil, errors.New("swap not found")
	}
	return record, nil
}

// GetSwapByHex returns a swap record by hex-encoded ID
func (b *AtomicBridge) GetSwapByHex(swapIDHex string) (*SwapRecord, error) {
	decoded, err := hex.DecodeString(swapIDHex)
	if err != nil {
		return nil, err
	}
	if len(decoded) != 32 {
		return nil, errors.New("invalid swap ID length")
	}
	var swapID [32]byte
	copy(swapID[:], decoded)
	return b.GetSwap(swapID)
}

// ListSwaps returns all swaps matching the filter
func (b *AtomicBridge) ListSwaps(state SwapState) []*SwapRecord {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var result []*SwapRecord
	for _, record := range b.swaps {
		record.mu.RLock()
		if state == 0 || record.State == state {
			result = append(result, record)
		}
		record.mu.RUnlock()
	}
	return result
}

// CleanupExpired removes expired swaps
func (b *AtomicBridge) CleanupExpired() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := uint64(time.Now().Unix())
	cleaned := 0

	for id, record := range b.swaps {
		record.mu.Lock()
		if record.Deadline < now && record.State != SwapStateSettled {
			record.State = SwapStateExpired
			delete(b.swaps, id)
			cleaned++
		}
		record.mu.Unlock()
	}

	return cleaned
}
