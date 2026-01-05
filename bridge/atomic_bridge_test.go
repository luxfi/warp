// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
	"github.com/luxfi/warp/payload"
	"github.com/stretchr/testify/require"
)

// generateTestID creates a random ID for testing
func generateTestID() ids.ID {
	var id ids.ID
	rand.Read(id[:])
	return id
}

// mockBackend implements backend.Backend for testing
type mockBackend struct {
	messages []*warp.UnsignedMessage
	mu       sync.Mutex
}

func newMockBackend() *mockBackend {
	return &mockBackend{
		messages: make([]*warp.UnsignedMessage, 0),
	}
}

func (m *mockBackend) AddMessage(msg *warp.UnsignedMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, msg)
	return nil
}

func (m *mockBackend) GetMessage(index uint32) (*warp.Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if int(index) >= len(m.messages) {
		return nil, nil
	}
	return &warp.Message{
		UnsignedMessage: m.messages[index],
	}, nil
}

func (m *mockBackend) GetValidatorState() warp.ValidatorState {
	return nil
}

func (m *mockBackend) GetMessageCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.messages)
}

func TestNewAtomicBridge(t *testing.T) {
	require := require.New(t)

	sourceChain := generateTestID()
	destChain := generateTestID()
	backend := newMockBackend()

	cfg := &BridgeConfig{
		NetworkID:     1,
		SourceChainID: sourceChain,
		DestChainID:   destChain,
		Backend:       backend,
	}

	bridge := NewAtomicBridge(cfg)
	require.NotNil(bridge)
	require.Equal(uint32(1), bridge.networkID)
	require.Equal(sourceChain, bridge.sourceChainID)
	require.Equal(destChain, bridge.destChainID)
	require.NotNil(bridge.swaps)
}

func TestSwapStateString(t *testing.T) {
	tests := []struct {
		state    SwapState
		expected string
	}{
		{SwapStatePending, "pending"},
		{SwapStateLocked, "locked"},
		{SwapStateMinted, "minted"},
		{SwapStateSwapped, "swapped"},
		{SwapStateSettled, "settled"},
		{SwapStateCancelled, "canceled"},
		{SwapStateExpired, "expired"},
		{SwapState(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestInitiateSwap(t *testing.T) {
	require := require.New(t)

	sourceChain := generateTestID()
	destChain := generateTestID()
	backend := newMockBackend()

	cfg := &BridgeConfig{
		NetworkID:     1,
		SourceChainID: sourceChain,
		DestChainID:   destChain,
		Backend:       backend,
	}

	bridge := NewAtomicBridge(cfg)

	sender := make([]byte, 20)
	recipient := make([]byte, 20)
	rand.Read(sender)
	rand.Read(recipient)

	var asset [32]byte
	rand.Read(asset[:])

	amount := big.NewInt(1000000) // 1 token with 6 decimals
	minReceive := big.NewInt(990000)
	deadline := uint64(time.Now().Add(1 * time.Hour).Unix())

	// Create swap route
	route := []payload.SwapRoute{
		{
			TokenIn:     [20]byte{0x01},
			TokenOut:    [20]byte{0x02},
			PoolFee:     3000,
			TickSpacing: 60,
		},
	}

	record, err := bridge.InitiateSwap(
		context.Background(),
		sender,
		recipient,
		asset,
		amount,
		minReceive,
		deadline,
		route,
	)

	require.NoError(err)
	require.NotNil(record)
	require.Equal(SwapStateLocked, record.State)
	require.Equal(sourceChain, record.SourceChain)
	require.Equal(destChain, record.DestChain)
	require.Equal(amount, record.Amount)
	require.Equal(minReceive, record.MinReceive)
	require.Equal(deadline, record.Deadline)
	require.Equal(uint64(0), record.Nonce) // First swap
	require.NotEqual([32]byte{}, record.SwapID)
	require.NotEqual([32]byte{}, record.HashLock)
	require.NotEqual([32]byte{}, record.Preimage)

	// Verify hashlock is correct
	expectedHash := sha256.Sum256(record.Preimage[:])
	require.Equal(expectedHash, record.HashLock)

	// Verify message was sent
	require.Equal(1, backend.GetMessageCount())
}

func TestInitiateSwapWithCallbacks(t *testing.T) {
	require := require.New(t)

	sourceChain := generateTestID()
	destChain := generateTestID()
	backend := newMockBackend()

	cfg := &BridgeConfig{
		NetworkID:     1,
		SourceChainID: sourceChain,
		DestChainID:   destChain,
		Backend:       backend,
	}

	bridge := NewAtomicBridge(cfg)

	// Track callback invocations
	lockCalled := false
	bridge.SetCallbacks(
		func(ctx context.Context, swap *SwapRecord) error {
			lockCalled = true
			return nil
		},
		nil, nil, nil,
	)

	sender := make([]byte, 20)
	recipient := make([]byte, 20)
	var asset [32]byte
	amount := big.NewInt(1000000)
	deadline := uint64(time.Now().Add(1 * time.Hour).Unix())

	_, err := bridge.InitiateSwap(
		context.Background(),
		sender,
		recipient,
		asset,
		amount,
		big.NewInt(0),
		deadline,
		nil,
	)

	require.NoError(err)
	require.True(lockCalled)
}

func TestGetSwap(t *testing.T) {
	require := require.New(t)

	bridge := NewAtomicBridge(&BridgeConfig{
		NetworkID:     1,
		SourceChainID: generateTestID(),
		DestChainID:   generateTestID(),
		Backend:       newMockBackend(),
	})

	sender := make([]byte, 20)
	recipient := make([]byte, 20)
	var asset [32]byte
	amount := big.NewInt(1000000)
	deadline := uint64(time.Now().Add(1 * time.Hour).Unix())

	record, err := bridge.InitiateSwap(
		context.Background(),
		sender,
		recipient,
		asset,
		amount,
		big.NewInt(0),
		deadline,
		nil,
	)
	require.NoError(err)

	// Get by ID
	found, err := bridge.GetSwap(record.SwapID)
	require.NoError(err)
	require.Equal(record.SwapID, found.SwapID)

	// Get non-existent
	var fakeID [32]byte
	rand.Read(fakeID[:])
	_, err = bridge.GetSwap(fakeID)
	require.Error(err)
}

func TestGetSwapByHex(t *testing.T) {
	require := require.New(t)

	bridge := NewAtomicBridge(&BridgeConfig{
		NetworkID:     1,
		SourceChainID: generateTestID(),
		DestChainID:   generateTestID(),
		Backend:       newMockBackend(),
	})

	sender := make([]byte, 20)
	recipient := make([]byte, 20)
	var asset [32]byte
	amount := big.NewInt(1000000)
	deadline := uint64(time.Now().Add(1 * time.Hour).Unix())

	record, err := bridge.InitiateSwap(
		context.Background(),
		sender,
		recipient,
		asset,
		amount,
		big.NewInt(0),
		deadline,
		nil,
	)
	require.NoError(err)

	// Convert to hex and lookup
	hexID := ""
	for _, b := range record.SwapID {
		hexID += string([]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}[b>>4])
		hexID += string([]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}[b&0xf])
	}

	found, err := bridge.GetSwapByHex(hexID)
	require.NoError(err)
	require.Equal(record.SwapID, found.SwapID)

	// Invalid hex
	_, err = bridge.GetSwapByHex("invalid")
	require.Error(err)

	// Wrong length
	_, err = bridge.GetSwapByHex("abcd")
	require.Error(err)
}

func TestListSwaps(t *testing.T) {
	require := require.New(t)

	bridge := NewAtomicBridge(&BridgeConfig{
		NetworkID:     1,
		SourceChainID: generateTestID(),
		DestChainID:   generateTestID(),
		Backend:       newMockBackend(),
	})

	sender := make([]byte, 20)
	recipient := make([]byte, 20)
	var asset [32]byte
	amount := big.NewInt(1000000)
	deadline := uint64(time.Now().Add(1 * time.Hour).Unix())

	// Create 3 swaps
	for i := 0; i < 3; i++ {
		_, err := bridge.InitiateSwap(
			context.Background(),
			sender,
			recipient,
			asset,
			amount,
			big.NewInt(0),
			deadline,
			nil,
		)
		require.NoError(err)
	}

	// List all (0 means all states since SwapStatePending is 0)
	all := bridge.ListSwaps(0)
	require.Len(all, 3)

	// List by state - all swaps are locked after InitiateSwap
	locked := bridge.ListSwaps(SwapStateLocked)
	require.Len(locked, 3)

	// No settled swaps
	settled := bridge.ListSwaps(SwapStateSettled)
	require.Len(settled, 0)
}

func TestSettleSwap(t *testing.T) {
	require := require.New(t)

	bridge := NewAtomicBridge(&BridgeConfig{
		NetworkID:     1,
		SourceChainID: generateTestID(),
		DestChainID:   generateTestID(),
		Backend:       newMockBackend(),
	})

	settleCalled := false
	bridge.SetCallbacks(nil, nil, nil, func(ctx context.Context, swap *SwapRecord) error {
		settleCalled = true
		return nil
	})

	sender := make([]byte, 20)
	recipient := make([]byte, 20)
	var asset [32]byte
	amount := big.NewInt(1000000)
	deadline := uint64(time.Now().Add(1 * time.Hour).Unix())

	record, err := bridge.InitiateSwap(
		context.Background(),
		sender,
		recipient,
		asset,
		amount,
		big.NewInt(0),
		deadline,
		nil,
	)
	require.NoError(err)

	// Settle with correct preimage
	err = bridge.SettleSwap(context.Background(), record.SwapID, record.Preimage)
	require.NoError(err)
	require.True(settleCalled)

	// Verify state
	found, err := bridge.GetSwap(record.SwapID)
	require.NoError(err)
	require.Equal(SwapStateSettled, found.State)
}

func TestSettleSwapInvalidPreimage(t *testing.T) {
	require := require.New(t)

	bridge := NewAtomicBridge(&BridgeConfig{
		NetworkID:     1,
		SourceChainID: generateTestID(),
		DestChainID:   generateTestID(),
		Backend:       newMockBackend(),
	})

	sender := make([]byte, 20)
	recipient := make([]byte, 20)
	var asset [32]byte
	amount := big.NewInt(1000000)
	deadline := uint64(time.Now().Add(1 * time.Hour).Unix())

	record, err := bridge.InitiateSwap(
		context.Background(),
		sender,
		recipient,
		asset,
		amount,
		big.NewInt(0),
		deadline,
		nil,
	)
	require.NoError(err)

	// Settle with wrong preimage
	var wrongPreimage [32]byte
	rand.Read(wrongPreimage[:])
	err = bridge.SettleSwap(context.Background(), record.SwapID, wrongPreimage)
	require.Error(err)
	require.Contains(err.Error(), "invalid preimage")
}

func TestSettleSwapNotFound(t *testing.T) {
	require := require.New(t)

	bridge := NewAtomicBridge(&BridgeConfig{
		NetworkID:     1,
		SourceChainID: generateTestID(),
		DestChainID:   generateTestID(),
		Backend:       newMockBackend(),
	})

	var fakeID [32]byte
	var preimage [32]byte
	rand.Read(fakeID[:])
	rand.Read(preimage[:])

	err := bridge.SettleSwap(context.Background(), fakeID, preimage)
	require.Error(err)
	require.Contains(err.Error(), "swap not found")
}

func TestCancelSwap(t *testing.T) {
	require := require.New(t)

	bridge := NewAtomicBridge(&BridgeConfig{
		NetworkID:     1,
		SourceChainID: generateTestID(),
		DestChainID:   generateTestID(),
		Backend:       newMockBackend(),
	})

	sender := make([]byte, 20)
	recipient := make([]byte, 20)
	var asset [32]byte
	amount := big.NewInt(1000000)
	// Deadline in the past
	deadline := uint64(time.Now().Add(-1 * time.Hour).Unix())

	record, err := bridge.InitiateSwap(
		context.Background(),
		sender,
		recipient,
		asset,
		amount,
		big.NewInt(0),
		deadline,
		nil,
	)
	require.NoError(err)

	// Cancel after deadline
	err = bridge.CancelSwap(context.Background(), record.SwapID)
	require.NoError(err)

	found, err := bridge.GetSwap(record.SwapID)
	require.NoError(err)
	require.Equal(SwapStateCancelled, found.State)
}

func TestCancelSwapBeforeDeadline(t *testing.T) {
	require := require.New(t)

	bridge := NewAtomicBridge(&BridgeConfig{
		NetworkID:     1,
		SourceChainID: generateTestID(),
		DestChainID:   generateTestID(),
		Backend:       newMockBackend(),
	})

	sender := make([]byte, 20)
	recipient := make([]byte, 20)
	var asset [32]byte
	amount := big.NewInt(1000000)
	// Deadline in the future
	deadline := uint64(time.Now().Add(1 * time.Hour).Unix())

	record, err := bridge.InitiateSwap(
		context.Background(),
		sender,
		recipient,
		asset,
		amount,
		big.NewInt(0),
		deadline,
		nil,
	)
	require.NoError(err)

	// Try to cancel before deadline
	err = bridge.CancelSwap(context.Background(), record.SwapID)
	require.Error(err)
	require.Contains(err.Error(), "deadline not reached")
}

func TestCancelSwapNotFound(t *testing.T) {
	require := require.New(t)

	bridge := NewAtomicBridge(&BridgeConfig{
		NetworkID:     1,
		SourceChainID: generateTestID(),
		DestChainID:   generateTestID(),
		Backend:       newMockBackend(),
	})

	var fakeID [32]byte
	rand.Read(fakeID[:])

	err := bridge.CancelSwap(context.Background(), fakeID)
	require.Error(err)
	require.Contains(err.Error(), "swap not found")
}

func TestCleanupExpired(t *testing.T) {
	require := require.New(t)

	bridge := NewAtomicBridge(&BridgeConfig{
		NetworkID:     1,
		SourceChainID: generateTestID(),
		DestChainID:   generateTestID(),
		Backend:       newMockBackend(),
	})

	sender := make([]byte, 20)
	recipient := make([]byte, 20)
	var asset [32]byte
	amount := big.NewInt(1000000)

	// Create expired swap
	expiredDeadline := uint64(time.Now().Add(-1 * time.Hour).Unix())
	_, err := bridge.InitiateSwap(
		context.Background(),
		sender,
		recipient,
		asset,
		amount,
		big.NewInt(0),
		expiredDeadline,
		nil,
	)
	require.NoError(err)

	// Create valid swap
	validDeadline := uint64(time.Now().Add(1 * time.Hour).Unix())
	_, err = bridge.InitiateSwap(
		context.Background(),
		sender,
		recipient,
		asset,
		amount,
		big.NewInt(0),
		validDeadline,
		nil,
	)
	require.NoError(err)

	// Cleanup
	cleaned := bridge.CleanupExpired()
	require.Equal(1, cleaned)

	// Only 1 swap remaining
	all := bridge.ListSwaps(0)
	require.Len(all, 1)
}

func TestConcurrentSwaps(t *testing.T) {
	require := require.New(t)

	bridge := NewAtomicBridge(&BridgeConfig{
		NetworkID:     1,
		SourceChainID: generateTestID(),
		DestChainID:   generateTestID(),
		Backend:       newMockBackend(),
	})

	var wg sync.WaitGroup
	numSwaps := 10

	for i := 0; i < numSwaps; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			sender := make([]byte, 20)
			recipient := make([]byte, 20)
			rand.Read(sender)
			rand.Read(recipient)

			var asset [32]byte
			rand.Read(asset[:])

			amount := big.NewInt(1000000)
			deadline := uint64(time.Now().Add(1 * time.Hour).Unix())

			_, err := bridge.InitiateSwap(
				context.Background(),
				sender,
				recipient,
				asset,
				amount,
				big.NewInt(0),
				deadline,
				nil,
			)
			require.NoError(err)
		}()
	}

	wg.Wait()

	// Verify all swaps created
	all := bridge.ListSwaps(0)
	require.Len(all, numSwaps)

	// Verify unique nonces
	nonces := make(map[uint64]bool)
	for _, swap := range all {
		require.False(nonces[swap.Nonce], "duplicate nonce found")
		nonces[swap.Nonce] = true
	}
}

func TestGenerateHashLock(t *testing.T) {
	require := require.New(t)

	hashLock, preimage, err := generateHashLock()
	require.NoError(err)
	require.NotEqual([32]byte{}, hashLock)
	require.NotEqual([32]byte{}, preimage)

	// Verify hashlock is sha256 of preimage
	expected := sha256.Sum256(preimage[:])
	require.Equal(expected, hashLock)
}

func TestNonceIncrement(t *testing.T) {
	require := require.New(t)

	bridge := NewAtomicBridge(&BridgeConfig{
		NetworkID:     1,
		SourceChainID: generateTestID(),
		DestChainID:   generateTestID(),
		Backend:       newMockBackend(),
	})

	sender := make([]byte, 20)
	recipient := make([]byte, 20)
	var asset [32]byte
	amount := big.NewInt(1000000)
	deadline := uint64(time.Now().Add(1 * time.Hour).Unix())

	// Create multiple swaps
	for i := 0; i < 5; i++ {
		record, err := bridge.InitiateSwap(
			context.Background(),
			sender,
			recipient,
			asset,
			amount,
			big.NewInt(0),
			deadline,
			nil,
		)
		require.NoError(err)
		require.Equal(uint64(i), record.Nonce)
	}
}

func TestSwapWithRoute(t *testing.T) {
	require := require.New(t)

	bridge := NewAtomicBridge(&BridgeConfig{
		NetworkID:     1,
		SourceChainID: generateTestID(),
		DestChainID:   generateTestID(),
		Backend:       newMockBackend(),
	})

	sender := make([]byte, 20)
	recipient := make([]byte, 20)
	var asset [32]byte
	amount := big.NewInt(1000000)
	deadline := uint64(time.Now().Add(1 * time.Hour).Unix())

	route := []payload.SwapRoute{
		{
			TokenIn:     [20]byte{0x01},
			TokenOut:    [20]byte{0x02},
			PoolFee:     500, // 0.05%
			TickSpacing: 10,
		},
		{
			TokenIn:     [20]byte{0x02},
			TokenOut:    [20]byte{0x03},
			PoolFee:     3000, // 0.3%
			TickSpacing: 60,
		},
	}

	record, err := bridge.InitiateSwap(
		context.Background(),
		sender,
		recipient,
		asset,
		amount,
		big.NewInt(0),
		deadline,
		route,
	)
	require.NoError(err)
	require.Len(record.SwapRoute, 2)
	require.Equal(uint32(500), record.SwapRoute[0].PoolFee)
	require.Equal(uint32(3000), record.SwapRoute[1].PoolFee)
}
