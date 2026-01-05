// Copyright (C) 2019-2025, Lux Industries Inc All rights reserved.
// See the file LICENSE for licensing terms.

package payload

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/luxfi/ids"
)

// generateTestID creates a random ID for testing
func generateTestID() ids.ID {
	var id ids.ID
	rand.Read(id[:])
	return id
}

func TestAtomicSwapPayload_NewAndBytes(t *testing.T) {
	sourceChain := generateTestID()
	destChain := generateTestID()
	swapID := [32]byte{1, 2, 3, 4}
	sender := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78}
	recipient := []byte{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01}
	asset := [32]byte{0xaa, 0xbb, 0xcc}
	amount := big.NewInt(1000000) // 1 token with 6 decimals
	minReceive := big.NewInt(990000)
	deadline := uint64(1704067200) // 2024-01-01
	nonce := uint64(42)
	data := []byte{0x11, 0x22, 0x33}

	p, err := NewAtomicSwapPayload(
		OpLock,
		swapID,
		sourceChain, destChain,
		sender, recipient,
		asset,
		amount, minReceive,
		deadline, nonce,
		data,
	)
	if err != nil {
		t.Fatalf("NewAtomicSwapPayload failed: %v", err)
	}

	// Test serialization
	encoded := p.Bytes()
	if len(encoded) == 0 {
		t.Fatal("encoded payload is empty")
	}

	// Test deserialization
	decoded, err := ParseAtomicSwapPayload(encoded)
	if err != nil {
		t.Fatalf("ParseAtomicSwapPayload failed: %v", err)
	}

	// Verify all fields
	if decoded.Version != 1 {
		t.Errorf("version mismatch: got %d, want 1", decoded.Version)
	}
	if decoded.Operation != OpLock {
		t.Errorf("operation mismatch: got %d, want %d", decoded.Operation, OpLock)
	}
	if decoded.SwapID != swapID {
		t.Errorf("swapID mismatch")
	}
	if decoded.SourceChain != sourceChain {
		t.Errorf("sourceChain mismatch")
	}
	if decoded.DestChain != destChain {
		t.Errorf("destChain mismatch")
	}
	if !bytes.Equal(decoded.Sender, sender) {
		t.Errorf("sender mismatch")
	}
	if !bytes.Equal(decoded.Recipient, recipient) {
		t.Errorf("recipient mismatch")
	}
	if decoded.Asset != asset {
		t.Errorf("asset mismatch")
	}
	if decoded.Amount.Cmp(amount) != 0 {
		t.Errorf("amount mismatch: got %s, want %s", decoded.Amount, amount)
	}
	if decoded.MinReceive.Cmp(minReceive) != 0 {
		t.Errorf("minReceive mismatch: got %s, want %s", decoded.MinReceive, minReceive)
	}
	if decoded.Deadline != deadline {
		t.Errorf("deadline mismatch: got %d, want %d", decoded.Deadline, deadline)
	}
	if decoded.Nonce != nonce {
		t.Errorf("nonce mismatch: got %d, want %d", decoded.Nonce, nonce)
	}
	if !bytes.Equal(decoded.Data, data) {
		t.Errorf("data mismatch")
	}
}

func TestAtomicSwapPayload_ValidationErrors(t *testing.T) {
	sourceChain := generateTestID()
	destChain := generateTestID()
	swapID := [32]byte{1}
	asset := [32]byte{1}

	tests := []struct {
		name      string
		sender    []byte
		recipient []byte
		amount    *big.Int
		wantErr   string
	}{
		{
			name:      "empty sender",
			sender:    []byte{},
			recipient: []byte{1, 2, 3},
			amount:    big.NewInt(100),
			wantErr:   "sender address required",
		},
		{
			name:      "empty recipient",
			sender:    []byte{1, 2, 3},
			recipient: []byte{},
			amount:    big.NewInt(100),
			wantErr:   "recipient address required",
		},
		{
			name:      "nil amount",
			sender:    []byte{1, 2, 3},
			recipient: []byte{4, 5, 6},
			amount:    nil,
			wantErr:   "amount must be positive",
		},
		{
			name:      "zero amount",
			sender:    []byte{1, 2, 3},
			recipient: []byte{4, 5, 6},
			amount:    big.NewInt(0),
			wantErr:   "amount must be positive",
		},
		{
			name:      "negative amount",
			sender:    []byte{1, 2, 3},
			recipient: []byte{4, 5, 6},
			amount:    big.NewInt(-100),
			wantErr:   "amount must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAtomicSwapPayload(
				OpLock,
				swapID,
				sourceChain, destChain,
				tt.sender, tt.recipient,
				asset,
				tt.amount, nil,
				0, 0,
				nil,
			)
			if err == nil {
				t.Error("expected error, got nil")
			} else if err.Error() != tt.wantErr {
				t.Errorf("error mismatch: got %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestAtomicSwapPayload_OperationName(t *testing.T) {
	tests := []struct {
		op   uint8
		want string
	}{
		{OpLock, "Lock"},
		{OpUnlock, "Unlock"},
		{OpMint, "Mint"},
		{OpBurn, "Burn"},
		{OpSwap, "Swap"},
		{OpSettle, "Settle"},
		{99, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			p := &AtomicSwapPayload{Operation: tt.op}
			if got := p.OperationName(); got != tt.want {
				t.Errorf("OperationName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAtomicSwapPayload_IsValid(t *testing.T) {
	tests := []struct {
		name    string
		payload *AtomicSwapPayload
		wantErr bool
	}{
		{
			name: "valid",
			payload: &AtomicSwapPayload{
				Version:   1,
				Operation: OpLock,
				Sender:    []byte{1, 2, 3},
				Recipient: []byte{4, 5, 6},
				Amount:    big.NewInt(100),
			},
			wantErr: false,
		},
		{
			name: "invalid version",
			payload: &AtomicSwapPayload{
				Version:   2,
				Operation: OpLock,
				Sender:    []byte{1, 2, 3},
				Recipient: []byte{4, 5, 6},
				Amount:    big.NewInt(100),
			},
			wantErr: true,
		},
		{
			name: "invalid operation",
			payload: &AtomicSwapPayload{
				Version:   1,
				Operation: 99,
				Sender:    []byte{1, 2, 3},
				Recipient: []byte{4, 5, 6},
				Amount:    big.NewInt(100),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.payload.IsValid()
			if (err != nil) != tt.wantErr {
				t.Errorf("IsValid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSwapRoute_Bytes(t *testing.T) {
	route := &SwapRoute{
		TokenIn:     [20]byte{0x11, 0x22, 0x33},
		TokenOut:    [20]byte{0xaa, 0xbb, 0xcc},
		PoolFee:     3000, // 0.3%
		TickSpacing: 60,
		Hooks:       [20]byte{},
	}

	encoded := route.Bytes()
	if len(encoded) != 68 {
		t.Fatalf("encoded length = %d, want 68", len(encoded))
	}

	decoded, err := ParseSwapRoute(encoded)
	if err != nil {
		t.Fatalf("ParseSwapRoute failed: %v", err)
	}

	if decoded.TokenIn != route.TokenIn {
		t.Error("TokenIn mismatch")
	}
	if decoded.TokenOut != route.TokenOut {
		t.Error("TokenOut mismatch")
	}
	if decoded.PoolFee != route.PoolFee {
		t.Errorf("PoolFee = %d, want %d", decoded.PoolFee, route.PoolFee)
	}
	if decoded.TickSpacing != route.TickSpacing {
		t.Errorf("TickSpacing = %d, want %d", decoded.TickSpacing, route.TickSpacing)
	}
	if decoded.Hooks != route.Hooks {
		t.Error("Hooks mismatch")
	}
}

func TestMultiHopRoute_Bytes(t *testing.T) {
	multiHop := &MultiHopRoute{
		Hops: []SwapRoute{
			{
				TokenIn:     [20]byte{0x11},
				TokenOut:    [20]byte{0x22},
				PoolFee:     500,
				TickSpacing: 10,
			},
			{
				TokenIn:     [20]byte{0x22},
				TokenOut:    [20]byte{0x33},
				PoolFee:     3000,
				TickSpacing: 60,
			},
		},
	}

	encoded := multiHop.Bytes()
	expectedLen := 4 + 2*68
	if len(encoded) != expectedLen {
		t.Fatalf("encoded length = %d, want %d", len(encoded), expectedLen)
	}

	decoded, err := ParseMultiHopRoute(encoded)
	if err != nil {
		t.Fatalf("ParseMultiHopRoute failed: %v", err)
	}

	if len(decoded.Hops) != 2 {
		t.Fatalf("hops count = %d, want 2", len(decoded.Hops))
	}
	if decoded.Hops[0].PoolFee != 500 {
		t.Errorf("first hop fee = %d, want 500", decoded.Hops[0].PoolFee)
	}
	if decoded.Hops[1].PoolFee != 3000 {
		t.Errorf("second hop fee = %d, want 3000", decoded.Hops[1].PoolFee)
	}
}

func TestXVMAssetLock_Bytes(t *testing.T) {
	lock := &XVMAssetLock{
		TxID:        [32]byte{0xaa, 0xbb},
		OutputIndex: 0,
		AssetID:     [32]byte{0xcc, 0xdd},
		Amount:      1000000,
		LockScript:  []byte{0x76, 0xa9, 0x14}, // P2PKH prefix
		HashLock:    [32]byte{0xff},
		TimeLock:    1704067200,
	}

	encoded := lock.Bytes()
	if len(encoded) == 0 {
		t.Fatal("encoded lock is empty")
	}

	// Basic size check: 32 + 4 + 32 + 8 + 4 + len(script) + 32 + 8
	expectedMinLen := 32 + 4 + 32 + 8 + 4 + len(lock.LockScript) + 32 + 8
	if len(encoded) != expectedMinLen {
		t.Errorf("encoded length = %d, want %d", len(encoded), expectedMinLen)
	}
}

func TestParseAtomicSwapPayload_InvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{1, 2, 3}},
		{"invalid version", append([]byte{2}, make([]byte, 200)...)}, // version 2
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAtomicSwapPayload(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestParseSwapRoute_TooShort(t *testing.T) {
	_, err := ParseSwapRoute([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestParseMultiHopRoute_TooShort(t *testing.T) {
	_, err := ParseMultiHopRoute([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for short data")
	}
}

func BenchmarkAtomicSwapPayload_Bytes(b *testing.B) {
	p := &AtomicSwapPayload{
		Version:     1,
		Operation:   OpSwap,
		SwapID:      [32]byte{1, 2, 3, 4},
		SourceChain: generateTestID(),
		DestChain:   generateTestID(),
		Sender:      make([]byte, 20),
		Recipient:   make([]byte, 20),
		Asset:       [32]byte{0xaa, 0xbb},
		Amount:      big.NewInt(1000000),
		MinReceive:  big.NewInt(990000),
		Deadline:    1704067200,
		Nonce:       42,
		Data:        make([]byte, 64),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Bytes()
	}
}

func BenchmarkParseAtomicSwapPayload(b *testing.B) {
	p := &AtomicSwapPayload{
		Version:     1,
		Operation:   OpSwap,
		SwapID:      [32]byte{1, 2, 3, 4},
		SourceChain: generateTestID(),
		DestChain:   generateTestID(),
		Sender:      make([]byte, 20),
		Recipient:   make([]byte, 20),
		Asset:       [32]byte{0xaa, 0xbb},
		Amount:      big.NewInt(1000000),
		MinReceive:  big.NewInt(990000),
		Deadline:    1704067200,
		Nonce:       42,
		Data:        make([]byte, 64),
	}
	encoded := p.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseAtomicSwapPayload(encoded)
	}
}
