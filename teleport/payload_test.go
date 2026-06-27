// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package teleport

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
)

func sample(t *testing.T) *TeleportPayload {
	t.Helper()
	return &TeleportPayload{
		Version:     TeleportBindingVersion,
		DestChainID: 96369,
		Token:       common.HexToAddress("0x1111111111111111111111111111111111111111"),
		Amount:      new(big.Int).Mul(big.NewInt(123456789), big.NewInt(1e18)),
		Recipient:   common.HexToAddress("0x2222222222222222222222222222222222222222"),
		VaultIsZero: true,
		Nonce:       42,
	}
}

func TestRoundTrip(t *testing.T) {
	pl := sample(t)
	encoded, err := pl.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(encoded) != PayloadSize {
		t.Fatalf("payload size = %d, want %d", len(encoded), PayloadSize)
	}

	var decoded TeleportPayload
	if err := decoded.UnmarshalBinary(encoded); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if decoded.Version != pl.Version ||
		decoded.DestChainID != pl.DestChainID ||
		decoded.Token != pl.Token ||
		decoded.Amount.Cmp(pl.Amount) != 0 ||
		decoded.Recipient != pl.Recipient ||
		decoded.VaultIsZero != pl.VaultIsZero ||
		decoded.Nonce != pl.Nonce {
		t.Fatalf("round-trip mismatch:\nwant=%+v\n got=%+v", pl, decoded)
	}
}

// TestAmountIsFull32Bytes proves the amount field is the FULL 32-byte
// big-endian value with no leading-zero stripping.
func TestAmountIsFull32Bytes(t *testing.T) {
	pl := sample(t)
	pl.Amount = big.NewInt(1) // 1 wei => 31 leading zero bytes + 0x01
	b, err := pl.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	// Amount occupies bytes [29:61]; for value 1 it must be 31 zeros + 0x01.
	amount := b[29:61]
	want := make([]byte, 32)
	want[31] = 0x01
	if !bytes.Equal(amount, want) {
		t.Fatalf("amount not full-32 big-endian: %x", amount)
	}
}

// TestEnvelopeIDMatchesComputeMessageHash pins D == warp.Message.ID()
// for a message whose payload is the 90-byte teleport block. Validators sign
// one D and the contract verifies the same D — one canonical preimage.
func TestEnvelopeIDMatchesComputeMessageHash(t *testing.T) {
	pl := &TeleportPayload{
		Version:     TeleportBindingVersion,
		DestChainID: 1,
		Token:       common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Amount:      big.NewInt(1_000_000),
		Recipient:   common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		VaultIsZero: false,
		Nonce:       7,
	}
	payload, err := pl.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	var sourceChainID ids.ID
	copy(sourceChainID[:], []byte("the-source-chain-id-32-bytes-pad"))
	networkID := uint32(96369)

	want, err := ComputeMessageHash(networkID, sourceChainID, pl)
	if err != nil {
		t.Fatalf("ComputeMessageHash: %v", err)
	}

	// The canonical preimage is exactly the Message NewMessage builds.
	message, err := warp.NewMessage(networkID, sourceChainID, payload)
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	got := message.ID()
	if !bytes.Equal(want[:], got[:]) {
		t.Fatalf("D mismatch:\n want = %x\n  got = %x", want[:], got[:])
	}
}

func TestVerifyRejectsWrongVersion(t *testing.T) {
	pl := sample(t)
	pl.Version = TeleportBindingVersion + 1
	if err := pl.Verify(); err == nil {
		t.Fatal("expected version mismatch error")
	}
	if _, err := pl.MarshalBinary(); err == nil {
		t.Fatal("expected MarshalBinary to refuse wrong version")
	}
}

func TestVerifyRejectsZeroDestChain(t *testing.T) {
	pl := sample(t)
	pl.DestChainID = 0
	if err := pl.Verify(); err == nil {
		t.Fatal("expected zero destChain error")
	}
}

func TestVerifyRejectsNegativeAmount(t *testing.T) {
	pl := sample(t)
	pl.Amount = big.NewInt(-1)
	if err := pl.Verify(); err == nil {
		t.Fatal("expected negative amount error")
	}
}

func TestAmountUint256Boundary(t *testing.T) {
	pl := sample(t)
	pl.Amount = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)) // 2^256-1
	if _, err := pl.MarshalBinary(); err != nil {
		t.Fatalf("MarshalBinary at uint256 max: %v", err)
	}
	pl.Amount = new(big.Int).Lsh(big.NewInt(1), 256) // 2^256, one too many
	if _, err := pl.MarshalBinary(); err == nil {
		t.Fatal("expected ErrAmountTooLarge for amount > uint256")
	}
}

// TestUnmarshalRejectsWrongLength proves decode is strict on the 90-byte
// length.
func TestUnmarshalRejectsWrongLength(t *testing.T) {
	pl := sample(t)
	b, err := pl.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	var d TeleportPayload
	if err := d.UnmarshalBinary(b[:len(b)-1]); err == nil {
		t.Fatal("expected length error on short payload")
	}
	if err := d.UnmarshalBinary(append(b, 0x00)); err == nil {
		t.Fatal("expected length error on long payload")
	}
}

// TestUnmarshalRejectsBadVaultByte proves the vault flag is a strict
// {0x00,0x01} boolean.
func TestUnmarshalRejectsBadVaultByte(t *testing.T) {
	pl := sample(t)
	b, err := pl.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	// VaultIsZero byte sits at offset 81.
	b[81] = 0x02
	var d TeleportPayload
	if err := d.UnmarshalBinary(b); err == nil {
		t.Fatal("expected error on out-of-domain vault byte")
	}
}
