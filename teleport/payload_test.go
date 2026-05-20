// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package teleport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/rlp"
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
)

func TestRoundTrip(t *testing.T) {
	pl := &TeleportPayload{
		Version:     TeleportBindingVersion,
		DestChainID: 96369,
		Token:       common.HexToAddress("0x1111111111111111111111111111111111111111"),
		Amount:      new(big.Int).Mul(big.NewInt(123456789), big.NewInt(1e18)),
		Recipient:   common.HexToAddress("0x2222222222222222222222222222222222222222"),
		VaultIsZero: true,
		Nonce:       42,
	}

	encoded, err := pl.MarshalRLP()
	if err != nil {
		t.Fatalf("MarshalRLP: %v", err)
	}

	var decoded TeleportPayload
	if err := decoded.UnmarshalRLP(encoded); err != nil {
		t.Fatalf("UnmarshalRLP: %v", err)
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

// TestEnvelopeIDMatchesComputeMessageHash pins the invariant that
// EnvelopeV2.ID() for a Teleport envelope is byte-equal to
// ComputeMessageHash(NetworkID, SourceChainID, payload). Without this,
// validators sign one preimage and the contract verifies another (the
// RED-2 wire-format split). Any reorganisation of the wire format
// MUST keep this round-trip green.
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
	payload, err := pl.MarshalRLP()
	if err != nil {
		t.Fatalf("MarshalRLP: %v", err)
	}

	var sourceChainID ids.ID
	copy(sourceChainID[:], []byte("the-source-chain-id-32-bytes-pad"))
	networkID := uint32(96369)

	// Path A: via the package's canonical hash.
	want, err := ComputeMessageHash(networkID, sourceChainID, pl)
	if err != nil {
		t.Fatalf("ComputeMessageHash: %v", err)
	}

	// Path B: build a real UnsignedMessage and take its ID via warp.
	unsigned := &warp.UnsignedMessage{
		NetworkID:     networkID,
		SourceChainID: sourceChainID,
		Payload:       payload,
	}
	got := unsigned.ID()

	if !bytes.Equal(want[:], got[:]) {
		t.Fatalf("canonical hash mismatch:\n want = %s\n  got = %s",
			hex.EncodeToString(want[:]), hex.EncodeToString(got[:]))
	}

	// Belt-and-braces: sha256(rlp([networkID, sourceChainID[:], payload])) == want.
	body, _ := rlp.EncodeToBytes([]interface{}{networkID, sourceChainID[:], payload})
	check := sha256.Sum256(body)
	if !bytes.Equal(want[:], check[:]) {
		t.Fatalf("explicit sha256 mismatch:\n want = %s\n  got = %s",
			hex.EncodeToString(want[:]), hex.EncodeToString(check[:]))
	}
}

func TestVerifyRejectsWrongVersion(t *testing.T) {
	pl := &TeleportPayload{
		Version:     TeleportBindingVersion + 1,
		DestChainID: 1,
		Token:       common.Address{},
		Amount:      big.NewInt(1),
		Recipient:   common.Address{},
		VaultIsZero: true,
		Nonce:       0,
	}
	if err := pl.Verify(); err == nil {
		t.Fatal("expected version mismatch error")
	}
	if _, err := pl.MarshalRLP(); err == nil {
		t.Fatal("expected MarshalRLP to refuse wrong version")
	}
}

func TestVerifyRejectsZeroDestChain(t *testing.T) {
	pl := &TeleportPayload{
		Version:     TeleportBindingVersion,
		DestChainID: 0,
		Token:       common.Address{},
		Amount:      big.NewInt(1),
		Recipient:   common.Address{},
		VaultIsZero: true,
		Nonce:       0,
	}
	if err := pl.Verify(); err == nil {
		t.Fatal("expected zero destChain error")
	}
}

func TestVerifyRejectsNegativeAmount(t *testing.T) {
	pl := &TeleportPayload{
		Version:     TeleportBindingVersion,
		DestChainID: 1,
		Token:       common.Address{},
		Amount:      big.NewInt(-1),
		Recipient:   common.Address{},
		VaultIsZero: true,
		Nonce:       0,
	}
	if err := pl.Verify(); err == nil {
		t.Fatal("expected negative amount error")
	}
}

// TestAmountUint256Boundary confirms the canonical-amount encoding
// matches uint256 semantics: 2^256-1 encodes as 32 bytes, anything
// larger rejects.
func TestAmountUint256Boundary(t *testing.T) {
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	pl := &TeleportPayload{
		Version:     TeleportBindingVersion,
		DestChainID: 1,
		Token:       common.Address{},
		Amount:      max,
		Recipient:   common.Address{},
		VaultIsZero: false,
		Nonce:       0,
	}
	if _, err := pl.MarshalRLP(); err != nil {
		t.Fatalf("MarshalRLP at uint256 max: %v", err)
	}
	too := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256, one too many
	pl.Amount = too
	if _, err := pl.MarshalRLP(); err == nil {
		t.Fatal("expected ErrAmountTooLarge for amount > uint256")
	}
}
