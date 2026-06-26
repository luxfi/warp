// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command fixtures emits the canonical TeleportPayload byte fixtures used
// by the Solidity round-trip test. The output is a JSON document at the
// path given by `-out` (defaults to
// teleport/contracts/test/fixtures/teleport_payload.json relative to the
// lux workspace root).
//
// The Solidity test reads the JSON and asserts that its on-chain
// _computeMessageHash matches `messageHash` (= D), and that its on-chain
// teleport-payload packing matches `payload` (the fixed 90-byte block)
// and the canonical SignedCore preimage matches `coreC14n`. Drift between
// the Go encoder and the Solidity encoder is a CI failure.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
	"github.com/luxfi/warp/teleport"
)

type Fixture struct {
	Name          string `json:"name"`
	NetworkID     string `json:"networkID"`     // decimal string (uint32 fits, but uniform with the rest)
	SourceChainID string `json:"sourceChainID"` // 0x-prefixed 32-byte hex
	Version       uint8  `json:"version"`
	DestChainID   string `json:"destChainID"` // decimal string (uint64 may exceed JS safe int)
	Token         string `json:"token"`       // 0x-prefixed 20-byte hex
	Amount        string `json:"amount"`      // decimal string (uint256)
	Recipient     string `json:"recipient"`   // 0x-prefixed 20-byte hex
	VaultIsZero   bool   `json:"vaultIsZero"`
	Nonce         string `json:"nonce"` // decimal string (uint64)

	// Outputs (Go-computed; Solidity must match byte-for-byte).
	Payload     string `json:"payload"`     // hex of the fixed 90-byte TeleportPayload block
	CoreC14n    string `json:"coreC14n"`    // hex of zap_c14n(SignedCore) — the digest preimage
	MessageHash string `json:"messageHash"` // hex of D = keccak256("LUX-WARP-ZAP-CORE-v1" ‖ coreC14n)
}

func parseSrcChain(hexStr string) (ids.ID, error) {
	var id ids.ID
	b, err := hex.DecodeString(hexStr[2:])
	if err != nil {
		return id, err
	}
	if len(b) != 32 {
		return id, fmt.Errorf("sourceChainID must be 32 bytes, got %d", len(b))
	}
	copy(id[:], b)
	return id, nil
}

func emit(name string, networkID uint32, sourceChainID, token, recipient string, destChainID uint64, amount *big.Int, vaultIsZero bool, nonce uint64) (Fixture, error) {
	src, err := parseSrcChain(sourceChainID)
	if err != nil {
		return Fixture{}, err
	}
	pl := &teleport.TeleportPayload{
		Version:     teleport.TeleportBindingVersion,
		DestChainID: destChainID,
		Token:       common.HexToAddress(token),
		Amount:      new(big.Int).Set(amount),
		Recipient:   common.HexToAddress(recipient),
		VaultIsZero: vaultIsZero,
		Nonce:       nonce,
	}
	payload, err := pl.MarshalBinary()
	if err != nil {
		return Fixture{}, err
	}
	core, err := warp.NewSignedCore(networkID, src, payload)
	if err != nil {
		return Fixture{}, err
	}
	hash, err := teleport.ComputeMessageHash(networkID, src, pl)
	if err != nil {
		return Fixture{}, err
	}
	return Fixture{
		Name:          name,
		NetworkID:     fmt.Sprintf("%d", networkID),
		SourceChainID: "0x" + hex.EncodeToString(src[:]),
		Version:       pl.Version,
		DestChainID:   fmt.Sprintf("%d", pl.DestChainID),
		Token:         "0x" + hex.EncodeToString(pl.Token.Bytes()),
		Amount:        pl.Amount.String(),
		Recipient:     "0x" + hex.EncodeToString(pl.Recipient.Bytes()),
		VaultIsZero:   pl.VaultIsZero,
		Nonce:         fmt.Sprintf("%d", pl.Nonce),
		Payload:       "0x" + hex.EncodeToString(payload),
		CoreC14n:      "0x" + hex.EncodeToString(core.Bytes()),
		MessageHash:   "0x" + hex.EncodeToString(hash[:]),
	}, nil
}

func main() {
	var out string
	flag.StringVar(&out, "out", "", "output JSON path (default stdout)")
	flag.Parse()

	smallAmount := new(big.Int).Mul(big.NewInt(1), big.NewInt(1_000_000_000_000_000_000)) // 1 token
	bigAmount := new(big.Int).Mul(big.NewInt(123_456_789), big.NewInt(1_000_000_000_000_000_000))
	maxAmount := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

	// rightAlignedID encodes a uint64 sourceChainID into the
	// right-aligned 32-byte form Solidity's
	// bytes32(uint256(sourceChainId)) produces. Fixtures using this
	// helper exercise the full Solidity messageHash; fixtures with
	// arbitrary 32-byte source ids exercise only the payload RLP
	// (which is independent of source-chain-id shape).
	rightAlignedID := func(v uint64) string {
		var b [32]byte
		for i := 0; i < 8; i++ {
			b[31-i] = byte(v >> (8 * uint(i)))
		}
		return "0x" + hex.EncodeToString(b[:])
	}

	cases := []struct {
		Name        string
		NetworkID   uint32
		SourceChain string
		Token       string
		Recipient   string
		DestChainID uint64
		Amount      *big.Int
		VaultIsZero bool
		Nonce       uint64
	}{
		// Solidity-compatible source chain IDs (right-aligned
		// big-endian of the networkID). The on-chain Solidity helper
		// composes `bytes32(uint256(networkId))` which matches this
		// layout exactly, so these fixtures exercise the FULL
		// Go ↔ Solidity round-trip end-to-end.
		{
			Name:        "sol_compatible_small_burn",
			NetworkID:   96369,
			SourceChain: rightAlignedID(96369),
			Token:       "0x1111111111111111111111111111111111111111",
			Recipient:   "0x2222222222222222222222222222222222222222",
			DestChainID: 1,
			Amount:      smallAmount,
			VaultIsZero: true,
			Nonce:       0,
		},
		{
			Name:        "sol_compatible_large_vault",
			NetworkID:   96369,
			SourceChain: rightAlignedID(96369),
			Token:       "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Recipient:   "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			DestChainID: 42,
			Amount:      bigAmount,
			VaultIsZero: false,
			Nonce:       1,
		},
		{
			Name:        "sol_compatible_uint256_max",
			NetworkID:   1,
			SourceChain: rightAlignedID(1),
			Token:       "0xcccccccccccccccccccccccccccccccccccccccc",
			Recipient:   "0xdddddddddddddddddddddddddddddddddddddddd",
			DestChainID: 96369,
			Amount:      maxAmount,
			VaultIsZero: false,
			Nonce:       18446744073709551615, // uint64 max
		},
		{
			Name:        "sol_compatible_one_wei",
			NetworkID:   3,
			SourceChain: rightAlignedID(3),
			Token:       "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			Recipient:   "0xffffffffffffffffffffffffffffffffffffffff",
			DestChainID: 7,
			Amount:      big.NewInt(1),
			VaultIsZero: true,
			Nonce:       99,
		},
		// Payload-only fixtures: arbitrary 32-byte source chain IDs.
		// These exercise the RLP payload encoder; the Solidity
		// round-trip skips them at the unsignedMessage and hash
		// layer (no way to express a 32-byte source id through the
		// uint64 surface).
		{
			Name:        "payload_only_repeated_ab",
			NetworkID:   96369,
			SourceChain: "0x" + hex.EncodeToString(fillRepeated(0xab)),
			Token:       "0x1111111111111111111111111111111111111111",
			Recipient:   "0x2222222222222222222222222222222222222222",
			DestChainID: 1,
			Amount:      smallAmount,
			VaultIsZero: true,
			Nonce:       0,
		},
	}

	fixtures := make([]Fixture, 0, len(cases))
	for _, c := range cases {
		f, err := emit(c.Name, c.NetworkID, c.SourceChain, c.Token, c.Recipient, c.DestChainID, c.Amount, c.VaultIsZero, c.Nonce)
		if err != nil {
			fmt.Fprintf(os.Stderr, "emit %s: %v\n", c.Name, err)
			os.Exit(1)
		}
		fixtures = append(fixtures, f)
	}

	b, err := json.MarshalIndent(fixtures, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if out == "" {
		fmt.Println(string(b))
		return
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func fillRepeated(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
