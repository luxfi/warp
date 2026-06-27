// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package teleport defines the canonical wire payload carried inside a
// Warp Message for the Teleport bridge.
//
// The Teleport bridge packs all destination-side intent (version, token,
// amount, recipient, vault/burn-and-mint flag, nonce, dest chain) into a
// single FIXED 90-byte block. That block becomes the [Payload] field of
// a [warp.Message]; the message ID — D — is the keccak256 digest of
// the canonical Message (see [warp.Message.ID]).
//
// Fixed teleport payload layout (90 bytes, big-endian, no length prefixes):
//
//	off  size  field
//	  0     1  Version      uint8   (== TeleportBindingVersion, 3)
//	  1     8  DestChainID  uint64  big-endian
//	  9    20  Token        address (20 bytes)
//	 29    32  Amount       uint256 (FULL 32 bytes, no leading-zero strip)
//	 61    20  Recipient    address (20 bytes)
//	 81     1  VaultIsZero  bool    (0x00 / 0x01 only)
//	 82     8  Nonce        uint64  big-endian
//	      ----
//	       90
//
// Amount is the FULL 32-byte big-endian uint256 — left-zero-padded, never
// stripped — so Solidity rebuilds it with bytes32(amount) directly.
//
// VaultIsZero is the negation of the Solidity "vault" boolean: burn-and-mint
// (no vault) is the true/0x01 wire form.
//
// HARD-FORK LOCKSTEP: ComputeMessageHash returns D, the SAME digest the
// on-chain BridgeV2 MUST recompute (see lux/teleport, BridgeV2.sol). The
// Solidity side is a SEPARATE coordinated deploy; it MUST rebuild the
// canonical Message preimage and keccak256 it identically per §4.2:
//
//	core_c14n =
//	    0x01                                 // zapKindMessage
//	  ‖ uint32_be(networkID)
//	  ‖ sourceChainID                        // 32 bytes
//	  ‖ bytes32(0)                           // SourceNebulaRoot — zero for teleport
//	  ‖ uint64_be(0)                         // SourceKeyEraID   — zero for teleport
//	  ‖ uint64_be(0)                         // SourceGeneration — zero for teleport
//	  ‖ uint32_be(11) ‖ "Pulsar-SHA3"        // HashSuiteID (MessageHashProfileTag, pinned)
//	  ‖ uint32_be(90) ‖ teleportPayload[90]  // Payload
//	D = keccak256("LUX-WARP-ZAP-CORE-v1" ‖ core_c14n)
//
// The previous sha256(rlp(...)) preimage and the abi.encode 7-tuple are
// BOTH gone; there is exactly one preimage and one keccak256 digest on
// both sides. A teleport Message therefore uses zero PQ lineage and
// the default hash suite — the off-chain relayer that signs the envelope
// MUST construct the Message with these same fields (it is the same
// message ComputeMessageHash builds), so validators sign the same D the
// contract verifies.
package teleport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
)

// TeleportBindingVersion is the value carried in TeleportPayload.Version
// for the pure post-quantum (v3) Teleport binding. v1 was the EIP-712
// ECDSA oracle; v2 was the hybrid BLS Beam + optional ML-DSA cert set;
// v3 is the ML-DSA-capable binding under the ZAP codec. The on-chain
// BridgeV2 contract pins the constant in TELEPORT_BINDING_VERSION; the
// value MUST match here.
const TeleportBindingVersion uint8 = 3

// PayloadSize is the fixed wire length of a Teleport payload block.
const PayloadSize = 1 + 8 + common.AddressLength + 32 + common.AddressLength + 1 + 8 // 90

// MaxAmountBytes is the maximum significant byte length of Amount. uint256
// is at most 32 bytes; anything larger is refused.
const MaxAmountBytes = 32

// Errors specific to the Teleport payload codec.
var (
	// ErrInvalidPayload is returned when a payload fails structural
	// validation (wrong version, amount overflow, length, vault byte).
	ErrInvalidPayload = errors.New("invalid teleport payload")

	// ErrAmountTooLarge is returned when Amount exceeds uint256.
	ErrAmountTooLarge = errors.New("teleport payload amount exceeds uint256")

	// ErrNegativeAmount is returned when Amount is negative. *big.Int is
	// signed; on the Teleport surface only non-negative amounts are valid.
	ErrNegativeAmount = errors.New("teleport payload amount is negative")
)

// TeleportPayload is the canonical Teleport binding carried in the payload
// field of a Warp Message. Encoded as the fixed 90-byte block above.
type TeleportPayload struct {
	// Version is the Teleport binding version. MUST equal
	// TeleportBindingVersion; older values are rejected.
	Version uint8

	// DestChainID is the destination-chain primary-network ID the claim
	// must execute against. Must be non-zero on the wire.
	DestChainID uint64

	// Token is the 20-byte destination-chain token address that the claim
	// will mint (or release from a vault).
	Token common.Address

	// Amount is the transfer amount in token base units, bounded to
	// uint256. Encoded as the FULL 32-byte big-endian value.
	Amount *big.Int

	// Recipient is the 20-byte destination-chain account that receives the
	// mint or vault release.
	Recipient common.Address

	// VaultIsZero is true iff the source-side path was burn-and-mint (no
	// vault). It is the negation of the Solidity "vault" boolean.
	VaultIsZero bool

	// Nonce is the source-chain burn nonce.
	Nonce uint64
}

// Verify checks the structural invariants of the payload.
func (p *TeleportPayload) Verify() error {
	if p == nil {
		return ErrInvalidPayload
	}
	if p.Version != TeleportBindingVersion {
		return fmt.Errorf("%w: version=%d (want %d)", ErrInvalidPayload, p.Version, TeleportBindingVersion)
	}
	if p.DestChainID == 0 {
		return fmt.Errorf("%w: destChainID=0", ErrInvalidPayload)
	}
	if p.Amount == nil {
		return fmt.Errorf("%w: amount=nil", ErrInvalidPayload)
	}
	if p.Amount.Sign() < 0 {
		return ErrNegativeAmount
	}
	if len(p.Amount.Bytes()) > MaxAmountBytes {
		return ErrAmountTooLarge
	}
	return nil
}

// MarshalBinary returns the fixed 90-byte canonical encoding of the
// payload. This is the byte sequence that goes into Message.Payload.
func (p *TeleportPayload) MarshalBinary() ([]byte, error) {
	if err := p.Verify(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, PayloadSize)
	out = append(out, p.Version)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], p.DestChainID)
	out = append(out, u64[:]...)
	out = append(out, p.Token.Bytes()...) // 20
	// FULL 32-byte big-endian amount — left-zero-padded, never stripped.
	var amount [32]byte
	p.Amount.FillBytes(amount[:]) // safe: Verify bounded Amount to <= 32 bytes
	out = append(out, amount[:]...)
	out = append(out, p.Recipient.Bytes()...) // 20
	if p.VaultIsZero {
		out = append(out, 0x01)
	} else {
		out = append(out, 0x00)
	}
	binary.BigEndian.PutUint64(u64[:], p.Nonce)
	out = append(out, u64[:]...)
	return out, nil
}

// UnmarshalBinary decodes a payload from its fixed 90-byte form, rejecting
// any other length and a vault byte outside {0x00,0x01}.
func (p *TeleportPayload) UnmarshalBinary(b []byte) error {
	if len(b) != PayloadSize {
		return fmt.Errorf("%w: payload len=%d (want %d)", ErrInvalidPayload, len(b), PayloadSize)
	}
	off := 0
	p.Version = b[off]
	off++
	p.DestChainID = binary.BigEndian.Uint64(b[off : off+8])
	off += 8
	p.Token = common.BytesToAddress(b[off : off+common.AddressLength])
	off += common.AddressLength
	p.Amount = new(big.Int).SetBytes(b[off : off+32])
	off += 32
	p.Recipient = common.BytesToAddress(b[off : off+common.AddressLength])
	off += common.AddressLength
	switch b[off] {
	case 0x00:
		p.VaultIsZero = false
	case 0x01:
		p.VaultIsZero = true
	default:
		return fmt.Errorf("%w: vaultIsZero byte 0x%02x", ErrInvalidPayload, b[off])
	}
	off++
	p.Nonce = binary.BigEndian.Uint64(b[off : off+8])
	return p.Verify()
}

// ComputeMessageHash returns D, the canonical Teleport message hash that
// validators sign and BridgeV2 verifies. It is byte-equal to
// warp.Message.ID() for a message whose Payload is this payload's 90-byte
// block, NetworkID/SourceChainID are these arguments, PQ lineage is zero,
// and HashSuiteID is the default — i.e. exactly what NewMessage builds.
func ComputeMessageHash(networkID uint32, sourceChainID ids.ID, payload *TeleportPayload) ([32]byte, error) {
	if payload == nil {
		return [32]byte{}, ErrInvalidPayload
	}
	body, err := payload.MarshalBinary()
	if err != nil {
		return [32]byte{}, err
	}
	return ComputeMessageHashFromPayload(networkID, sourceChainID, body)
}

// ComputeMessageHashFromPayload returns D given an already-encoded 90-byte
// payload. Use this on the signing path when the payload bytes are in hand.
func ComputeMessageHashFromPayload(networkID uint32, sourceChainID ids.ID, payload []byte) ([32]byte, error) {
	message, err := warp.NewMessage(networkID, sourceChainID, payload)
	if err != nil {
		return [32]byte{}, err
	}
	return [32]byte(message.ID()), nil
}
