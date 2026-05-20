// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package teleport defines the canonical wire payload carried inside a
// Warp 2.0 UnsignedMessage for the Teleport bridge.
//
// The Teleport bridge attaches all destination-side intent (token,
// amount, recipient, vault/burn-and-mint flag, nonce, version) into a
// single RLP-encoded blob. That blob becomes the [Payload] field of
// the canonical [warp.UnsignedMessage]; the v1 message wire ID — and
// therefore [warp.EnvelopeV2.ID] — is the sha256 of the RLP encoding
// of [NetworkID, SourceChainID, payload].
//
// The on-chain BridgeV2 contract recomputes this same hash from
// (NetworkID, SourceChainID, TeleportPayload) and binds the envelope's
// signed root to its local view of the transfer. Validators sign one
// hash, the contract verifies the same hash — there is exactly one
// canonical preimage.
//
// Wire layout (RLP):
//
//	UnsignedMessage = rlp([
//	    NetworkID     uint32,
//	    SourceChainID [32]byte,
//	    Payload       []byte,        // = TeleportPayload.MarshalRLP()
//	])
//
//	TeleportPayload = rlp([
//	    Version      uint8,           // TeleportBindingVersion (3)
//	    DestChainID  uint64,
//	    Token        [20]byte,
//	    Amount       *big.Int (uint256),
//	    Recipient    [20]byte,
//	    VaultIsZero  bool,            // true ⇔ burn-and-mint (no vault)
//	    Nonce        uint64,
//	])
//
//	messageHash = sha256(UnsignedMessage)
//
// VaultIsZero is the negation of the "vault" boolean on the Solidity
// surface: the burn path sets vault=true to lock tokens in a vault on
// the source chain (the destination releases from a vault), and
// vault=false to burn-and-mint. We carry the negation so that the
// no-vault-required case is the false (RLP empty-string) wire form;
// this keeps the most common path encoding-stable across releases.
//
// See WARP2_BRIDGE.md §3 in lux/teleport for the contract-side
// description and BridgeV2.sol for the matching Solidity decoder.
package teleport

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/rlp"
	"github.com/luxfi/ids"
)

// TeleportBindingVersion is the value carried in TeleportPayload.Version
// for the pure post-quantum (v3) Teleport binding. v1 was the EIP-712
// ECDSA oracle; v2 was the hybrid BLS Beam + optional ML-DSA cert set;
// v3 is the ML-DSA-only binding. The on-chain BridgeV2 contract pins
// the constant in TELEPORT_BINDING_VERSION; the value MUST match here.
const TeleportBindingVersion uint8 = 3

// MaxAmountBytes is the maximum byte length of the RLP-encoded amount.
// uint256 stripped of leading zeros is at most 32 bytes; we refuse
// anything larger to bound decoder work and match the Solidity uint256.
const MaxAmountBytes = 32

// Errors specific to the Teleport payload codec.
var (
	// ErrInvalidPayload is returned when a payload fails structural
	// validation (wrong version, amount overflow, addresses, etc.).
	ErrInvalidPayload = errors.New("invalid teleport payload")

	// ErrAmountTooLarge is returned when the payload's Amount exceeds
	// uint256.
	ErrAmountTooLarge = errors.New("teleport payload amount exceeds uint256")

	// ErrNegativeAmount is returned when the payload's Amount is
	// negative. *big.Int is signed; on the Teleport surface only
	// non-negative amounts are valid.
	ErrNegativeAmount = errors.New("teleport payload amount is negative")
)

// TeleportPayload is the canonical Teleport binding carried in the
// payload field of a Warp 2.0 UnsignedMessage. Encoded as a fixed
// 7-element RLP list with the layout documented in the package doc.
type TeleportPayload struct {
	// Version is the Teleport binding version. MUST equal
	// TeleportBindingVersion under the v3 binding; older values are
	// rejected.
	Version uint8

	// DestChainID is the destination-chain primary-network ID the
	// claim must execute against. Must be non-zero on the wire.
	DestChainID uint64

	// Token is the 20-byte destination-chain token address that the
	// claim will mint (or release from a vault).
	Token common.Address

	// Amount is the transfer amount in token base units, bounded to
	// uint256 (32 bytes). RLP encodes this as the canonical
	// big-endian byte string with no leading zeros.
	Amount *big.Int

	// Recipient is the 20-byte destination-chain account that
	// receives the mint or vault release.
	Recipient common.Address

	// VaultIsZero is true iff the source-side path was burn-and-mint
	// (no vault). It is the negation of the Solidity "vault" boolean
	// — see the package doc for the rationale.
	VaultIsZero bool

	// Nonce is the source-chain burn nonce. Together with
	// (SourceChainID, DestChainID, Token, Amount, Recipient,
	// VaultIsZero) it uniquely identifies a single transfer.
	Nonce uint64
}

// rlpAmount returns the canonical big-endian byte string for Amount,
// suitable for embedding in an RLP list element. RLP serialises an
// integer as its big-endian byte string with leading zero bytes
// stripped; zero is encoded as the empty byte string.
//
// This helper exists so the Solidity counterpart can mirror it
// byte-for-byte: in Solidity we strip leading zero bytes of the
// uint256 the same way before RLP-prefixing.
func (p *TeleportPayload) rlpAmount() ([]byte, error) {
	if p.Amount == nil {
		return []byte{}, nil
	}
	if p.Amount.Sign() < 0 {
		return nil, ErrNegativeAmount
	}
	b := p.Amount.Bytes() // big-endian, no leading zeros
	if len(b) > MaxAmountBytes {
		return nil, ErrAmountTooLarge
	}
	return b, nil
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

// MarshalRLP returns the RLP encoding of the payload as a 7-element
// list. This is the byte sequence that goes into the
// UnsignedMessage.Payload field.
//
// Encoding the *big.Int via its canonical byte string (rather than
// letting geth's RLP encode the *big.Int interface) gives us a stable
// representation that matches what Solidity computes when it strips
// leading zeros from the uint256.
func (p *TeleportPayload) MarshalRLP() ([]byte, error) {
	if err := p.Verify(); err != nil {
		return nil, err
	}
	amount, err := p.rlpAmount()
	if err != nil {
		return nil, err
	}
	return rlp.EncodeToBytes([]interface{}{
		p.Version,
		p.DestChainID,
		p.Token.Bytes(),
		amount,
		p.Recipient.Bytes(),
		p.VaultIsZero,
		p.Nonce,
	})
}

// UnmarshalRLP decodes a payload from its canonical RLP form.
func (p *TeleportPayload) UnmarshalRLP(b []byte) error {
	var raw struct {
		Version     uint8
		DestChainID uint64
		Token       []byte
		Amount      []byte
		Recipient   []byte
		VaultIsZero bool
		Nonce       uint64
	}
	if err := rlp.DecodeBytes(b, &raw); err != nil {
		return fmt.Errorf("%w: decode: %v", ErrInvalidPayload, err)
	}
	if len(raw.Token) != common.AddressLength {
		return fmt.Errorf("%w: token len=%d (want %d)", ErrInvalidPayload, len(raw.Token), common.AddressLength)
	}
	if len(raw.Recipient) != common.AddressLength {
		return fmt.Errorf("%w: recipient len=%d (want %d)", ErrInvalidPayload, len(raw.Recipient), common.AddressLength)
	}
	if len(raw.Amount) > MaxAmountBytes {
		return ErrAmountTooLarge
	}
	p.Version = raw.Version
	p.DestChainID = raw.DestChainID
	p.Token = common.BytesToAddress(raw.Token)
	p.Amount = new(big.Int).SetBytes(raw.Amount)
	p.Recipient = common.BytesToAddress(raw.Recipient)
	p.VaultIsZero = raw.VaultIsZero
	p.Nonce = raw.Nonce
	return p.Verify()
}

// ComputeMessageHash returns the canonical Teleport message hash that
// validators sign and BridgeV2 verifies. It is identical to
// EnvelopeV2.ID() when the envelope's UnsignedMessage carries the same
// (networkID, sourceChainID, payload) tuple.
//
//	messageHash = sha256(rlp([networkID, sourceChainID, payload]))
//
// where `payload = TeleportPayload.MarshalRLP()`.
func ComputeMessageHash(networkID uint32, sourceChainID ids.ID, payload *TeleportPayload) ([32]byte, error) {
	if payload == nil {
		return [32]byte{}, ErrInvalidPayload
	}
	body, err := payload.MarshalRLP()
	if err != nil {
		return [32]byte{}, err
	}
	return computeMessageHashFromPayload(networkID, sourceChainID, body), nil
}

// ComputeMessageHashFromPayload returns the canonical Teleport message
// hash given the already-encoded payload bytes. Use this when the
// caller already has the RLP-encoded payload in hand (e.g. on the
// signing path).
func ComputeMessageHashFromPayload(networkID uint32, sourceChainID ids.ID, payload []byte) [32]byte {
	return computeMessageHashFromPayload(networkID, sourceChainID, payload)
}

func computeMessageHashFromPayload(networkID uint32, sourceChainID ids.ID, payload []byte) [32]byte {
	unsigned, _ := rlp.EncodeToBytes([]interface{}{
		networkID,
		sourceChainID[:],
		payload,
	})
	return sha256.Sum256(unsigned)
}

// EncodeUnsignedMessage returns the RLP-encoded UnsignedMessage tuple
// that is the preimage of the message hash. Useful for cross-language
// fixtures.
func EncodeUnsignedMessage(networkID uint32, sourceChainID ids.ID, payload []byte) ([]byte, error) {
	return rlp.EncodeToBytes([]interface{}{
		networkID,
		sourceChainID[:],
		payload,
	})
}
