// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"errors"

	"github.com/luxfi/ids"
	"golang.org/x/crypto/sha3"
)

// codec.go — the Warp ZAP profile: the domain-specific constants and
// signing-domain construction layered on top of the generic canonical
// TLV mechanism in zap.go. There is exactly ONE codec (ZAP) and exactly
// ONE signing digest (D). No RLP, no codec version, no type registry.

// Kind discriminators. zapKindMessage is the first byte of a Message
// c14n stream; kindEnvelope is the envelope kind byte that follows the
// wire magic. They are distinct so a Message can never be mistaken for
// a full envelope and vice-versa.
const (
	zapKindMessage byte = 0x01
	kindEnvelope   byte = 0x02
)

// Size limits. MaxMessageSize bounds a Message's canonical encoding;
// MaxEnvelopeSize bounds the full envelope (message + Beam + the two PQ
// lanes). Both are hard ceilings checked at the decode boundary.
const (
	// MaxMessageSize is the maximum canonical Message size.
	MaxMessageSize = 256 * KiB

	// MaxEnvelopeSize is the maximum Envelope wire size. Bounded at
	// 4×MaxMessageSize to leave room for the Pulse (~33 KB) and the
	// ML-DSA cert set alongside the message and Beam.
	MaxEnvelopeSize = 4 * MaxMessageSize
)

// Cross-cutting errors. Envelope-shape errors live in envelope.go.
var (
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrInvalidMessage     = errors.New("invalid message")
	ErrUnknownValidator   = errors.New("unknown validator")
	ErrInsufficientWeight = errors.New("insufficient weight")
)

// Domain-separation tags. D = keccak256(messageDST ‖ zap_c14n(Message))
// is the single signed digest (the "Prism" transcript): message ID,
// replay key, and on-chain messageHash all at once. Each lane signs the
// SAME D under its OWN tag, so a signature in one lane can never be
// replayed into another (BLS objects vs lattice objects are already
// non-interchangeable; the distinct tags close the door regardless).
const (
	messageDST = "LUX-WARP-ZAP-CORE-v1"
	beamDST    = "LUX-WARP-ZAP-BEAM-v1"
	pulseDST   = "LUX-WARP-ZAP-PULSE-v1"
	mldsaDST   = "LUX-WARP-ZAP-MLDSA-v1"
)

// keccak256 is Ethereum's keccak256 — golang.org/x/crypto/sha3
// NewLegacyKeccak256 (Keccak padding 0x01), NOT NIST SHA3 (pad 0x06) and
// NOT crypto/sha256. The on-chain keccak256 opcode computes exactly this,
// so the digest D matches byte-for-byte between Go and Solidity.
func keccak256(parts ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// BeamSigningBytes returns the exact bytes the BLS Beam lane signs and
// verifies: beamDST ‖ D. The Beam now authenticates the full Message
// (including PQ lineage) rather than only the unsigned message body.
func BeamSigningBytes(d ids.ID) []byte { return append([]byte(beamDST), d[:]...) }

// PulseSigningBytes returns the exact bytes the Pulsar Pulse lane signs
// and verifies: pulseDST ‖ D.
func PulseSigningBytes(d ids.ID) []byte { return append([]byte(pulseDST), d[:]...) }

// MLDSASigningBytes returns the exact bytes the ML-DSA cert-set lane signs
// and verifies: mldsaDST ‖ D.
func MLDSASigningBytes(d ids.ID) []byte { return append([]byte(mldsaDST), d[:]...) }
