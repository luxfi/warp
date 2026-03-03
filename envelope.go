// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/luxfi/geth/rlp"
)

// Envelope versions on the wire. The first byte of any
// envelope-encoded warp message identifies the version. Warp 1.x
// messages have NO leading version byte and are decoded directly via
// ParseMessage / Codec.Unmarshal — the dispatcher in ParseEnvelope
// recognises them as the implicit "v1" envelope.
const (
	// EnvelopeVersion1 is the implicit Warp 1.x envelope: a v1 Message
	// (UnsignedMessage + BitSetSignature) with NO leading version byte.
	// Warp 1.x verifiers see only this format on the wire and decode it
	// straight from Codec.Unmarshal. Receivers that accept either v1 or
	// v2 dispatch via ParseEnvelope, which detects v2's leading
	// version byte and falls back to v1 parsing otherwise.
	EnvelopeVersion1 = 0x01

	// EnvelopeVersion2 is the Warp 2.0 envelope: a leading 0x02 byte
	// followed by an RLP-encoded EnvelopeV2 record carrying the v1
	// message plus the Pulse / ML-DSA cert set / Pulsar lineage fields
	// pinned in LP-105 §"Warp evolution".
	EnvelopeVersion2 = 0x02

	// MaxEnvelopeV2Size is the upper bound on a serialised Warp 2.0
	// envelope including the version byte. Bounded conservatively at
	// 4×MaxMessageSize to leave room for the optional Pulse and MLDSA
	// cert-set bytes alongside the v1 message.
	MaxEnvelopeV2Size = 4 * MaxMessageSize
)

// Errors specific to the envelope dispatcher.
var (
	// ErrUnknownEnvelopeVersion is returned when the dispatcher sees a
	// leading version byte it does not understand.
	ErrUnknownEnvelopeVersion = errors.New("unknown warp envelope version")

	// ErrEnvelopeTooLarge is returned when a serialised v2 envelope
	// exceeds MaxEnvelopeV2Size.
	ErrEnvelopeTooLarge = errors.New("warp envelope exceeds maximum size")

	// ErrEnvelopeEmpty is returned when ParseEnvelope is called on
	// zero bytes.
	ErrEnvelopeEmpty = errors.New("warp envelope is empty")

	// ErrEnvelopeMissingMessage is returned when an EnvelopeV2 lacks
	// the embedded v1 Message (Beam component).
	ErrEnvelopeMissingMessage = errors.New("warp envelope missing v1 message")

	// ErrEnvelopeBadSuiteID is returned when an EnvelopeV2's
	// HashSuiteID is non-empty but does not match the configured
	// HashSuite of the verifier.
	ErrEnvelopeBadSuiteID = errors.New("warp envelope hash-suite mismatch")
)

// EnvelopeV2 is the Warp 2.0 wire envelope. It carries a v1 Message
// (so the Beam / BLS aggregate path remains unchanged) plus four
// transcript-binding fields and two optional PQ lanes (Pulse and the
// ML-DSA cert set) pinned in LP-105 §"Warp evolution".
//
// Wire layout, RLP-encoded after the leading EnvelopeVersion2 byte:
//
//	[
//	    Message,                     // v1 Beam (UnsignedMessage + BitSetSignature)
//	    SourceNebulaRoot   [32]byte, // Pulsar transcript anchor (LP-105)
//	    SourceKeyEraID     uint64,   // Pulsar lineage
//	    SourceGeneration   uint64,   // Pulsar lineage
//	    HashSuiteID        string,   // e.g. "Pulsar-SHA3"; "" defaults
//	    PulsarPulse        []byte,   // optional; Pulsar threshold sig bytes
//	    MLDSACertSet       []byte,   // optional; ML-DSA attestation bytes
//	]
//
// All fields after Message are unconditionally present in the RLP list;
// the optional PQ lanes are signalled by zero-length byte slices when
// absent. This keeps cross-version decoding unambiguous: the field
// count is fixed, and a verifier only needs to inspect the lengths.
//
// Backward compatibility: a Warp 1.x receiver that calls
// ParseEnvelope/ParseMessage directly on the v2 wire bytes will reject
// the stream because the leading 0x02 byte is not the start of a valid
// RLP list-of-Message; that's the correct refusal — the v1 verifier
// cannot validate v2 transcript binding. Senders that need to support
// v1-only verifiers MUST emit Warp 1.x bytes (call Message.Bytes()) on
// the v1 channel; the same UnsignedMessage may be embedded in a v2
// envelope on the v2 channel without re-signing the Beam.
//
// Forward compatibility: a Warp 2.0 receiver decoding Warp 1.x bytes
// uses ParseEnvelope, which falls back to ParseMessage when no v2
// version byte is present. The result is a Warp 2.0 envelope with
// only the Beam lane populated and all v2 fields zero-valued.
type EnvelopeV2 struct {
	// Message is the v1 Beam: an UnsignedMessage plus BitSetSignature.
	// Warp 2.0 keeps this byte-equal to the Warp 1.x format so a
	// validator's BLS aggregate signature lives unchanged inside the
	// envelope.
	Message *Message `serialize:"true"`

	// SourceNebulaRoot is the source-chain Nebula root (LP-105) the
	// Pulsar transcript binds to. Zero-valued for messages that do not
	// commit to a specific source-chain DAG state.
	SourceNebulaRoot [32]byte `serialize:"true"`

	// SourceKeyEraID is the Pulsar group-key lineage ID for the source
	// chain at the time of signing. Bumps only at Reanchor.
	SourceKeyEraID uint64 `serialize:"true"`

	// SourceGeneration is the LSS resharing generation ID for the
	// source chain at the time of signing. Bumps every Refresh /
	// Reshare under the same GroupKey.
	SourceGeneration uint64 `serialize:"true"`

	// HashSuiteID pins the hash profile this envelope was produced
	// under. Empty defaults to "Pulsar-SHA3" in HashSuiteOrDefault.
	HashSuiteID string `serialize:"true"`

	// PulsarPulse is the optional Pulsar threshold-signature bytes
	// over the envelope's transcript. Zero-length when absent.
	PulsarPulse []byte `serialize:"true"`

	// MLDSACertSet is the optional ML-DSA attestation set bytes for
	// the envelope's signers (or a Z-Chain Groth16 rollup of those
	// attestations). Zero-length when absent.
	MLDSACertSet []byte `serialize:"true"`
}

// DefaultHashSuiteID is the canonical hash profile for Warp 2.0
// envelopes when HashSuiteID is left empty. Matches the Pulsar default
// at github.com/luxfi/pulsar/hash.DefaultID.
const DefaultHashSuiteID = "Pulsar-SHA3"

// HashSuiteOrDefault returns the envelope's HashSuiteID, falling back
// to DefaultHashSuiteID when the field is empty.
func (e *EnvelopeV2) HashSuiteOrDefault() string {
	if e == nil || e.HashSuiteID == "" {
		return DefaultHashSuiteID
	}
	return e.HashSuiteID
}

// HasPulse reports whether the envelope carries a Pulsar pulse.
func (e *EnvelopeV2) HasPulse() bool {
	return e != nil && len(e.PulsarPulse) > 0
}

// HasMLDSACertSet reports whether the envelope carries an ML-DSA cert
// set (or its Z-Chain Groth16 rollup).
func (e *EnvelopeV2) HasMLDSACertSet() bool {
	return e != nil && len(e.MLDSACertSet) > 0
}

// Verify checks that the envelope's structural invariants hold:
// embedded v1 Message present and well-formed, optional PQ lane bytes
// bounded by MaxEnvelopeV2Size. It does NOT verify the BLS Beam, the
// Pulsar Pulse, or the ML-DSA cert set — those are independent calls
// (see VerifyV2 and pulsar/* helpers).
func (e *EnvelopeV2) Verify() error {
	if e == nil {
		return ErrInvalidMessage
	}
	if e.Message == nil {
		return ErrEnvelopeMissingMessage
	}
	if err := e.Message.Verify(); err != nil {
		return err
	}
	totalLen := len(e.PulsarPulse) + len(e.MLDSACertSet)
	if totalLen > MaxEnvelopeV2Size {
		return ErrEnvelopeTooLarge
	}
	return nil
}

// Bytes returns the wire-format serialisation of the envelope: a
// leading EnvelopeVersion2 byte followed by the RLP-encoded
// EnvelopeV2 list.
func (e *EnvelopeV2) Bytes() ([]byte, error) {
	if e == nil {
		return nil, ErrInvalidMessage
	}
	body, err := rlp.EncodeToBytes(e)
	if err != nil {
		return nil, fmt.Errorf("failed to encode envelope v2 body: %w", err)
	}
	out := make([]byte, 0, 1+len(body))
	out = append(out, EnvelopeVersion2)
	out = append(out, body...)
	if len(out) > MaxEnvelopeV2Size {
		return nil, ErrEnvelopeTooLarge
	}
	return out, nil
}

// ID returns the v1 Message ID (hash of the UnsignedMessage). v1 and
// v2 envelopes that wrap the same UnsignedMessage share an ID; this is
// deliberate so destination-chain replay protection works uniformly
// across versions.
func (e *EnvelopeV2) ID() (id [32]byte) {
	if e == nil || e.Message == nil || e.Message.UnsignedMessage == nil {
		return id
	}
	return e.Message.UnsignedMessage.ID()
}

// EncodeRLP implements rlp.Encoder for EnvelopeV2.
func (e *EnvelopeV2) EncodeRLP(w io.Writer) error {
	if e == nil {
		return ErrInvalidMessage
	}
	if e.Message == nil {
		return ErrEnvelopeMissingMessage
	}
	pulse := e.PulsarPulse
	if pulse == nil {
		pulse = []byte{}
	}
	cert := e.MLDSACertSet
	if cert == nil {
		cert = []byte{}
	}
	return rlp.Encode(w, []interface{}{
		e.Message,
		e.SourceNebulaRoot,
		e.SourceKeyEraID,
		e.SourceGeneration,
		e.HashSuiteID,
		pulse,
		cert,
	})
}

// DecodeRLP implements rlp.Decoder for EnvelopeV2.
func (e *EnvelopeV2) DecodeRLP(s *rlp.Stream) error {
	if _, err := s.List(); err != nil {
		return err
	}

	e.Message = &Message{}
	if err := s.Decode(e.Message); err != nil {
		return fmt.Errorf("failed to decode v1 message in envelope v2: %w", err)
	}
	if err := s.Decode(&e.SourceNebulaRoot); err != nil {
		return fmt.Errorf("failed to decode SourceNebulaRoot: %w", err)
	}
	if err := s.Decode(&e.SourceKeyEraID); err != nil {
		return fmt.Errorf("failed to decode SourceKeyEraID: %w", err)
	}
	if err := s.Decode(&e.SourceGeneration); err != nil {
		return fmt.Errorf("failed to decode SourceGeneration: %w", err)
	}
	if err := s.Decode(&e.HashSuiteID); err != nil {
		return fmt.Errorf("failed to decode HashSuiteID: %w", err)
	}
	if err := s.Decode(&e.PulsarPulse); err != nil {
		return fmt.Errorf("failed to decode PulsarPulse: %w", err)
	}
	if err := s.Decode(&e.MLDSACertSet); err != nil {
		return fmt.Errorf("failed to decode MLDSACertSet: %w", err)
	}
	return s.ListEnd()
}

// ParseEnvelopeV2 decodes a Warp 2.0 envelope from its wire format
// (leading version byte + RLP body). The leading byte MUST equal
// EnvelopeVersion2; otherwise ErrUnknownEnvelopeVersion is returned.
func ParseEnvelopeV2(b []byte) (*EnvelopeV2, error) {
	if len(b) == 0 {
		return nil, ErrEnvelopeEmpty
	}
	if len(b) > MaxEnvelopeV2Size {
		return nil, ErrEnvelopeTooLarge
	}
	if b[0] != EnvelopeVersion2 {
		return nil, fmt.Errorf("%w: byte=0x%02x", ErrUnknownEnvelopeVersion, b[0])
	}
	env := &EnvelopeV2{}
	if err := rlp.DecodeBytes(b[1:], env); err != nil {
		return nil, fmt.Errorf("failed to decode envelope v2: %w", err)
	}
	if err := env.Verify(); err != nil {
		return nil, err
	}
	return env, nil
}

// ParseEnvelope is the cross-version dispatcher. It accepts either:
//
//   - Warp 2.0 wire bytes (leading 0x02 + RLP envelope), or
//   - Warp 1.x wire bytes (RLP-encoded Message with no leading version),
//
// and returns a Warp 2.0 EnvelopeV2 in both cases. v1 inputs produce
// an envelope with only the Beam lane populated and all v2 fields
// zero-valued; the receiver can branch on env.HasPulse() / env.HasMLDSACertSet()
// to apply the appropriate verification policy.
//
// This is the recommended entrypoint for cross-chain receivers that
// want forward compatibility without breaking existing relayers.
func ParseEnvelope(b []byte) (*EnvelopeV2, error) {
	if len(b) == 0 {
		return nil, ErrEnvelopeEmpty
	}

	// Detect v2 by the leading version byte. RLP-encoded lists never
	// start with 0x02 — RLP single-byte values < 0x80 ARE the value
	// itself, but a Warp 1.x message is always an RLP list (starts at
	// 0xc0..0xff for short lists or 0xf7..0xff for long lists). 0x02
	// is therefore unambiguously a v2 version byte.
	if b[0] == EnvelopeVersion2 {
		return ParseEnvelopeV2(b)
	}

	// Fall back to v1: parse a bare Message and lift it into an
	// envelope shape with empty v2 fields.
	msg, err := ParseMessage(b)
	if err != nil {
		return nil, err
	}
	return &EnvelopeV2{Message: msg}, nil
}

// VerifyV1 verifies a Warp 1.x message against the source-chain
// validator set. It is exactly the v1 path — included here as a named
// entrypoint so callers that branch on envelope version have a uniform
// API surface.
func VerifyV1(
	msg *Message,
	networkID uint32,
	validatorState ValidatorState,
	quorumNum uint64,
	quorumDen uint64,
) error {
	return VerifyMessage(msg, networkID, validatorState, quorumNum, quorumDen)
}

// PulseVerifier verifies a Pulsar threshold pulse against the
// envelope's transcript-binding inputs. Implementations live in the
// warp/pulsar subpackage (so this package does not need to import the
// pulsar kernel directly — that would create an import cycle through
// the threshold orchestration framework).
type PulseVerifier interface {
	// VerifyPulse checks that the given pulse bytes are a valid Pulsar
	// threshold signature over the envelope's canonical transcript.
	// The implementation MUST bind the verification to all of:
	// SourceChainID, SourceNebulaRoot, SourceKeyEraID, SourceGeneration,
	// HashSuiteID. msgBytes is the byte stream of the envelope's
	// embedded UnsignedMessage.
	VerifyPulse(env *EnvelopeV2, msgBytes []byte) error
}

// MLDSACertSetVerifier verifies the optional ML-DSA cert-set lane.
// Implementations may verify either an ML-DSA cert set or a Z-Chain
// Groth16 rollup of one. msgBytes is the byte stream of the envelope's
// embedded UnsignedMessage.
type MLDSACertSetVerifier interface {
	VerifyCertSet(env *EnvelopeV2, msgBytes []byte) error
}

// VerifyV2Options bundles the optional verifiers a Warp 2.0 receiver
// applies to an envelope. A nil PulseVerifier means "skip the Pulsar
// lane"; a nil MLDSACertSetVerifier means "skip the ML-DSA lane".
//
// RequirePulse / RequireCertSet, when true, demand the corresponding
// lane be present AND the corresponding verifier be configured AND
// the verification succeed. When the bytes are absent and the
// requirement is true, ErrInvalidMessage is returned.
type VerifyV2Options struct {
	// Required Beam configuration (always verified).
	NetworkID      uint32
	ValidatorState ValidatorState
	QuorumNum      uint64
	QuorumDen      uint64

	// Optional PQ-lane verifiers.
	Pulse           PulseVerifier
	CertSet         MLDSACertSetVerifier
	RequirePulse    bool
	RequireCertSet  bool

	// HashSuiteID is the suite the verifier expects the envelope to
	// have been produced under. Empty means "accept whatever the
	// envelope declares" (after defaulting to DefaultHashSuiteID).
	HashSuiteID string

	// SkipBeam, when true, skips the BLS aggregate (Beam) verification.
	// Use this only when the caller has already validated the Beam
	// through a separate code path; otherwise leave it false. Tests
	// also use this to exercise the PQ-lane plumbing without setting
	// up a full validator set.
	SkipBeam bool
}

// VerifyV2 verifies a Warp 2.0 envelope under the given options:
//
//  1. Structural invariants (Verify).
//  2. Hash-suite consistency (when opts.HashSuiteID is set).
//  3. Beam lane: BLS aggregate against the source-chain validator set
//     and quorum (skipped when opts.SkipBeam is true; senders rarely
//     want this — it exists for tests and for receivers that have
//     already validated the Beam through a separate code path).
//  4. ML-DSA cert set lane (when configured / required).
//  5. Pulsar Pulse lane (when configured / required).
//
// Verification of independent lanes is independent: a verifier that
// only cares about the Beam can leave Pulse and CertSet nil (and
// Required* false) and VerifyV2 reduces to VerifyV1.
func VerifyV2(env *EnvelopeV2, opts VerifyV2Options) error {
	if err := env.Verify(); err != nil {
		return err
	}

	if opts.HashSuiteID != "" && env.HashSuiteOrDefault() != opts.HashSuiteID {
		return fmt.Errorf("%w: expected %q, got %q",
			ErrEnvelopeBadSuiteID, opts.HashSuiteID, env.HashSuiteOrDefault())
	}

	if !opts.SkipBeam {
		if err := VerifyV1(env.Message, opts.NetworkID, opts.ValidatorState, opts.QuorumNum, opts.QuorumDen); err != nil {
			return err
		}
	}

	return verifyPQLanes(env, opts)
}

// verifyPQLanes runs the optional Pulsar / ML-DSA lane verifications
// declared in opts. Split out from VerifyV2 so callers that already
// own the Beam path (e.g. existing v1 receivers) can layer in PQ-lane
// validation without re-running BLS aggregate verification.
func verifyPQLanes(env *EnvelopeV2, opts VerifyV2Options) error {
	msgBytes := env.Message.UnsignedMessage.Bytes()

	// ML-DSA cert set lane.
	if env.HasMLDSACertSet() {
		if opts.CertSet == nil {
			if opts.RequireCertSet {
				return fmt.Errorf("%w: ML-DSA cert set lane required but no verifier configured", ErrInvalidMessage)
			}
			// Lane present but no verifier — accept (caller chose to ignore).
		} else if err := opts.CertSet.VerifyCertSet(env, msgBytes); err != nil {
			return fmt.Errorf("ml-dsa cert set verify: %w", err)
		}
	} else if opts.RequireCertSet {
		return fmt.Errorf("%w: ML-DSA cert set lane required but absent from envelope", ErrInvalidMessage)
	}

	// Pulsar Pulse lane.
	if env.HasPulse() {
		if opts.Pulse == nil {
			if opts.RequirePulse {
				return fmt.Errorf("%w: Pulsar Pulse lane required but no verifier configured", ErrInvalidMessage)
			}
		} else if err := opts.Pulse.VerifyPulse(env, msgBytes); err != nil {
			return fmt.Errorf("pulsar pulse verify: %w", err)
		}
	} else if opts.RequirePulse {
		return fmt.Errorf("%w: Pulsar Pulse lane required but absent from envelope", ErrInvalidMessage)
	}

	return nil
}

// VerifyPQLanes runs only the Pulsar / ML-DSA lane verifications on
// the envelope (skipping Beam entirely). Use this when a caller has
// already verified the Beam via VerifyV1 / VerifyMessage and wants to
// layer PQ-lane checks on top without re-running BLS aggregate
// verification. opts.NetworkID / ValidatorState / QuorumNum /
// QuorumDen / SkipBeam are ignored.
func VerifyPQLanes(env *EnvelopeV2, opts VerifyV2Options) error {
	if err := env.Verify(); err != nil {
		return err
	}
	if opts.HashSuiteID != "" && env.HashSuiteOrDefault() != opts.HashSuiteID {
		return fmt.Errorf("%w: expected %q, got %q",
			ErrEnvelopeBadSuiteID, opts.HashSuiteID, env.HashSuiteOrDefault())
	}
	return verifyPQLanes(env, opts)
}

// Equal reports whether two envelopes are byte-equal under
// canonical RLP serialisation.
func (e *EnvelopeV2) Equal(other *EnvelopeV2) bool {
	if e == nil || other == nil {
		return e == other
	}
	a, errA := e.Bytes()
	b, errB := other.Bytes()
	if errA != nil || errB != nil {
		return false
	}
	return bytes.Equal(a, b)
}
