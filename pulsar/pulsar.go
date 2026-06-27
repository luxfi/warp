// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pulsar wires Warp 2.0 envelopes to the Pulsar lattice
// threshold-signature kernel. It is the interface the warp root
// package's PulseVerifier callback satisfies.
//
// Why a subpackage. The root warp package MUST NOT import the Pulsar
// kernel directly: doing so would create an import cycle through the
// threshold orchestration framework (warp →
// threshold/protocols/lss/lss_pulsar → warp via signature plumbing).
// Splitting the Pulse path into a subpackage lets the root warp
// package depend only on the small PulseVerifier interface, while the
// concrete kernel-driven verifier lives here.
//
// Architecture:
//
//	warp                      (root pkg; no Pulsar import)
//	  ├── Envelope        (the single envelope type)
//	  ├── PulseVerifier       (interface)
//	  └── VerifyWithOptions / VerifyPQLanes
//
//	warp/pulsar (this pkg; imports github.com/luxfi/pulsar)
//	  ├── KernelVerifier      (PulseVerifier impl; Pulse over PulseSigningBytes(D))
//	  └── HorizonCertificate  (LP-105 §"HorizonCertificate" helper)
//
// The KernelVerifier accepts a function that pulls a (GroupKey,
// HashSuiteID) tuple from a (KeyEraID, Generation) pair — typically
// supplied by the destination chain's source-chain key registry. The
// kernel's Verify is then invoked over the canonical signing bytes.
//
// LP-105 §"Warp evolution" is the normative spec; this package is the
// production wiring.
package pulsar

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/warp"

	"github.com/luxfi/corona/hash"
	corona "github.com/luxfi/corona/threshold"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/buffer"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// Errors returned by the Warp Pulse path.
var (
	// ErrPulseAbsent is returned when a verifier is asked to verify a
	// Pulse that the envelope does not carry.
	ErrPulseAbsent = errors.New("warp pulsar: envelope has no Pulse to verify")

	// ErrGroupKeyResolverFailed is returned when the GroupKeyResolver
	// could not produce a key for the envelope's (KeyEraID, Generation).
	ErrGroupKeyResolverFailed = errors.New("warp pulsar: group-key resolver failed")

	// ErrPulseVerifyFailed is returned when the Pulsar kernel rejects
	// the threshold signature.
	ErrPulseVerifyFailed = errors.New("warp pulsar: kernel rejected pulse")

	// ErrSuiteMismatch is returned when the envelope's HashSuiteID does
	// not match the resolver-supplied HashSuite.
	ErrSuiteMismatch = errors.New("warp pulsar: hash-suite mismatch")
)

// GroupKeyResolver maps a (sourceChainID, keyEraID, generation) tuple
// to the Pulsar GroupKey + HashSuite identifier the source chain was
// using when the envelope was signed. Destination chains implement
// this against their source-chain key registry — a contract that
// records the source's GroupKey lineage as it evolves through
// Bootstrap, Reshare, and Reanchor events.
//
// Returning a zero-pointer GroupKey or empty suiteID is treated as
// ErrGroupKeyResolverFailed.
type GroupKeyResolver interface {
	ResolveGroupKey(
		sourceChainID [32]byte,
		keyEraID uint64,
		generation uint64,
	) (gk *corona.GroupKey, suiteID string, err error)
}

// KernelVerifier is the production PulseVerifier. It uses a
// GroupKeyResolver to fetch the source-chain Pulsar GroupKey, builds
// the canonical signing bytes via BuildSigningBytes, and verifies the
// envelope's Pulse against the kernel's pulsar.Verify.
type KernelVerifier struct {
	Resolver GroupKeyResolver
}

// NewKernelVerifier returns a Pulse verifier backed by the given
// resolver.
func NewKernelVerifier(r GroupKeyResolver) *KernelVerifier {
	return &KernelVerifier{Resolver: r}
}

// VerifyPulse implements warp.PulseVerifier.
//
// The verification chain:
//
//  1. Envelope must carry a non-empty Pulse.
//  2. Resolve the source-chain GroupKey for (KeyEraID, Generation).
//  3. Confirm the resolver-supplied suiteID matches the envelope's
//     resolved HashSuiteID.
//  4. Recompute D from the envelope's Message and build the Pulse
//     signing bytes warp.PulseSigningBytes(D) = "LUX-WARP-ZAP-PULSE-v1"‖D.
//  5. Deserialize the envelope's PulseSig into a corona.Signature.
//  6. Call corona.Verify(gk, signingBytes, sig).
//
// D folds in SourceNebulaRoot / SourceKeyEraID / SourceGeneration /
// HashSuiteID / SourceChainID / NetworkID / Payload, so verifying the
// Pulse over PulseSigningBytes(D) binds the Pulse to every one of them.
func (v *KernelVerifier) VerifyPulse(env *warp.Envelope) error {
	if env == nil || !env.HasPulse() {
		return ErrPulseAbsent
	}
	if v == nil || v.Resolver == nil {
		return fmt.Errorf("%w: nil resolver", ErrGroupKeyResolverFailed)
	}

	src := env.Message.SourceChainID

	gk, suiteID, err := v.Resolver.ResolveGroupKey(src, env.Message.SourceKeyEraID, env.Message.SourceGeneration)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGroupKeyResolverFailed, err)
	}
	if gk == nil {
		return fmt.Errorf("%w: nil GroupKey", ErrGroupKeyResolverFailed)
	}
	if suiteID == "" {
		suiteID = hash.DefaultID
	}
	if env.Message.HashSuiteOrDefault() != suiteID {
		return fmt.Errorf("%w: envelope=%q resolver=%q",
			ErrSuiteMismatch, env.Message.HashSuiteOrDefault(), suiteID)
	}

	signing := warp.PulseSigningBytes(env.Message.ID())

	sig, err := DeserializePulse(env.PulseSig)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPulseVerifyFailed, err)
	}

	if !corona.Verify(gk, string(signing), sig) {
		return ErrPulseVerifyFailed
	}
	return nil
}

// SerializePulse returns the byte stream the envelope's Pulse
// field carries for a given pulsar threshold signature. The wire
// format wraps the kernel's canonical Vector/Matrix WriteTo stream
// (LP-073 §"Wire Format") in three length-prefixed frames:
//
//	uint32 LE        len(C_bytes)
//	C_bytes:         ring.Poly.WriteTo
//	uint32 LE        len(Z_bytes)
//	Z_bytes:         structs.Vector[ring.Poly].WriteTo
//	uint32 LE        len(Delta_bytes)
//	Delta_bytes:     structs.Vector[ring.Poly].WriteTo
//
// Each component carries its own 4-byte little-endian length prefix
// so deserialisation can dispatch each into a fresh, slice-backed
// buffer.NewBuffer (the recommended lattigo path for slice-backed
// reads). Total length grows by 12 bytes versus a raw concatenation
// — negligible relative to the ~33 KB lattice signature.
func SerializePulse(sig *corona.Signature) ([]byte, error) {
	if sig == nil {
		return nil, errors.New("warp pulsar: nil pulse")
	}

	cBuf := buffer.NewBufferSize(sig.C.BinarySize())
	if _, err := sig.C.WriteTo(cBuf); err != nil {
		return nil, fmt.Errorf("warp pulsar: encode C: %w", err)
	}
	zBuf := buffer.NewBufferSize(sig.Z.BinarySize())
	if _, err := sig.Z.WriteTo(zBuf); err != nil {
		return nil, fmt.Errorf("warp pulsar: encode Z: %w", err)
	}
	dBuf := buffer.NewBufferSize(sig.Delta.BinarySize())
	if _, err := sig.Delta.WriteTo(dBuf); err != nil {
		return nil, fmt.Errorf("warp pulsar: encode Delta: %w", err)
	}

	cb := cBuf.Bytes()
	zb := zBuf.Bytes()
	db := dBuf.Bytes()
	out := make([]byte, 0, 12+len(cb)+len(zb)+len(db))
	out = appendLenPrefixed(out, cb)
	out = appendLenPrefixed(out, zb)
	out = appendLenPrefixed(out, db)
	return out, nil
}

// MaxPulseWireSize is the upper bound on a Warp 2.0 PulsarPulse byte
// stream. A real Pulsar lattice threshold signature is ~33 KB
// (LP-073 §"Wire Format"); we accept up to 64 KB to leave headroom
// for ring-parameter changes without admitting buffer-bomb inputs that
// could OOM or stack-overflow the lattigo deserializer on attacker-
// controlled length prefixes. Hardened in response to a fuzz finding
// against `luxfi/lattice/v7`'s `ReadUint64Slice` recursion (Mar-3).
//
// The cap is also a recursion bound: lattigo's ReadUint64Slice
// recurses by length field, so bounding the byte stream bounds the
// recursion depth. 64 KB ÷ 8 bytes/uint64 = 8192 frames worst case;
// well under Go's default 8 MB goroutine stack at 64 bytes per frame.
const MaxPulseWireSize = 64 * 1024

// MaxPulseFrameSize bounds each individual lane (C, Z, Delta) inside
// a serialized pulse. Real lanes are ≤ ~16 KB; we accept up to 32 KB.
const MaxPulseFrameSize = 32 * 1024

// MaxLatticeUintSliceLen bounds the largest uint64 slice we permit in
// a lattigo wire frame. A canonical Pulsar Poly has 256 coefficients
// per level; a Vector/Matrix has at most M*N = 8*32 = 256 polys; so
// every inner length-prefix should fit comfortably under this bound.
// A frame whose declared inner length exceeds this is a structural
// red flag and we reject it before lattigo's ReadFrom can recurse.
const MaxLatticeUintSliceLen = 4096

// validatePolyFrame walks the lattigo Poly wire format end-to-end
// and validates every length-prefix.
//
// Layout (per `ring/poly.go` Poly.WriteTo → Coeffs (Matrix[uint64]).WriteTo):
//
//	uint64 LE   levels        // matrix outer length
//	per level:
//	  uint64 LE coeff_count
//	  coeff_count × uint64 LE  // the coefficient slice
//
// luxfi/lattice/v7's `ReadUint64Slice` recurses on the declared
// length field without bounding by available bytes. An attacker can
// supply a frame with an inner length-prefix of 0xFFFFFFFF and only
// a few bytes of payload, triggering an unrecoverable stack overflow
// in the destination chain. This walker rejects such inputs before
// they reach lattigo.
func validatePolyFrame(frame []byte) error {
	if len(frame) < 8 {
		return fmt.Errorf("poly frame too short: %d < 8", len(frame))
	}
	levels := binary.LittleEndian.Uint64(frame[:8])
	if levels > MaxLatticeUintSliceLen {
		return fmt.Errorf("poly levels %d exceeds %d", levels, MaxLatticeUintSliceLen)
	}
	rest := frame[8:]
	for k := uint64(0); k < levels; k++ {
		if len(rest) < 8 {
			return fmt.Errorf("poly level %d: rest too short for header (%d)", k, len(rest))
		}
		coeffs := binary.LittleEndian.Uint64(rest[:8])
		rest = rest[8:]
		if coeffs > MaxLatticeUintSliceLen {
			return fmt.Errorf("poly level %d: coeff count %d exceeds %d", k, coeffs, MaxLatticeUintSliceLen)
		}
		need := coeffs * 8
		if uint64(len(rest)) < need {
			return fmt.Errorf("poly level %d: need %d coeff bytes, have %d", k, need, len(rest))
		}
		rest = rest[need:]
	}
	if len(rest) != 0 {
		return fmt.Errorf("poly frame trailing %d bytes", len(rest))
	}
	return nil
}

// validateVectorPolyFrame walks a lattigo Vector[Poly] wire format
// end-to-end (one 8-byte vector length header followed by N
// concatenated Poly frames). Same hardening posture as
// validatePolyFrame.
func validateVectorPolyFrame(frame []byte) error {
	if len(frame) < 8 {
		return fmt.Errorf("vector frame too short: %d < 8", len(frame))
	}
	n := binary.LittleEndian.Uint64(frame[:8])
	if n > MaxLatticeUintSliceLen {
		return fmt.Errorf("vector length %d exceeds %d", n, MaxLatticeUintSliceLen)
	}
	rest := frame[8:]
	for i := uint64(0); i < n; i++ {
		// Each Poly frame starts with its own 8-byte levels header,
		// then per-level (8 + 8*coeff_count). We walk inline here
		// rather than recursing into validatePolyFrame so we can
		// continue past one Poly into the next.
		if len(rest) < 8 {
			return fmt.Errorf("vector poly %d: header truncated (%d)", i, len(rest))
		}
		levels := binary.LittleEndian.Uint64(rest[:8])
		if levels > MaxLatticeUintSliceLen {
			return fmt.Errorf("vector poly %d: levels %d exceeds %d", i, levels, MaxLatticeUintSliceLen)
		}
		rest = rest[8:]
		for k := uint64(0); k < levels; k++ {
			if len(rest) < 8 {
				return fmt.Errorf("vector poly %d level %d: header truncated", i, k)
			}
			coeffs := binary.LittleEndian.Uint64(rest[:8])
			rest = rest[8:]
			if coeffs > MaxLatticeUintSliceLen {
				return fmt.Errorf("vector poly %d level %d: coeff count %d exceeds %d", i, k, coeffs, MaxLatticeUintSliceLen)
			}
			need := coeffs * 8
			if uint64(len(rest)) < need {
				return fmt.Errorf("vector poly %d level %d: need %d coeff bytes, have %d", i, k, need, len(rest))
			}
			rest = rest[need:]
		}
	}
	if len(rest) != 0 {
		return fmt.Errorf("vector frame trailing %d bytes", len(rest))
	}
	return nil
}

// DeserializePulse is the inverse of SerializePulse. It is hardened
// against attacker-controlled length prefixes and lattigo
// deserialization panics: every code path returns a clean error and
// no panic crosses the boundary.
func DeserializePulse(b []byte) (sig *corona.Signature, err error) {
	if len(b) == 0 {
		return nil, errors.New("warp pulsar: empty pulse")
	}
	if len(b) > MaxPulseWireSize {
		return nil, fmt.Errorf("warp pulsar: pulse exceeds max wire size %d > %d", len(b), MaxPulseWireSize)
	}

	// Convert any lattigo-deserialize panic into a clean error. The
	// known offender is `luxfi/lattice/v7/utils/buffer/reader.go`
	// `ReadUint64Slice` which recurses on partial-peek without
	// making progress; tracked upstream and bounded here.
	defer func() {
		if r := recover(); r != nil {
			sig = nil
			err = fmt.Errorf("warp pulsar: deserialize panic recovered: %v", r)
		}
	}()

	cBytes, rest, err := readLenPrefixed(b)
	if err != nil {
		return nil, fmt.Errorf("warp pulsar: decode C frame: %w", err)
	}
	if len(cBytes) > MaxPulseFrameSize {
		return nil, fmt.Errorf("warp pulsar: C frame exceeds %d bytes", MaxPulseFrameSize)
	}
	if err := validatePolyFrame(cBytes); err != nil {
		return nil, fmt.Errorf("warp pulsar: C frame: %w", err)
	}
	zBytes, rest, err := readLenPrefixed(rest)
	if err != nil {
		return nil, fmt.Errorf("warp pulsar: decode Z frame: %w", err)
	}
	if len(zBytes) > MaxPulseFrameSize {
		return nil, fmt.Errorf("warp pulsar: Z frame exceeds %d bytes", MaxPulseFrameSize)
	}
	if err := validateVectorPolyFrame(zBytes); err != nil {
		return nil, fmt.Errorf("warp pulsar: Z frame: %w", err)
	}
	dBytes, rest, err := readLenPrefixed(rest)
	if err != nil {
		return nil, fmt.Errorf("warp pulsar: decode Delta frame: %w", err)
	}
	if len(dBytes) > MaxPulseFrameSize {
		return nil, fmt.Errorf("warp pulsar: Delta frame exceeds %d bytes", MaxPulseFrameSize)
	}
	if err := validateVectorPolyFrame(dBytes); err != nil {
		return nil, fmt.Errorf("warp pulsar: Delta frame: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("warp pulsar: %d trailing bytes after pulse", len(rest))
	}

	sig = &corona.Signature{}
	if _, err := sig.C.ReadFrom(buffer.NewBuffer(cBytes)); err != nil {
		return nil, fmt.Errorf("warp pulsar: decode C: %w", err)
	}
	var z structs.Vector[ring.Poly]
	if _, err := z.ReadFrom(buffer.NewBuffer(zBytes)); err != nil {
		return nil, fmt.Errorf("warp pulsar: decode Z: %w", err)
	}
	sig.Z = z
	var delta structs.Vector[ring.Poly]
	if _, err := delta.ReadFrom(buffer.NewBuffer(dBytes)); err != nil {
		return nil, fmt.Errorf("warp pulsar: decode Delta: %w", err)
	}
	sig.Delta = delta
	return sig, nil
}

// appendLenPrefixed appends a 4-byte little-endian length followed
// by data to dst.
func appendLenPrefixed(dst, data []byte) []byte {
	var l [4]byte
	binary.LittleEndian.PutUint32(l[:], uint32(len(data)))
	dst = append(dst, l[:]...)
	dst = append(dst, data...)
	return dst
}

// readLenPrefixed parses one little-endian length-prefixed frame from
// src, returning the frame bytes plus the remainder.
func readLenPrefixed(src []byte) (frame []byte, rest []byte, err error) {
	if len(src) < 4 {
		return nil, nil, fmt.Errorf("len-prefix: need 4 bytes, have %d", len(src))
	}
	n := binary.LittleEndian.Uint32(src[:4])
	if uint64(n) > uint64(len(src)-4) {
		return nil, nil, fmt.Errorf("len-prefix: frame length %d exceeds remaining %d", n, len(src)-4)
	}
	return src[4 : 4+n], src[4+n:], nil
}

// HorizonCertificate is the LP-105 §"HorizonCertificate" three-lane
// certificate constructed from a verified Warp 2.0 envelope. It is
// the artifact a destination chain admits as "Horizon-final" once
// Prism has bound all three lanes to the same source-chain
// transcript.
//
// This helper does not run verification — that is VerifyV2 /
// VerifyPQLanes. It only marshals the verified envelope into the
// canonical certificate shape consensus / bridge code consumes.
type HorizonCertificate struct {
	// SourceChainID is the originating chain identifier.
	SourceChainID [32]byte

	// Beam is the BLS aggregate signature bytes (v1 Message signature).
	Beam []byte

	// MLDSACertSet is the per-validator ML-DSA attestation set bytes
	// (or its Z-Chain Groth16 rollup). Empty if the envelope did not
	// carry the ML-DSA lane.
	MLDSACertSet []byte

	// Pulse is the Pulsar threshold-signature bytes. Empty if the
	// envelope did not carry the Pulse lane.
	Pulse []byte

	// SourceNebulaRoot is the source chain's Nebula root anchor.
	SourceNebulaRoot [32]byte

	// SourceKeyEraID is the source-chain Pulsar lineage ID.
	SourceKeyEraID uint64

	// SourceGeneration is the source-chain LSS generation.
	SourceGeneration uint64

	// HashSuiteID pins the hash profile.
	HashSuiteID string

	// UnsignedMessageBytes is the canonical UnsignedMessage byte
	// stream — the transcript subject every lane signs.
	UnsignedMessageBytes []byte
}

// HorizonFromEnvelope lifts a Warp 2.0 envelope into a HorizonCertificate.
// The envelope MUST already have been verified via VerifyV2 — this
// helper does no signature checks.
func HorizonFromEnvelope(env *warp.Envelope) (*HorizonCertificate, error) {
	if env == nil {
		return nil, errors.New("warp pulsar: nil envelope")
	}
	return &HorizonCertificate{
		SourceChainID:        env.Message.SourceChainID,
		Beam:                 append([]byte(nil), env.Beam.Signature[:]...),
		MLDSACertSet:         append([]byte(nil), env.MLDSACertSet...),
		Pulse:                append([]byte(nil), env.PulseSig...),
		SourceNebulaRoot:     env.Message.SourceNebulaRoot,
		SourceKeyEraID:       env.Message.SourceKeyEraID,
		SourceGeneration:     env.Message.SourceGeneration,
		HashSuiteID:          env.Message.HashSuiteOrDefault(),
		UnsignedMessageBytes: env.Message.Bytes(),
	}, nil
}

// HorizonMarshalPrefix is the canonical magic prefix for Horizon
// certificate wire bytes. Distinct from any Warp envelope or Pulsar
// activation prefix.
const HorizonMarshalPrefix = "QUASAR-HORIZON-CERT-v1"

// MarshalBinary returns the canonical wire-format bytes for a
// HorizonCertificate. Layout:
//
//	prefix                         len(HorizonMarshalPrefix) bytes
//	source_chain_id                32 bytes
//	source_nebula_root             32 bytes
//	source_key_era_id              8 bytes (big-endian)
//	source_generation              8 bytes (big-endian)
//	hash_suite_id_len              4 bytes (big-endian) || bytes
//	beam_len                       4 bytes (big-endian) || bytes
//	mldsa_cert_set_len             4 bytes (big-endian) || bytes
//	pulse_len                      4 bytes (big-endian) || bytes
//	unsigned_message_bytes_len     4 bytes (big-endian) || bytes
//
// Encoding is total-order canonical: every byte is determined by the
// struct contents and the same struct value always produces the same
// bytes. Re-decoding via UnmarshalBinary yields a struct that
// MarshalBinary will re-encode byte-equally.
func (h *HorizonCertificate) MarshalBinary() ([]byte, error) {
	if h == nil {
		return nil, errors.New("warp pulsar: nil HorizonCertificate")
	}
	out := make([]byte, 0, len(HorizonMarshalPrefix)+32+32+8+8+4+len(h.HashSuiteID)+4+len(h.Beam)+4+len(h.MLDSACertSet)+4+len(h.Pulse)+4+len(h.UnsignedMessageBytes))
	out = append(out, []byte(HorizonMarshalPrefix)...)
	out = append(out, h.SourceChainID[:]...)
	out = append(out, h.SourceNebulaRoot[:]...)

	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], h.SourceKeyEraID)
	out = append(out, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], h.SourceGeneration)
	out = append(out, u64[:]...)

	out = appendBELenPrefixed(out, []byte(h.HashSuiteID))
	out = appendBELenPrefixed(out, h.Beam)
	out = appendBELenPrefixed(out, h.MLDSACertSet)
	out = appendBELenPrefixed(out, h.Pulse)
	out = appendBELenPrefixed(out, h.UnsignedMessageBytes)
	return out, nil
}

// UnmarshalBinary is the inverse of MarshalBinary.
func (h *HorizonCertificate) UnmarshalBinary(b []byte) error {
	if h == nil {
		return errors.New("warp pulsar: nil HorizonCertificate receiver")
	}
	if len(b) < len(HorizonMarshalPrefix) {
		return errors.New("warp pulsar: horizon cert too short for prefix")
	}
	if string(b[:len(HorizonMarshalPrefix)]) != HorizonMarshalPrefix {
		return errors.New("warp pulsar: horizon cert prefix mismatch")
	}
	rest := b[len(HorizonMarshalPrefix):]
	if len(rest) < 32+32+8+8 {
		return errors.New("warp pulsar: horizon cert truncated header")
	}
	copy(h.SourceChainID[:], rest[:32])
	rest = rest[32:]
	copy(h.SourceNebulaRoot[:], rest[:32])
	rest = rest[32:]
	h.SourceKeyEraID = binary.BigEndian.Uint64(rest[:8])
	rest = rest[8:]
	h.SourceGeneration = binary.BigEndian.Uint64(rest[:8])
	rest = rest[8:]

	suite, rest, err := readBELenPrefixed(rest)
	if err != nil {
		return fmt.Errorf("warp pulsar: horizon hash_suite_id: %w", err)
	}
	h.HashSuiteID = string(suite)

	beam, rest, err := readBELenPrefixed(rest)
	if err != nil {
		return fmt.Errorf("warp pulsar: horizon beam: %w", err)
	}
	h.Beam = beam

	cert, rest, err := readBELenPrefixed(rest)
	if err != nil {
		return fmt.Errorf("warp pulsar: horizon mldsa: %w", err)
	}
	h.MLDSACertSet = cert

	pulse, rest, err := readBELenPrefixed(rest)
	if err != nil {
		return fmt.Errorf("warp pulsar: horizon pulse: %w", err)
	}
	h.Pulse = pulse

	umsg, rest, err := readBELenPrefixed(rest)
	if err != nil {
		return fmt.Errorf("warp pulsar: horizon unsigned_message: %w", err)
	}
	h.UnsignedMessageBytes = umsg

	if len(rest) != 0 {
		return fmt.Errorf("warp pulsar: %d trailing bytes after horizon cert", len(rest))
	}
	return nil
}

// PrismVerify runs the structural / transcript-binding portion of the
// LP-105 §Prism verification path on the certificate. It checks the
// invariants Prism enforces BEFORE delegating to per-lane signature
// verifiers — i.e. the property that "every lane refracts from the
// same source-chain transcript." Specifically:
//
//  1. SourceChainID is non-zero.
//  2. UnsignedMessageBytes is present (it is the transcript subject
//     every lane signs against).
//  3. HashSuiteID is non-empty (defaulting handled elsewhere).
//  4. Lineage fields are coherent: at least one of (Beam, Pulse,
//     MLDSACertSet) is present — a HorizonCertificate with no lanes
//     populated cannot establish anything, and is rejected.
//  5. The wire bytes round-trip: marshalling the receiver yields a
//     byte stream that re-unmarshals to the same struct shape (this
//     catches caller-side mutation that produced a struct
//     MarshalBinary cannot represent).
//
// PrismVerify does NOT verify the BLS, ML-DSA, or Pulsar signatures —
// those are independent reductions per
// proofs/quasar/horizon-soundness.tex Theorem ref:horizon-soundness.
// Callers feed the result of PrismVerify into the lane-specific
// verifiers (VerifyV1 / KernelVerifier.VerifyPulse / ML-DSA cert-set
// verifier) to complete the Horizon-final check.
func (h *HorizonCertificate) PrismVerify() error {
	if h == nil {
		return errors.New("warp pulsar: nil HorizonCertificate")
	}
	if h.SourceChainID == ([32]byte{}) {
		return errors.New("warp pulsar: horizon SourceChainID zero")
	}
	if len(h.UnsignedMessageBytes) == 0 {
		return errors.New("warp pulsar: horizon UnsignedMessageBytes empty")
	}
	if len(h.HashSuiteID) == 0 {
		return errors.New("warp pulsar: horizon HashSuiteID empty")
	}
	if len(h.Beam) == 0 && len(h.Pulse) == 0 && len(h.MLDSACertSet) == 0 {
		return errors.New("warp pulsar: horizon has no lanes populated")
	}
	// Round-trip self-check: the struct must be losslessly serialisable.
	wire, err := h.MarshalBinary()
	if err != nil {
		return fmt.Errorf("warp pulsar: horizon marshal: %w", err)
	}
	var rt HorizonCertificate
	if err := rt.UnmarshalBinary(wire); err != nil {
		return fmt.Errorf("warp pulsar: horizon round-trip: %w", err)
	}
	if rt.SourceChainID != h.SourceChainID ||
		rt.SourceNebulaRoot != h.SourceNebulaRoot ||
		rt.SourceKeyEraID != h.SourceKeyEraID ||
		rt.SourceGeneration != h.SourceGeneration ||
		rt.HashSuiteID != h.HashSuiteID {
		return errors.New("warp pulsar: horizon round-trip mismatch on header fields")
	}
	if !bytesEqual(rt.Beam, h.Beam) ||
		!bytesEqual(rt.MLDSACertSet, h.MLDSACertSet) ||
		!bytesEqual(rt.Pulse, h.Pulse) ||
		!bytesEqual(rt.UnsignedMessageBytes, h.UnsignedMessageBytes) {
		return errors.New("warp pulsar: horizon round-trip mismatch on lane bytes")
	}
	return nil
}

// appendBELenPrefixed appends a 4-byte big-endian length followed by
// data to dst. Mirrors appendLenPrefixed but in big-endian — chosen
// for HorizonCertificate because the rest of the Horizon header
// (SourceKeyEraID, SourceGeneration) is already big-endian, so
// keeping a single endianness inside the cert format is the simpler
// invariant.
func appendBELenPrefixed(dst, data []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(data)))
	dst = append(dst, l[:]...)
	dst = append(dst, data...)
	return dst
}

// readBELenPrefixed reads a 4-byte big-endian length-prefixed frame
// from src.
func readBELenPrefixed(src []byte) (frame, rest []byte, err error) {
	if len(src) < 4 {
		return nil, nil, fmt.Errorf("be-len-prefix: need 4 bytes, have %d", len(src))
	}
	n := binary.BigEndian.Uint32(src[:4])
	if uint64(n) > uint64(len(src)-4) {
		return nil, nil, fmt.Errorf("be-len-prefix: frame length %d exceeds remaining %d", n, len(src)-4)
	}
	out := append([]byte(nil), src[4:4+n]...)
	return out, src[4+n:], nil
}

// bytesEqual returns true iff a and b are byte-equal. Treated as
// equal when both are zero-length, regardless of nil vs empty slice.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
