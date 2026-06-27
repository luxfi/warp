// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pulsar wires Quasar envelopes to the Corona Ringtail (Module-LWE)
// lattice threshold-signature kernel, and hosts the Horizon multi-lane
// certificate helpers. It is the interface the warp root package's
// CoronaVerifier callback satisfies.
//
// NAMING NOTE (the conflation this change kills): the lattice-threshold lane
// wired here is CORONA (the corona kernel, Module-LWE / Ringtail), NOT Pulsar
// (threshold ML-DSA). The package directory is still named "pulsar" for now;
// the lane it verifies is Corona. Pulsar (threshold ML-DSA) is a separate,
// reserved, fail-closed evidence kind in the root package (evidence.go).
//
// Why a subpackage. The root warp package MUST NOT import the corona
// kernel directly: doing so would create an import cycle through the
// threshold orchestration framework. Splitting the corona lane into a
// subpackage lets the root warp package depend only on the small
// CoronaVerifier interface, while the concrete kernel-driven verifier
// lives here.
//
// Architecture:
//
//	warp                      (root pkg; no corona-kernel import)
//	  ├── Envelope            (the Quasar envelope type)
//	  ├── CoronaVerifier      (interface: VerifyRingtailThreshold)
//	  └── VerifyWithOptions / VerifyPQLanes / VerifyFinalityEvidence
//
//	warp/pulsar (this pkg; imports github.com/luxfi/corona)
//	  ├── RingtailVerifier    (CoronaVerifier impl; corona sig over CoronaSigningBytes(D))
//	  └── HorizonCertificate  (LP-105 §"HorizonCertificate" helper)
//
// The RingtailVerifier accepts a CoronaGroupKeyResolver that pulls a
// (corona.GroupKey, suiteID) tuple from a (KeyEraID, Generation) pair —
// typically supplied by the destination chain's source-chain corona key
// registry. The corona kernel's Verify is then invoked over the canonical
// signing bytes.
//
// LP-105 §"Warp evolution" is the normative spec; this package is the
// production wiring.
package pulsar

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/ids"
	"github.com/luxfi/warp"

	corona "github.com/luxfi/corona/threshold"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/buffer"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// Errors returned by the Warp Corona Ringtail lane path.
var (
	// ErrCoronaAbsent is returned when a verifier is asked to verify a
	// corona signature that the envelope does not carry.
	ErrCoronaAbsent = errors.New("warp corona: envelope has no Corona signature to verify")

	// ErrCoronaGroupKeyResolverFailed is returned when the
	// CoronaGroupKeyResolver could not produce a key for the envelope's
	// (KeyEraID, Generation).
	ErrCoronaGroupKeyResolverFailed = errors.New("warp corona: group-key resolver failed")

	// ErrCoronaVerifyFailed is returned when the corona kernel rejects the
	// threshold signature.
	ErrCoronaVerifyFailed = errors.New("warp corona: kernel rejected signature")

	// ErrCoronaSuiteMismatch is returned when the resolver-supplied suite is
	// not the Corona Ringtail lane suite (warp.DefaultCoronaSuiteID). This
	// is the CORONA lane suite check — decoupled from the Message's generic
	// c14n hash tag.
	ErrCoronaSuiteMismatch = errors.New("warp corona: resolver suite is not the Corona Ringtail suite")
)

// CoronaGroupKeyResolver maps a (sourceChainID, keyEraID, generation) tuple
// to the Corona Ringtail GroupKey + suite identifier the source chain was
// using when the envelope was signed. Destination chains implement this
// against their source-chain CORONA key registry — a contract that records
// the source's corona GroupKey lineage as it evolves through Bootstrap,
// Reshare, and Reanchor events.
//
// This is the CORONA threshold-lane resolver. It is a DISTINCT type from the
// warp.PulsarKeyEraResolver (threshold ML-DSA, one group key): the two key-era
// records are not interchangeable. The P3Q / cert-set lanes need no group-key
// resolver at all — they resolve INDEPENDENT per-validator keys via
// warp.SignerSetAuthority.
//
// Returning a zero-pointer GroupKey is treated as
// ErrCoronaGroupKeyResolverFailed; an empty suiteID defaults to the Corona
// Ringtail suite (warp.DefaultCoronaSuiteID).
type CoronaGroupKeyResolver interface {
	ResolveGroupKey(
		sourceChainID [32]byte,
		keyEraID uint64,
		generation uint64,
	) (gk *corona.GroupKey, suiteID string, err error)
}

// RingtailVerifier is the production CoronaVerifier. It uses a
// CoronaGroupKeyResolver to fetch the source-chain Corona GroupKey, builds
// the canonical signing bytes via warp.CoronaSigningBytes, and verifies the
// envelope's CoronaSig against the corona kernel's Verify.
type RingtailVerifier struct {
	Resolver CoronaGroupKeyResolver
}

// NewRingtailVerifier returns a Corona Ringtail verifier backed by the given
// resolver.
func NewRingtailVerifier(r CoronaGroupKeyResolver) *RingtailVerifier {
	return &RingtailVerifier{Resolver: r}
}

// VerifyRingtailThreshold implements warp.CoronaVerifier (the Corona Ringtail
// lattice-threshold lane). It is SUBJECT-AGNOSTIC: subject is the 32-byte
// finality digest the corona signature is over — D for a warp cross-chain
// envelope, M for a quasar consensus cert — and ev is the typed corona lane
// payload (routing + serialized signature). This single verification core
// serves both carriers; the carrier only decides which subject to pass.
//
// The verification chain:
//
//  1. The evidence must carry a non-empty corona signature.
//  2. Resolve the Corona GroupKey for (ChainID, KeyEraID, Generation).
//  3. Confirm the resolver-supplied suiteID IS the Corona Ringtail lane suite
//     (warp.DefaultCoronaSuiteID). This is the CORONA lane suite check —
//     DECOUPLED from the Message's generic c14n hash tag (HashSuiteID), which
//     is pinned to "Pulsar-SHA3" for teleport/BridgeV2 D-lockstep and is NOT a
//     lane selector. (Decoupling these is what kills the old spurious
//     ErrSuiteMismatch where the corona resolver's suite was compared against
//     the message's "Pulsar-SHA3" tag.)
//  4. Build the corona signing bytes warp.CoronaSigningBytes(subject) =
//     "LUX-WARP-ZAP-CORONA-v1"‖subject.
//  5. Deserialize ev.Sig into a corona.Signature.
//  6. Call corona.Verify(gk, signingBytes, sig).
//
// For a warp envelope, subject = D folds in SourceNebulaRoot / SourceKeyEraID /
// SourceGeneration / HashSuiteID / SourceChainID / NetworkID / Payload, so
// verifying over CoronaSigningBytes(D) binds the signature to every one of them.
func (v *RingtailVerifier) VerifyRingtailThreshold(subject []byte, ev warp.CoronaEvidence) error {
	if len(ev.Sig) == 0 {
		return ErrCoronaAbsent
	}
	if v == nil || v.Resolver == nil {
		return fmt.Errorf("%w: nil resolver", ErrCoronaGroupKeyResolverFailed)
	}

	sid, err := ids.ToID(subject)
	if err != nil {
		return fmt.Errorf("%w: bad subject: %v", ErrCoronaVerifyFailed, err)
	}

	gk, suiteID, err := v.Resolver.ResolveGroupKey([32]byte(ev.ChainID), ev.KeyEraID, ev.Generation)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCoronaGroupKeyResolverFailed, err)
	}
	if gk == nil {
		return fmt.Errorf("%w: nil GroupKey", ErrCoronaGroupKeyResolverFailed)
	}
	if suiteID == "" {
		suiteID = string(warp.DefaultCoronaSuiteID)
	}
	if suiteID != string(warp.DefaultCoronaSuiteID) {
		return fmt.Errorf("%w: resolver=%q want=%q",
			ErrCoronaSuiteMismatch, suiteID, warp.DefaultCoronaSuiteID)
	}

	signing := warp.CoronaSigningBytes(sid)

	sig, err := DeserializeCoronaSig(ev.Sig)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCoronaVerifyFailed, err)
	}

	if !corona.Verify(gk, string(signing), sig) {
		return ErrCoronaVerifyFailed
	}
	return nil
}

// SerializeCoronaSig returns the byte stream the envelope's CoronaSig
// field carries for a given corona threshold signature. The wire
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
func SerializeCoronaSig(sig *corona.Signature) ([]byte, error) {
	if sig == nil {
		return nil, errors.New("warp corona: nil signature")
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

// MaxCoronaSigWireSize is the upper bound on a Quasar Corona signature byte
// stream. A real Corona lattice threshold signature is ~33 KB
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
const MaxCoronaSigWireSize = 64 * 1024

// MaxCoronaSigFrameSize bounds each individual lane (C, Z, Delta) inside
// a serialized pulse. Real lanes are ≤ ~16 KB; we accept up to 32 KB.
const MaxCoronaSigFrameSize = 32 * 1024

// MaxLatticeUintSliceLen bounds the largest uint64 slice we permit in
// a lattigo wire frame. A canonical corona Poly has 256 coefficients
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

// DeserializeCoronaSig is the inverse of SerializeCoronaSig. It is hardened
// against attacker-controlled length prefixes and lattigo
// deserialization panics: every code path returns a clean error and
// no panic crosses the boundary.
func DeserializeCoronaSig(b []byte) (sig *corona.Signature, err error) {
	if len(b) == 0 {
		return nil, errors.New("warp pulsar: empty corona signature")
	}
	if len(b) > MaxCoronaSigWireSize {
		return nil, fmt.Errorf("warp pulsar: corona signature exceeds max wire size %d > %d", len(b), MaxCoronaSigWireSize)
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
	if len(cBytes) > MaxCoronaSigFrameSize {
		return nil, fmt.Errorf("warp pulsar: C frame exceeds %d bytes", MaxCoronaSigFrameSize)
	}
	if err := validatePolyFrame(cBytes); err != nil {
		return nil, fmt.Errorf("warp pulsar: C frame: %w", err)
	}
	zBytes, rest, err := readLenPrefixed(rest)
	if err != nil {
		return nil, fmt.Errorf("warp pulsar: decode Z frame: %w", err)
	}
	if len(zBytes) > MaxCoronaSigFrameSize {
		return nil, fmt.Errorf("warp pulsar: Z frame exceeds %d bytes", MaxCoronaSigFrameSize)
	}
	if err := validateVectorPolyFrame(zBytes); err != nil {
		return nil, fmt.Errorf("warp pulsar: Z frame: %w", err)
	}
	dBytes, rest, err := readLenPrefixed(rest)
	if err != nil {
		return nil, fmt.Errorf("warp pulsar: decode Delta frame: %w", err)
	}
	if len(dBytes) > MaxCoronaSigFrameSize {
		return nil, fmt.Errorf("warp pulsar: Delta frame exceeds %d bytes", MaxCoronaSigFrameSize)
	}
	if err := validateVectorPolyFrame(dBytes); err != nil {
		return nil, fmt.Errorf("warp pulsar: Delta frame: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("warp pulsar: %d trailing bytes after corona signature", len(rest))
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

	// CoronaRingtail is the Corona Ringtail lattice threshold-signature
	// bytes. Empty if the envelope did not carry the corona lane.
	// (Formerly the "Pulse" field — it is the corona lane, NOT Pulsar.)
	CoronaRingtail []byte

	// SourceNebulaRoot is the source chain's Nebula root anchor.
	SourceNebulaRoot [32]byte

	// SourceKeyEraID is the source-chain corona key-era ID.
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
		CoronaRingtail:       append([]byte(nil), env.CoronaSig...),
		SourceNebulaRoot:     env.Message.SourceNebulaRoot,
		SourceKeyEraID:       env.Message.SourceKeyEraID,
		SourceGeneration:     env.Message.SourceGeneration,
		HashSuiteID:          env.Message.HashSuiteOrDefault(),
		UnsignedMessageBytes: env.Message.Bytes(),
	}, nil
}

// HorizonMarshalPrefix is the canonical magic prefix for Horizon
// certificate wire bytes. Distinct from any Warp envelope or corona
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
//	corona_sig_len                      4 bytes (big-endian) || bytes
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
	out := make([]byte, 0, len(HorizonMarshalPrefix)+32+32+8+8+4+len(h.HashSuiteID)+4+len(h.Beam)+4+len(h.MLDSACertSet)+4+len(h.CoronaRingtail)+4+len(h.UnsignedMessageBytes))
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
	out = appendBELenPrefixed(out, h.CoronaRingtail)
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

	coronaSig, rest, err := readBELenPrefixed(rest)
	if err != nil {
		return fmt.Errorf("warp pulsar: horizon corona sig: %w", err)
	}
	h.CoronaRingtail = coronaSig

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
//  4. Lineage fields are coherent: at least one of (Beam, Corona,
//     MLDSACertSet) is present — a HorizonCertificate with no lanes
//     populated cannot establish anything, and is rejected.
//  5. The wire bytes round-trip: marshalling the receiver yields a
//     byte stream that re-unmarshals to the same struct shape (this
//     catches caller-side mutation that produced a struct
//     MarshalBinary cannot represent).
//
// PrismVerify does NOT verify the BLS, ML-DSA, or Corona signatures —
// those are independent reductions per
// proofs/quasar/horizon-soundness.tex Theorem ref:horizon-soundness.
// Callers feed the result of PrismVerify into the lane-specific
// verifiers (VerifyEnvelope / RingtailVerifier.VerifyRingtailThreshold / ML-DSA cert-set
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
	if len(h.Beam) == 0 && len(h.CoronaRingtail) == 0 && len(h.MLDSACertSet) == 0 {
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
		!bytesEqual(rt.CoronaRingtail, h.CoronaRingtail) ||
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
