// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// signature_scheme_fuzz_test.go fuzzes the cross-product of
// envelope-decoder + signature-leg-parser against the PQ-native
// signature registry. The property under test:
//
//   For all input byte strings, ParseEnvelope MUST NOT panic and
//   MUST NOT silently classify a classical-only envelope as PQ-evidenced.
//
// The fuzz harness exercises three input shapes simultaneously:
//
//   1. Arbitrary bytes (catches decoder panics on malformed input).
//   2. v1 wire bytes lifted to v2 (catches dispatcher confusion).
//   3. v2 wire bytes with tampered Pulse / MLDSACertSet lengths
//      (catches buffer-overrun or off-by-one length parsing).
//
// Property anchors:
//   proofs/quasar/warp-pq-soundness.tex Theorem ref:warp-v2-soundness
//   proofs/definitions/finality-definitions.tex Remark ref:groth16-not-pq

package warp

import (
	"bytes"
	"testing"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
	"github.com/luxfi/pq"
)

// makeSchemeFuzzSeed builds a deterministic v2 envelope with the
// declared (hasPulse, hasCert) shape, then returns its wire bytes
// for seeding the fuzzer corpus. Mirrors the existing seed factory
// in fuzz_envelope_test.go but tagged for the signature-scheme
// fuzzer's call-site (kept independent so corpora don't collide
// at test discovery).
func makeSchemeFuzzSeed(t testing.TB, hasPulse, hasCert bool) []byte {
	t.Helper()
	chainID := ids.ID{0xA1, 0xA2, 0xA3, 0xA4}
	unsigned, err := NewUnsignedMessage(1, chainID, []byte("scheme-fuzz"))
	if err != nil {
		t.Fatalf("unsigned: %v", err)
	}
	signers := NewBitSet()
	signers.Add(0)
	signers.Add(2)

	var sigBytes [bls.SignatureLen]byte
	copy(sigBytes[:], bytes.Repeat([]byte{0xAB}, bls.SignatureLen))
	beam := NewBitSetSignature(signers, sigBytes)

	msg, err := NewMessage(unsigned, beam)
	if err != nil {
		t.Fatalf("new msg: %v", err)
	}

	var pulse []byte
	if hasPulse {
		pulse = bytes.Repeat([]byte{0x42}, 64)
	}
	var cert []byte
	if hasCert {
		cert = bytes.Repeat([]byte{0xC3}, 192)
	}
	env := &EnvelopeV2{
		Message:          msg,
		SourceNebulaRoot: [32]byte{0xDE, 0xAD, 0xBE, 0xEF},
		SourceKeyEraID:   7,
		SourceGeneration: 11,
		HashSuiteID:      DefaultHashSuiteID,
		PulsarPulse:      pulse,
		MLDSACertSet:     cert,
	}
	wire, err := env.Bytes()
	if err != nil {
		t.Fatalf("env bytes: %v", err)
	}
	return wire
}

// FuzzSignatureSchemeLegParser is the canonical fuzz harness for
// the PQ-native posture's wire-input surface. It exercises:
//
//   - Property A: ParseEnvelope never panics on any byte sequence.
//
//   - Property B: When ParseEnvelope succeeds, the envelope's
//     HasPQEvidence predicate is consistent with the actual
//     MLDSACertSet field (HasPQEvidence ⇔ len(MLDSACertSet) > 0).
//
//   - Property C: When HasPQEvidence is FALSE and the envelope is
//     fed to pq.ValidateMode(ModeStrictPQ, env, nil), the result is
//     ErrClassicalAuthForbidden. This is the audit-grep'able
//     guarantee that classical envelopes cannot leak through the
//     strict-PQ gate.
//
//   - Property D: When HasPQEvidence is TRUE, the strict-PQ gate
//     accepts the envelope (the verify closure is what does the
//     cryptographic verification work; the gate's job is only the
//     presence/absence dispatch).
func FuzzSignatureSchemeLegParser(f *testing.F) {
	// Seed corpus.
	f.Add(makeSchemeFuzzSeed(f, false, false)) // classical-only
	f.Add(makeSchemeFuzzSeed(f, true, false))  // pulse only
	f.Add(makeSchemeFuzzSeed(f, false, true))  // cert only
	f.Add(makeSchemeFuzzSeed(f, true, true))   // both lanes
	// Edge cases.
	f.Add([]byte{})
	f.Add([]byte{EnvelopeVersion2})
	f.Add([]byte{EnvelopeVersion2, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x05}) // unknown version byte

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Property A: never panics.
		env, err := ParseEnvelope(raw)
		if err != nil {
			return // errors are fine; only panic is a fuzz failure
		}

		// Property B: HasPQEvidence consistent with the field.
		hasField := env != nil && len(env.MLDSACertSet) > 0
		hasPredicate := env.HasPQEvidence()
		if hasField != hasPredicate {
			t.Fatalf("HasPQEvidence drift: field=%t predicate=%t (envelope=%+v)",
				hasField, hasPredicate, env)
		}

		// Property C: classical-only ⇒ strict-PQ refuses.
		gateErr := pq.ValidateMode(pq.ModeStrictPQ, env, nil)
		if !hasPredicate {
			if gateErr == nil {
				t.Fatalf("strict-PQ accepted classical-only envelope (raw=%x)", raw)
			}
			// Confirm it's the right error category.
			if !errorMatches(gateErr, pq.ErrClassicalAuthForbidden) {
				t.Fatalf("classical-only envelope refused with wrong error: %v", gateErr)
			}
		} else {
			// Property D: PQ-evidenced ⇒ strict-PQ gate accepts
			// when verify closure is nil (no verification work
			// configured; only presence/absence dispatch).
			if gateErr != nil {
				t.Fatalf("strict-PQ refused PQ-evidenced envelope: %v", gateErr)
			}
		}

		// Idempotence: re-encoding the parsed envelope MUST succeed
		// and MUST byte-equal the original encoding (round-trip on
		// the canonical RLP form). We compare against the parsed
		// envelope's own re-encoding to handle the v1-lifted case
		// where input bytes were RLP-Message and re-encoding yields
		// v2 wire bytes.
		if env != nil && env.Message != nil {
			wire, err := env.Bytes()
			if err != nil {
				t.Fatalf("re-encode failed: %v", err)
			}
			parsed2, err := ParseEnvelopeV2(wire)
			if err != nil {
				t.Fatalf("re-parse failed: %v (wire=%x)", err, wire)
			}
			wire2, err := parsed2.Bytes()
			if err != nil {
				t.Fatalf("re-re-encode failed: %v", err)
			}
			if !bytes.Equal(wire, wire2) {
				t.Fatalf("envelope wire bytes not stable across round-trip:\n  one=%x\n  two=%x", wire, wire2)
			}
		}
	})
}

// FuzzCorruptedMLDSACertSet tampers with the MLDSACertSet length
// prefix of an otherwise-valid v2 envelope. The envelope's RLP
// decoder MUST refuse rather than read into adjacent memory or
// produce a parsed envelope whose MLDSACertSet field is silently
// truncated.
func FuzzCorruptedMLDSACertSet(f *testing.F) {
	// Seed: a valid envelope with a non-empty MLDSACertSet.
	f.Add(makeSchemeFuzzSeed(f, false, true), uint16(0))
	f.Add(makeSchemeFuzzSeed(f, true, true), uint16(64))
	f.Add(makeSchemeFuzzSeed(f, false, true), uint16(0xFFFF))

	f.Fuzz(func(t *testing.T, raw []byte, mutateAt uint16) {
		if len(raw) < 10 {
			return
		}
		// Defensive copy + mutation.
		corrupted := make([]byte, len(raw))
		copy(corrupted, raw)
		pos := int(mutateAt) % len(corrupted)
		corrupted[pos] ^= 0xFF

		// Property: never panics.
		env, err := ParseEnvelope(corrupted)
		if err != nil {
			return
		}
		// If the parse succeeded, the envelope MUST verify its own
		// structural invariants (no overflow on lengths).
		if env != nil && env.Message != nil {
			_ = env.Verify() // any error is fine; we only check no panic
		}
	})
}

// errorMatches tests whether err's chain contains target, without
// importing errors at the top of the fuzz file (the imports list
// is kept minimal for fuzz harness clarity).
func errorMatches(err error, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		// Walk unwrap chain.
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
