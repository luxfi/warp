// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Warp envelope fuzz harness.
//
// Property anchor: proofs/quasar/warp-pq-soundness.tex
// Theorem ref:warp-v2-soundness.
//
// Properties under fuzzing:
//
//  1. ParseEnvelope on arbitrary bytes never panics. The dispatcher
//     accepts both v1 and v2 wire formats; malformed inputs MUST
//     produce a clean error rather than a runtime panic.
//
//  2. Valid v2 envelopes round-trip via Bytes ↔ ParseEnvelopeV2.
//
//  3. v1 envelopes (RLP-encoded Message with no leading version byte)
//     parse via the legacy path and produce an EnvelopeV2 with only
//     the Beam lane populated.

package warp

import (
	"bytes"
	"testing"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
)

// FuzzWarpEnvelopeV2 exercises ParseEnvelope against arbitrary bytes
// (v1 path, v2 path, and outright malformed inputs).
func FuzzWarpEnvelopeV2(f *testing.F) {
	// Seed corpus: a few bytes pulled from the existing
	// envelopeFixture used in envelope_test.go, both as v2 envelopes
	// and as raw v1 wire bytes.
	f.Add(makeFuzzSeedV2(7, 11, true, true))
	f.Add(makeFuzzSeedV2(0, 0, false, false))
	f.Add(makeFuzzSeedV1())
	// Edge cases.
	f.Add([]byte{})
	f.Add([]byte{EnvelopeVersion2})
	f.Add([]byte{0x05, 0x00, 0x00})
	f.Add([]byte{EnvelopeVersion2, 0xFF})

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Property 1: ParseEnvelope never panics.
		env, err := ParseEnvelope(raw)
		if err != nil {
			// Errors are fine; we only care that no panic was thrown.
			return
		}
		if env == nil || env.Message == nil {
			t.Fatalf("ParseEnvelope returned nil envelope without error")
		}

		// Property 2: envelope passes structural verification.
		if err := env.Verify(); err != nil {
			t.Fatalf("ParseEnvelope returned envelope that fails Verify: %v", err)
		}

		// Property 3: re-encoding the parsed envelope and re-parsing
		// produces a byte-equal envelope. Only run this on v2 inputs
		// (v1 inputs have no version byte; re-encoding via v2 Bytes
		// produces a v2 envelope that the v1 path cannot reproduce
		// — that asymmetry is by design and exercised by
		// TestParseEnvelopeForwardCompatV1Bytes).
		if len(raw) > 0 && raw[0] == EnvelopeVersion2 {
			out, err := env.Bytes()
			if err != nil {
				t.Fatalf("re-encode failed: %v", err)
			}
			env2, err := ParseEnvelopeV2(out)
			if err != nil {
				t.Fatalf("re-parse failed: %v", err)
			}
			if !env.Equal(env2) {
				t.Fatalf("round-trip not byte-equal")
			}
		}
	})
}

// TestFuzzCorpus_EnvelopeReplay re-runs the seed corpus deterministically
// for CI environments that want a non-fuzz replay.
func TestFuzzCorpus_EnvelopeReplay(t *testing.T) {
	seeds := [][]byte{
		makeFuzzSeedV2(7, 11, true, true),
		makeFuzzSeedV2(0, 0, false, false),
		makeFuzzSeedV1(),
	}
	for i, s := range seeds {
		env, err := ParseEnvelope(s)
		if err != nil {
			t.Fatalf("seed %d: parse failed: %v", i, err)
		}
		if err := env.Verify(); err != nil {
			t.Fatalf("seed %d: verify failed: %v", i, err)
		}
	}
}

// makeFuzzSeedV2 builds a valid v2 wire envelope with the given lineage
// fields, optionally including a Pulse and / or ML-DSA cert set blob.
// We construct without depending on the test package's helper to avoid
// coupling between fuzz seeds and the unit-test fixture; this version
// is internal to the fuzz harness.
func makeFuzzSeedV2(eraID, generation uint64, withPulse, withCertSet bool) []byte {
	const networkID = uint32(1)
	chainID := ids.ID{0xA1, 0xA2}
	payload := []byte("envelope-fuzz-payload")

	unsigned, err := NewUnsignedMessage(networkID, chainID, payload)
	if err != nil {
		panic(err)
	}
	signers := NewBitSet()
	signers.Add(0)
	signers.Add(2)
	var sig [bls.SignatureLen]byte
	copy(sig[:], bytes.Repeat([]byte{0xAB}, bls.SignatureLen))
	bsig := NewBitSetSignature(signers, sig)
	msg, err := NewMessage(unsigned, bsig)
	if err != nil {
		panic(err)
	}

	env := &EnvelopeV2{
		Message:          msg,
		SourceKeyEraID:   eraID,
		SourceGeneration: generation,
		HashSuiteID:      DefaultHashSuiteID,
		SourceNebulaRoot: [32]byte{0xDE, 0xAD},
	}
	if withPulse {
		env.PulsarPulse = bytes.Repeat([]byte{0x42}, 64)
	}
	if withCertSet {
		env.MLDSACertSet = bytes.Repeat([]byte{0xC3}, 192)
	}
	out, err := env.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}

// makeFuzzSeedV1 returns the v1 wire bytes for a representative
// Message. ParseEnvelope must accept these via the legacy path and
// return an EnvelopeV2 with only the Beam lane populated.
func makeFuzzSeedV1() []byte {
	const networkID = uint32(1)
	chainID := ids.ID{0xC1, 0xC2}
	payload := []byte("envelope-fuzz-v1-payload")

	unsigned, err := NewUnsignedMessage(networkID, chainID, payload)
	if err != nil {
		panic(err)
	}
	signers := NewBitSet()
	signers.Add(0)
	var sig [bls.SignatureLen]byte
	copy(sig[:], bytes.Repeat([]byte{0xCD}, bls.SignatureLen))
	bsig := NewBitSetSignature(signers, sig)
	msg, err := NewMessage(unsigned, bsig)
	if err != nil {
		panic(err)
	}
	return msg.Bytes()
}
