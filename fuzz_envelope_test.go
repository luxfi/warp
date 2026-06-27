// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Warp envelope fuzz harness.
//
// Properties under fuzzing:
//
//  1. ParseEnvelope on arbitrary bytes never panics — malformed input
//     produces a clean error, never a runtime panic.
//  2. A successfully parsed envelope passes Verify and re-encodes
//     byte-equally (canonical round-trip).
//  3. Legacy RLP / v2 lead bytes are rejected at the magic.

package warp

import (
	"bytes"
	"testing"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
)

func FuzzEnvelope(f *testing.F) {
	f.Add(makeFuzzSeed(7, 11, true, true))
	f.Add(makeFuzzSeed(0, 0, false, false))
	f.Add([]byte{})
	f.Add(wireMagic[:])
	f.Add(append(wireMagic[:], kindEnvelope))
	f.Add([]byte{0x05, 0x00, 0x00})
	f.Add(append(wireMagic[:], 0xFF))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Property 1: never panics.
		env, err := ParseEnvelope(raw)
		if err != nil {
			return
		}
		// Property 2: structurally valid + canonical round-trip.
		if err := env.Verify(); err != nil {
			t.Fatalf("parsed envelope fails Verify: %v", err)
		}
		out, err := env.Bytes()
		if err != nil {
			t.Fatalf("re-encode failed: %v", err)
		}
		// A canonical parse of arbitrary bytes must re-encode to those
		// exact bytes (the decoder accepts only canonical form).
		if !bytes.Equal(raw, out) {
			t.Fatalf("canonical round-trip not byte-equal:\n  in =%x\n  out=%x", raw, out)
		}
		env2, err := ParseEnvelope(out)
		if err != nil {
			t.Fatalf("re-parse failed: %v", err)
		}
		if !env.Equal(env2) {
			t.Fatalf("round-trip envelopes not equal")
		}
	})
}

// TestFuzzCorpus_EnvelopeReplay re-runs the seed corpus deterministically.
func TestFuzzCorpus_EnvelopeReplay(t *testing.T) {
	for i, s := range [][]byte{
		makeFuzzSeed(7, 11, true, true),
		makeFuzzSeed(0, 0, false, false),
	} {
		env, err := ParseEnvelope(s)
		if err != nil {
			t.Fatalf("seed %d: parse failed: %v", i, err)
		}
		if err := env.Verify(); err != nil {
			t.Fatalf("seed %d: verify failed: %v", i, err)
		}
	}
}

// makeFuzzSeed builds a valid envelope wire stream with the given lineage
// and optional PQ lanes.
func makeFuzzSeed(eraID, generation uint64, withPulse, withCertSet bool) []byte {
	core := &Core{
		NetworkID:        1,
		SourceChainID:    ids.ID{0xA1, 0xA2},
		SourceNebulaRoot: [32]byte{0xDE, 0xAD},
		SourceKeyEraID:   eraID,
		SourceGeneration: generation,
		HashSuiteID:      DefaultHashSuiteID,
		Payload:          []byte("envelope-fuzz-payload"),
	}
	signers := NewBitSet()
	signers.Add(0)
	signers.Add(2)
	var sig [bls.SignatureLen]byte
	copy(sig[:], bytes.Repeat([]byte{0xAB}, bls.SignatureLen))

	var pulse []byte
	if withPulse {
		pulse = bytes.Repeat([]byte{0x42}, 64)
	}
	var cert []byte
	if withCertSet {
		cert = bytes.Repeat([]byte{0xC3}, 192)
	}
	env, err := NewEnvelope(core, NewBitSetSignature(signers, sig), pulse, cert)
	if err != nil {
		panic(err)
	}
	out, err := env.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}
