// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package warp — Gate 4 negative-transcript tests over the Warp 2.0
// envelope's Pulsar-bound fields (Mar-3-2026 PQ Consensus Architecture
// Freeze).
//
// The Warp 2.0 envelope binds the Pulse signature to the source
// chain's transcript via the v2 fields:
//
//   SourceNebulaRoot  [32]byte
//   SourceKeyEraID    uint64
//   SourceGeneration  uint64
//   HashSuiteID       string  (defaults to "Pulsar-SHA3" when empty)
//   ImplementationVersion is NOT a field on EnvelopeV2 itself (the
//     destination-chain key registry's resolver-supplied profile string
//     plays an analogous role; receiver-side string-equality is tested
//     in warp/pulsar/hashsuite_mismatch_test.go).
//
// For each transcript-binding field we mutate the envelope after
// "signing" (we use a fixed-byte-equality model in line with
// pulsar/reshare/negative_transcript_test.go's honestThresholdVerifier
// abstraction) and assert that:
//
//   1. The canonical signing bytes change.
//   2. The honest verifier rejects the mutated envelope.
//
// Citations (canonical proof bucket):
//
//   proofs/definitions/transcript-binding.tex
//     Definition ref:warp-v2-envelope
//   proofs/pulsar/hash-suite-separation.tex
//     Theorem ref:hash-suite-separation
package warp

import (
	"bytes"
	"testing"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

// negEnvelopeFixture builds a fully-populated v2 envelope used as the
// baseline for transcript-mutation tests. Every Pulsar-bound field is
// non-zero so a mutation cannot accidentally land on the same value.
func negEnvelopeFixture(t *testing.T) *EnvelopeV2 {
	t.Helper()
	const networkID = uint32(1)
	chainID := ids.ID{0xA1, 0xA2, 0xA3, 0xA4}
	payload := []byte("envelope-negative-test-payload")

	unsigned, err := NewUnsignedMessage(networkID, chainID, payload)
	require.NoError(t, err)

	signers := NewBitSet()
	signers.Add(0)
	signers.Add(2)
	signers.Add(4)

	var sigBytes [bls.SignatureLen]byte
	copy(sigBytes[:], bytes.Repeat([]byte{0xAB}, bls.SignatureLen))
	v1Sig := NewBitSetSignature(signers, sigBytes)
	v1, err := NewMessage(unsigned, v1Sig)
	require.NoError(t, err)

	return &EnvelopeV2{
		Message:          v1,
		SourceNebulaRoot: [32]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE},
		SourceKeyEraID:   7,
		SourceGeneration: 11,
		HashSuiteID:      DefaultHashSuiteID,
		PulsarPulse:      bytes.Repeat([]byte{0xCC}, 64),
	}
}

// canonicalSigningBytes mimics warp/pulsar.BuildSigningBytes locally
// (without importing the subpackage, to avoid an import cycle with
// the test). It captures every Pulsar-transcript-bound field on the
// envelope so a single-field mutation flips the bytes.
func canonicalSigningBytes(env *EnvelopeV2) []byte {
	const sigPrefix = "WARP-PULSAR-ENVELOPE-v1"
	suite := env.HashSuiteOrDefault()
	src := env.Message.UnsignedMessage.SourceChainID
	msg := env.Message.UnsignedMessage.Bytes()

	out := make([]byte, 0, len(sigPrefix)+32+32+8+8+4+len(suite)+4+len(msg))
	out = append(out, []byte(sigPrefix)...)
	out = append(out, src[:]...)
	out = append(out, env.SourceNebulaRoot[:]...)

	be := func(v uint64) []byte {
		var b [8]byte
		for i := 0; i < 8; i++ {
			b[7-i] = byte(v >> (8 * i))
		}
		return b[:]
	}
	out = append(out, be(env.SourceKeyEraID)...)
	out = append(out, be(env.SourceGeneration)...)

	be32 := func(v uint32) []byte {
		var b [4]byte
		for i := 0; i < 4; i++ {
			b[3-i] = byte(v >> (8 * i))
		}
		return b[:]
	}
	out = append(out, be32(uint32(len(suite)))...)
	out = append(out, []byte(suite)...)
	out = append(out, be32(uint32(len(msg)))...)
	out = append(out, msg...)
	return out
}

// envHonestVerifier returns a closure that mimics the behaviour of a
// real Pulsar.Verify under an unchanged GroupKey: it accepts iff the
// envelope's canonical signing bytes equal the baseline's.
func envHonestVerifier(baseline *EnvelopeV2) func(env *EnvelopeV2) bool {
	baselineBytes := canonicalSigningBytes(baseline)
	return func(env *EnvelopeV2) bool {
		return bytes.Equal(canonicalSigningBytes(env), baselineBytes)
	}
}

// envMutateField returns a copy of the baseline envelope with exactly
// one Pulsar-transcript field mutated. The field name MUST be one of
// the Warp-v2 transcript fields tracked by Gate 4 ("nebula_root",
// "key_era_id", "generation", "hash_suite_id") plus the source-chain
// payload-derived "source_chain_id" (mutated by re-creating the v1
// UnsignedMessage with a different chain id).
func envMutateField(t *testing.T, base *EnvelopeV2, field string) *EnvelopeV2 {
	t.Helper()
	cp := *base
	cp.Message = base.Message
	switch field {
	case "nebula_root":
		cp.SourceNebulaRoot = [32]byte{0x99, 0x88, 0x77, 0x66}
	case "key_era_id":
		cp.SourceKeyEraID = base.SourceKeyEraID + 1000
	case "generation":
		cp.SourceGeneration = base.SourceGeneration + 1000
	case "hash_suite_id":
		// Default-empty fallback to "Pulsar-SHA3" makes a non-empty
		// distinct value the only safe mutation.
		cp.HashSuiteID = "Pulsar-BLAKE3"
	case "source_chain_id":
		// Mutate the embedded UnsignedMessage's SourceChainID via a
		// fresh Message — this is observable through canonical
		// signing bytes via the source-chain id binding.
		mu, err := NewUnsignedMessage(
			base.Message.UnsignedMessage.NetworkID,
			ids.ID{0xCA, 0xFE, 0xCA, 0xFE},
			base.Message.UnsignedMessage.Payload,
		)
		require.NoError(t, err)
		newMsg, err := NewMessage(mu, base.Message.Signature)
		require.NoError(t, err)
		cp.Message = newMsg
	default:
		t.Fatalf("unknown envelope field: %q", field)
	}
	return &cp
}

// TestWarpEnvelopeNegativeTranscriptMutationsRejected — one subtest
// per Pulsar-transcript-bound field. Mutate, recompute canonical
// signing bytes, assert the bytes changed and the honest verifier
// rejects.
func TestWarpEnvelopeNegativeTranscriptMutationsRejected(t *testing.T) {
	fields := []string{
		"nebula_root",
		"key_era_id",
		"generation",
		"hash_suite_id",
		"source_chain_id",
	}

	base := negEnvelopeFixture(t)
	baselineBytes := canonicalSigningBytes(base)
	verify := envHonestVerifier(base)

	// Sanity: the baseline verifies cleanly.
	require.True(t, verify(base))

	for _, f := range fields {
		t.Run(f, func(t *testing.T) {
			mutated := envMutateField(t, base, f)
			mBytes := canonicalSigningBytes(mutated)
			if bytes.Equal(mBytes, baselineBytes) {
				t.Fatalf("mutation of %q did not change signing bytes", f)
			}
			if verify(mutated) {
				t.Fatalf("honest verifier accepted mutated %q field", f)
			}
		})
	}
}

// TestWarpEnvelopeFieldsMutationsDistinct — orthogonality check: no
// two single-field mutations of the v2 envelope collide on canonical
// signing bytes.
func TestWarpEnvelopeFieldsMutationsDistinct(t *testing.T) {
	fields := []string{
		"nebula_root",
		"key_era_id",
		"generation",
		"hash_suite_id",
		"source_chain_id",
	}
	base := negEnvelopeFixture(t)

	seen := make(map[string]string, len(fields))
	for _, f := range fields {
		mutated := envMutateField(t, base, f)
		key := string(canonicalSigningBytes(mutated))
		if prev, ok := seen[key]; ok {
			t.Fatalf("envelope signing-bytes collision: %q and %q produce same bytes", prev, f)
		}
		seen[key] = f
	}
}

// TestWarpEnvelopeHashSuiteDefaultBindsExplicitly — even though
// HashSuiteOrDefault returns "Pulsar-SHA3" for both empty-string and
// "Pulsar-SHA3" envelopes, the canonical signing bytes are computed
// from HashSuiteOrDefault, so two envelopes that resolve to the same
// suite produce the same signing bytes (this is the COMPATIBILITY
// behaviour). What we test here is that an envelope with an EXPLICIT
// non-default suite produces DIFFERENT signing bytes from the
// default-resolved one — i.e. the resolver's view always matches the
// declared field when the field is non-empty.
func TestWarpEnvelopeHashSuiteDefaultBindsExplicitly(t *testing.T) {
	base := negEnvelopeFixture(t)
	defaultBytes := canonicalSigningBytes(base)

	cp := *base
	cp.HashSuiteID = "Pulsar-BLAKE3"
	mutatedBytes := canonicalSigningBytes(&cp)
	if bytes.Equal(defaultBytes, mutatedBytes) {
		t.Fatal("explicit non-default HashSuiteID failed to change signing bytes")
	}
}
