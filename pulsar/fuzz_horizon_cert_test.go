// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Horizon certificate fuzz harness.
//
// Property anchor: proofs/quasar/horizon-soundness.tex
// Theorem ref:horizon-soundness.
//
// HorizonCertificate is the artifact a destination chain admits as
// "Horizon-final" once Prism has bound all three lanes (Beam, ML-DSA,
// Pulse) to the same source-chain transcript. Prism's structural
// invariant — every lane refracts from the same UnsignedMessageBytes
// transcript and the same lineage tuple (SourceChainID, KeyEraID,
// Generation, HashSuiteID) — must be losslessly serialisable.
//
// This harness exercises:
//
//  1. UnmarshalBinary on arbitrary bytes never panics. Malformed inputs
//     produce a clean error.
//  2. Marshal → Unmarshal round-trip on valid certificates is
//     byte-equal in both directions.
//  3. PrismVerify rejects tampered certs (lane bytes mutated, header
//     fields zeroed, etc.).
//  4. PrismVerify accepts well-formed certs.
//
// File path note: the task spec lists this as
// `~/work/lux/pulsar/reshare/fuzz_horizon_cert_test.go`, but
// HorizonCertificate is defined in github.com/luxfi/warp/pulsar (a
// downstream consumer of github.com/luxfi/pulsar). Placing the fuzz
// harness in pulsar/reshare would introduce an import cycle
// (warp/pulsar already imports pulsar; pulsar importing warp/pulsar
// closes the cycle). The harness lives here, beside the type it
// tests, with the proof anchor unchanged.

package pulsar

import (
	"bytes"
	"testing"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
)

// FuzzHorizonCertificate exercises Marshal / Unmarshal / PrismVerify
// against arbitrary inputs.
func FuzzHorizonCertificate(f *testing.F) {
	// Seed corpus: a fully-populated cert plus a Beam-only cert and
	// edge-case bytes.
	full := mustHorizonSeedFull()
	beamOnly := mustHorizonSeedBeamOnly()
	pulseOnly := mustHorizonSeedPulseOnly()

	f.Add(full)
	f.Add(beamOnly)
	f.Add(pulseOnly)
	f.Add([]byte{})
	f.Add([]byte("QUASAR-HORIZON-CERT-v1"))
	f.Add([]byte("QUASAR-HORIZON-CERT-v2"))
	// Truncated-just-past-prefix.
	f.Add(append([]byte("QUASAR-HORIZON-CERT-v1"), 0x00))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Property 1: Unmarshal never panics.
		var h HorizonCertificate
		err := h.UnmarshalBinary(raw)
		if err != nil {
			return
		}

		// Property 2: round-trip is byte-equal.
		out, err := h.MarshalBinary()
		if err != nil {
			t.Fatalf("re-marshal failed: %v", err)
		}
		if !bytes.Equal(out, raw) {
			// We do not require raw == out for ARBITRARY inputs — the
			// fuzzer may produce bytes that decode-then-re-encode to a
			// canonical form (e.g. trailing data could be silently
			// dropped). But our UnmarshalBinary returns an error on
			// trailing data; if we got here without error, the encoder
			// SHOULD reproduce raw.
			t.Fatalf("Marshal does not reproduce input bytes")
		}

		// Property 3: re-decoding the freshly marshalled bytes succeeds.
		var h2 HorizonCertificate
		if err := h2.UnmarshalBinary(out); err != nil {
			t.Fatalf("re-Unmarshal of own output failed: %v", err)
		}
		if h.SourceChainID != h2.SourceChainID ||
			h.SourceNebulaRoot != h2.SourceNebulaRoot ||
			h.SourceKeyEraID != h2.SourceKeyEraID ||
			h.SourceGeneration != h2.SourceGeneration ||
			h.HashSuiteID != h2.HashSuiteID {
			t.Fatalf("round-trip header mismatch")
		}
		if !bytesEqual(h.Beam, h2.Beam) ||
			!bytesEqual(h.MLDSACertSet, h2.MLDSACertSet) ||
			!bytesEqual(h.Pulse, h2.Pulse) ||
			!bytesEqual(h.UnsignedMessageBytes, h2.UnsignedMessageBytes) {
			t.Fatalf("round-trip lane bytes mismatch")
		}

		// Property 4: PrismVerify behaves consistently. We do not
		// assert it always succeeds (the fuzzer can produce certs
		// missing required fields), only that it never panics.
		_ = h.PrismVerify()
	})
}

// TestFuzzCorpus_HorizonReplay re-runs the seed corpus deterministically.
func TestFuzzCorpus_HorizonReplay(t *testing.T) {
	full := mustHorizonSeedFull()

	// Decode round trip.
	var h HorizonCertificate
	if err := h.UnmarshalBinary(full); err != nil {
		t.Fatalf("seed full: unmarshal failed: %v", err)
	}
	out, err := h.MarshalBinary()
	if err != nil {
		t.Fatalf("seed full: marshal failed: %v", err)
	}
	if !bytes.Equal(out, full) {
		t.Fatalf("seed full: round-trip not byte-equal")
	}

	// Prism check on a fully-populated cert MUST pass.
	if err := h.PrismVerify(); err != nil {
		t.Fatalf("seed full: PrismVerify rejected a well-formed cert: %v", err)
	}

	// Tampered cert: zero out SourceChainID. PrismVerify must reject.
	bad := h
	bad.SourceChainID = [32]byte{}
	if err := bad.PrismVerify(); err == nil {
		t.Fatalf("PrismVerify accepted a cert with zero SourceChainID")
	}

	// Tampered cert: zero UnsignedMessageBytes. PrismVerify must reject.
	bad2 := h
	bad2.UnsignedMessageBytes = nil
	if err := bad2.PrismVerify(); err == nil {
		t.Fatalf("PrismVerify accepted a cert with empty UnsignedMessageBytes")
	}

	// Tampered cert: empty all lanes. PrismVerify must reject.
	bad3 := h
	bad3.Beam = nil
	bad3.MLDSACertSet = nil
	bad3.Pulse = nil
	if err := bad3.PrismVerify(); err == nil {
		t.Fatalf("PrismVerify accepted a cert with no lanes populated")
	}
}

// mustHorizonSeedFull builds a fully-populated HorizonCertificate seed.
func mustHorizonSeedFull() []byte {
	const networkID = uint32(1)
	chainID := ids.ID{0xDE, 0xAD, 0xBE, 0xEF}
	payload := []byte("horizon-fuzz-seed")
	unsigned, err := warp.NewUnsignedMessage(networkID, chainID, payload)
	if err != nil {
		panic(err)
	}
	signers := warp.NewBitSet()
	signers.Add(0)
	var sig [bls.SignatureLen]byte
	copy(sig[:], bytes.Repeat([]byte{0xAB}, bls.SignatureLen))
	bsig := warp.NewBitSetSignature(signers, sig)
	msg, err := warp.NewMessage(unsigned, bsig)
	if err != nil {
		panic(err)
	}
	env := &warp.EnvelopeV2{
		Message:          msg,
		SourceKeyEraID:   7,
		SourceGeneration: 11,
		HashSuiteID:      warp.DefaultHashSuiteID,
		SourceNebulaRoot: [32]byte{0xC0, 0xDE},
		PulsarPulse:      bytes.Repeat([]byte{0x42}, 64),
		MLDSACertSet:     bytes.Repeat([]byte{0xC3}, 192),
	}
	h, err := HorizonFromEnvelope(env)
	if err != nil {
		panic(err)
	}
	out, err := h.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return out
}

// mustHorizonSeedBeamOnly returns a Beam-only HorizonCertificate seed.
func mustHorizonSeedBeamOnly() []byte {
	const networkID = uint32(1)
	chainID := ids.ID{0xC0, 0xDE}
	unsigned, err := warp.NewUnsignedMessage(networkID, chainID, []byte("beam-only"))
	if err != nil {
		panic(err)
	}
	signers := warp.NewBitSet()
	signers.Add(1)
	var sig [bls.SignatureLen]byte
	copy(sig[:], bytes.Repeat([]byte{0x55}, bls.SignatureLen))
	bsig := warp.NewBitSetSignature(signers, sig)
	msg, err := warp.NewMessage(unsigned, bsig)
	if err != nil {
		panic(err)
	}
	env := &warp.EnvelopeV2{
		Message:     msg,
		HashSuiteID: warp.DefaultHashSuiteID,
	}
	h, err := HorizonFromEnvelope(env)
	if err != nil {
		panic(err)
	}
	out, err := h.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return out
}

// mustHorizonSeedPulseOnly returns a Pulse-only HorizonCertificate seed.
// Beam is constructed minimally because the v1 Message always carries a
// signature; the Beam lane is "present but unused" by the destination
// when only the Pulse lane is required.
func mustHorizonSeedPulseOnly() []byte {
	const networkID = uint32(1)
	chainID := ids.ID{0xFA, 0xCE}
	unsigned, err := warp.NewUnsignedMessage(networkID, chainID, []byte("pulse-only"))
	if err != nil {
		panic(err)
	}
	signers := warp.NewBitSet()
	signers.Add(0)
	var sig [bls.SignatureLen]byte
	copy(sig[:], bytes.Repeat([]byte{0x77}, bls.SignatureLen))
	bsig := warp.NewBitSetSignature(signers, sig)
	msg, err := warp.NewMessage(unsigned, bsig)
	if err != nil {
		panic(err)
	}
	env := &warp.EnvelopeV2{
		Message:          msg,
		SourceKeyEraID:   3,
		SourceGeneration: 5,
		HashSuiteID:      warp.DefaultHashSuiteID,
		PulsarPulse:      bytes.Repeat([]byte{0x99}, 32),
	}
	h, err := HorizonFromEnvelope(env)
	if err != nil {
		panic(err)
	}
	out, err := h.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return out
}
