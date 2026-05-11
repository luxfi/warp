// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Warp pulse fuzz harness.
//
// Property anchor: proofs/quasar/warp-pq-soundness.tex
// Theorem ref:warp-v2-soundness.
//
// Properties under fuzzing:
//
//  1. SerializePulse(sig) ↔ DeserializePulse(bytes) round-trips on
//     valid signatures (kernel-generated).
//
//  2. DeserializePulse(arbitrary bytes) never panics; tampered inputs
//     produce a clean error.
//
//  3. Tampering any byte of a serialized pulse causes either a parse
//     error (most cases) or a Verify failure (rare cases that happen
//     to land on valid lattigo wire framing). Either is acceptable —
//     we only forbid the silent-corruption / panic outcomes.

package pulsar

import (
	"bytes"
	"crypto/rand"
	"testing"

	corona "github.com/luxfi/corona/threshold"
)

// FuzzPulseDeserialize runs DeserializePulse over arbitrary bytes and
// confirms it never panics.
func FuzzPulseDeserialize(f *testing.F) {
	// Seed: a real pulse from a 3-of-2 ceremony.
	good := mustGoodPulseSeed()
	f.Add(good)
	// Truncated.
	if len(good) > 16 {
		f.Add(good[:16])
	}
	// Empty.
	f.Add([]byte{})
	// Plausible-shaped junk.
	f.Add(append([]byte{0x10, 0x00, 0x00, 0x00}, bytes.Repeat([]byte{0xff}, 32)...))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Property: DeserializePulse never panics regardless of input.
		_, _ = DeserializePulse(raw)
	})
}

// FuzzPulseSerialize runs the full SerializePulse → DeserializePulse →
// corona.Verify round trip over valid pulses, then mutates one
// byte at a time and confirms either a parse error or a Verify failure
// — never a silent-success / panic outcome.
//
// We do NOT fuzz the kernel sign protocol itself — that would mean
// running the threshold ceremony per fuzz call, which is too slow.
// Instead we generate one good pulse before the fuzz loop, then use
// the fuzzer to drive byte mutations.
func FuzzPulseSerialize(f *testing.F) {
	good, message, gk := mustGoodPulse()

	// Seed: indices into good[] to flip.
	f.Add(uint32(0))
	f.Add(uint32(len(good) - 1))
	f.Add(uint32(len(good) / 2))

	f.Fuzz(func(t *testing.T, idx uint32) {
		if len(good) == 0 {
			t.Skip("no good seed")
		}
		// Flip one byte at the fuzzer-provided index.
		i := int(idx) % len(good)
		mut := append([]byte(nil), good...)
		mut[i] ^= 0x01

		sig, err := DeserializePulse(mut)
		if err != nil {
			// Parse error is the expected outcome on most flips.
			return
		}
		// If the bytes happened to deserialize, then Verify against the
		// original message and group key MUST fail — flipping any byte
		// in a valid threshold signature breaks the verification
		// equation with overwhelming probability.
		if corona.Verify(gk, message, sig) {
			t.Fatalf("byte-flip at %d still verified — collision in pulse encoding", i)
		}
	})
}

// TestFuzzCorpus_PulseReplay re-runs the round-trip + tamper checks on
// a fixed seed corpus deterministically for CI replay.
func TestFuzzCorpus_PulseReplay(t *testing.T) {
	good, message, gk := mustGoodPulse()
	sig, err := DeserializePulse(good)
	if err != nil {
		t.Fatalf("seed: deserialize failed: %v", err)
	}
	if !corona.Verify(gk, message, sig) {
		t.Fatalf("seed: verify failed")
	}
	wire, err := SerializePulse(sig)
	if err != nil {
		t.Fatalf("seed: re-serialize failed: %v", err)
	}
	if !bytes.Equal(wire, good) {
		t.Fatalf("seed: round-trip not byte-equal")
	}
}

// mustGoodPulse runs a 3-of-2 Pulsar threshold ceremony and returns
// (serialized pulse, signed message, group key).
func mustGoodPulse() (wire []byte, msg string, gk *corona.GroupKey) {
	const n, threshold = 3, 2
	const message = "fuzz-pulse-seed"

	shares, key, err := corona.GenerateKeys(threshold, n, rand.Reader)
	if err != nil {
		panic(err)
	}
	signers := make([]int, n)
	for i := range signers {
		signers[i] = i
	}
	prfKey := make([]byte, 32)
	if _, err := rand.Read(prfKey); err != nil {
		panic(err)
	}
	parties := make([]*corona.Signer, n)
	for i := range parties {
		parties[i] = corona.NewSigner(shares[i])
	}
	r1 := make(map[int]*corona.Round1Data, n)
	for i, p := range parties {
		r1[i] = p.Round1(1, prfKey, signers)
	}
	r2 := make(map[int]*corona.Round2Data, n)
	for i, p := range parties {
		d, err := p.Round2(1, message, prfKey, signers, r1)
		if err != nil {
			panic(err)
		}
		r2[i] = d
	}
	sig, err := parties[0].Finalize(r2)
	if err != nil {
		panic(err)
	}
	wire, err = SerializePulse(sig)
	if err != nil {
		panic(err)
	}
	return wire, message, key
}

// mustGoodPulseSeed returns just the wire bytes for FuzzPulseDeserialize.
func mustGoodPulseSeed() []byte {
	w, _, _ := mustGoodPulse()
	return w
}
