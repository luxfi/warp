// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pulsar — Gate 3D HashSuite-mismatch tests for Warp 2.0
// envelope verification (Mar-3-2026 PQ Consensus Architecture Freeze).
//
// These tests exercise the receiver-side hash-suite check on Warp 2.0
// envelopes:
//
//   1. A Pulse signed under Pulsar-SHA3 verifies under Pulsar-SHA3.
//   2. The same envelope verified while the receiver expects
//      Pulsar-BLAKE3 is rejected with the canonical
//      ErrEnvelopeBadSuiteID error.
//   3. A receiver who sees a mutated HashSuiteID (the field on the
//      envelope is tampered AFTER signing, then re-serialised, with
//      the Pulse byte-identical) MUST reject — the Pulse transcript
//      binds HashSuiteID, so the kernel rejects on signature verify
//      even before the receiver-side string-equality check fires.
//
// Citations (canonical proof bucket):
//
//   proofs/pulsar/hash-suite-separation.tex
//     Theorem ref:hash-suite-separation
//   proofs/definitions/transcript-binding.tex
//     Definition ref:pulsar-transcript and Definition ref:warp-v2-envelope
package pulsar

import (
	"testing"

	"github.com/luxfi/warp"
	"github.com/stretchr/testify/require"
)

// TestVerifyV2AcceptsMatchingPulsarSHA3 — a Warp 2.0 envelope with
// HashSuiteID="Pulsar-SHA3" and a real Pulse over its transcript
// verifies cleanly when the receiver expects Pulsar-SHA3.
func TestVerifyV2AcceptsMatchingPulsarSHA3(t *testing.T) {
	env, _ := envFixture(t, 7, 11)
	env.HashSuiteID = warp.DefaultHashSuiteID
	msgBytes := env.Message.UnsignedMessage.Bytes()
	signing := BuildSigningBytes(env, msgBytes)

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializePulse(sig)
	require.NoError(t, err)
	env.PulsarPulse = pulse

	verifier := NewKernelVerifier(&stubResolver{gk: gk, suiteID: warp.DefaultHashSuiteID})
	opts := warp.VerifyV2Options{
		SkipBeam:     true,
		Pulse:        verifier,
		RequirePulse: true,
		HashSuiteID:  warp.DefaultHashSuiteID,
	}
	require.NoError(t, warp.VerifyV2(env, opts))
}

// TestVerifyV2RejectsExpectedSuiteMismatch — the same envelope
// verified while the RECEIVER expects "Pulsar-BLAKE3" must be rejected
// with the canonical ErrEnvelopeBadSuiteID. The envelope itself is
// honest; the receiver's policy disagrees.
func TestVerifyV2RejectsExpectedSuiteMismatch(t *testing.T) {
	env, _ := envFixture(t, 7, 11)
	env.HashSuiteID = warp.DefaultHashSuiteID
	msgBytes := env.Message.UnsignedMessage.Bytes()
	signing := BuildSigningBytes(env, msgBytes)

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializePulse(sig)
	require.NoError(t, err)
	env.PulsarPulse = pulse

	verifier := NewKernelVerifier(&stubResolver{gk: gk, suiteID: warp.DefaultHashSuiteID})
	opts := warp.VerifyV2Options{
		SkipBeam:     true,
		Pulse:        verifier,
		RequirePulse: true,
		// Receiver expects the legacy profile; envelope declares
		// production. VerifyV2 fires ErrEnvelopeBadSuiteID before any
		// PQ-lane verification runs.
		HashSuiteID: "Pulsar-BLAKE3",
	}
	err = warp.VerifyV2(env, opts)
	require.ErrorIs(t, err, warp.ErrEnvelopeBadSuiteID)
}

// TestVerifyV2RejectsMutatedHashSuiteIDPostSign — the envelope is
// signed with HashSuiteID="Pulsar-SHA3", a real Pulse is bound, the
// envelope is re-serialised, and then the HashSuiteID field is
// MUTATED (re-encoded) to "Pulsar-BLAKE3" while the Pulse stays
// byte-identical. Even if the receiver expects "Pulsar-BLAKE3" — i.e.
// the receiver-side string-equality check passes — the kernel
// verification must reject because BuildSigningBytes binds the
// HashSuiteID into the transcript that the threshold signature
// covers.
func TestVerifyV2RejectsMutatedHashSuiteIDPostSign(t *testing.T) {
	env, _ := envFixture(t, 7, 11)
	env.HashSuiteID = warp.DefaultHashSuiteID
	msgBytes := env.Message.UnsignedMessage.Bytes()
	signing := BuildSigningBytes(env, msgBytes)

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializePulse(sig)
	require.NoError(t, err)
	env.PulsarPulse = pulse

	// Round-trip the envelope through the wire so we are testing the
	// re-serialised bytes, not a Go-only mutation.
	wire, err := env.Bytes()
	require.NoError(t, err)
	parsed, err := warp.ParseEnvelopeV2(wire)
	require.NoError(t, err)

	// Mutate HashSuiteID after signing. Re-serialise and re-parse so
	// the Pulse bytes are unchanged but the envelope's declared profile
	// has been swapped.
	parsed.HashSuiteID = "Pulsar-BLAKE3"
	mutatedWire, err := parsed.Bytes()
	require.NoError(t, err)
	mutated, err := warp.ParseEnvelopeV2(mutatedWire)
	require.NoError(t, err)

	verifier := NewKernelVerifier(&stubResolver{gk: gk, suiteID: "Pulsar-BLAKE3"})
	// Receiver expects "Pulsar-BLAKE3" — same as the envelope's mutated
	// declaration — so the receiver-side string-equality check passes.
	// The kernel still rejects because the signed transcript bound the
	// original "Pulsar-SHA3" HashSuiteID.
	opts := warp.VerifyV2Options{
		SkipBeam:     true,
		Pulse:        verifier,
		RequirePulse: true,
		HashSuiteID:  "Pulsar-BLAKE3",
	}
	err = warp.VerifyV2(mutated, opts)
	require.Error(t, err)
	// The kernel's rejection surfaces through verifyPQLanes wrapping
	// the kernel error; assert it is the kernel-rejection error (not
	// the receiver-side ErrEnvelopeBadSuiteID).
	require.ErrorIs(t, err, ErrPulseVerifyFailed)
}

// TestKernelVerifierRejectsHashSuiteFieldMutation — direct kernel-side
// test of the same property: mutate the envelope's HashSuiteID after
// signing, keep the Pulse, and call VerifyPulse directly. The
// transcript binding catches it.
func TestKernelVerifierRejectsHashSuiteFieldMutation(t *testing.T) {
	env, _ := envFixture(t, 7, 11)
	env.HashSuiteID = warp.DefaultHashSuiteID
	msgBytes := env.Message.UnsignedMessage.Bytes()
	signing := BuildSigningBytes(env, msgBytes)

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializePulse(sig)
	require.NoError(t, err)
	env.PulsarPulse = pulse

	// Mutate HashSuiteID after signing. The Pulse stays unchanged.
	env.HashSuiteID = "Pulsar-BLAKE3"

	// Resolver agrees with the mutated declaration so the suite-mismatch
	// short-circuit does not fire — the only thing that can reject is
	// the kernel's transcript-binding check.
	verifier := NewKernelVerifier(&stubResolver{gk: gk, suiteID: "Pulsar-BLAKE3"})
	err = verifier.VerifyPulse(env, msgBytes)
	require.ErrorIs(t, err, ErrPulseVerifyFailed)
}
