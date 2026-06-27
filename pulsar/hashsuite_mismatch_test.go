// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pulsar — HashSuite-mismatch tests for Warp envelope verification.
//
//  1. A Pulse signed under Pulsar-SHA3 verifies under Pulsar-SHA3.
//  2. The same envelope, verified while the receiver expects Pulsar-BLAKE3,
//     is rejected with ErrEnvelopeBadSuiteID.
//  3. A mutated HashSuiteID (tampered after signing, Pulse byte-identical)
//     MUST reject — D folds HashSuiteID, so the Pulse over the original D
//     no longer verifies under the mutated D.
package pulsar

import (
	"testing"

	"github.com/luxfi/warp"
	"github.com/stretchr/testify/require"
)

func TestVerifyAcceptsMatchingPulsarSHA3(t *testing.T) {
	env := envFixture(t, 7, 11)
	env.Core.HashSuiteID = warp.DefaultHashSuiteID
	signing := warp.PulseSigningBytes(env.Core.ID())

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializePulse(sig)
	require.NoError(t, err)
	env.PulseSig = pulse

	verifier := NewKernelVerifier(&stubResolver{gk: gk, suiteID: warp.DefaultHashSuiteID})
	opts := warp.VerifyOptions{
		SkipBeam:     true,
		Pulse:        verifier,
		RequirePulse: true,
		HashSuiteID:  warp.DefaultHashSuiteID,
	}
	require.NoError(t, warp.VerifyWithOptions(env, opts))
}

func TestVerifyRejectsExpectedSuiteMismatch(t *testing.T) {
	env := envFixture(t, 7, 11)
	env.Core.HashSuiteID = warp.DefaultHashSuiteID
	signing := warp.PulseSigningBytes(env.Core.ID())

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializePulse(sig)
	require.NoError(t, err)
	env.PulseSig = pulse

	verifier := NewKernelVerifier(&stubResolver{gk: gk, suiteID: warp.DefaultHashSuiteID})
	opts := warp.VerifyOptions{
		SkipBeam:     true,
		Pulse:        verifier,
		RequirePulse: true,
		HashSuiteID:  "Pulsar-BLAKE3", // receiver policy disagrees with the honest envelope
	}
	require.ErrorIs(t, warp.VerifyWithOptions(env, opts), warp.ErrEnvelopeBadSuiteID)
}

func TestVerifyRejectsMutatedHashSuiteIDPostSign(t *testing.T) {
	env := envFixture(t, 7, 11)
	env.Core.HashSuiteID = warp.DefaultHashSuiteID
	signing := warp.PulseSigningBytes(env.Core.ID())

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializePulse(sig)
	require.NoError(t, err)
	env.PulseSig = pulse

	// Round-trip through the wire, then mutate HashSuiteID and re-serialise
	// so the Pulse bytes are unchanged but the declared profile is swapped.
	wire, err := env.Bytes()
	require.NoError(t, err)
	parsed, err := warp.ParseEnvelope(wire)
	require.NoError(t, err)

	parsed.Core.HashSuiteID = "Pulsar-BLAKE3"
	mutatedWire, err := parsed.Bytes()
	require.NoError(t, err)
	mutated, err := warp.ParseEnvelope(mutatedWire)
	require.NoError(t, err)

	// Receiver AND resolver both expect "Pulsar-BLAKE3", so the string
	// checks pass. The kernel still rejects because D bound the original
	// "Pulsar-SHA3" suite.
	verifier := NewKernelVerifier(&stubResolver{gk: gk, suiteID: "Pulsar-BLAKE3"})
	opts := warp.VerifyOptions{
		SkipBeam:     true,
		Pulse:        verifier,
		RequirePulse: true,
		HashSuiteID:  "Pulsar-BLAKE3",
	}
	err = warp.VerifyWithOptions(mutated, opts)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPulseVerifyFailed)
}

func TestKernelVerifierRejectsHashSuiteFieldMutation(t *testing.T) {
	env := envFixture(t, 7, 11)
	env.Core.HashSuiteID = warp.DefaultHashSuiteID
	signing := warp.PulseSigningBytes(env.Core.ID())

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializePulse(sig)
	require.NoError(t, err)
	env.PulseSig = pulse

	// Mutate HashSuiteID after signing; Pulse stays unchanged.
	env.Core.HashSuiteID = "Pulsar-BLAKE3"

	verifier := NewKernelVerifier(&stubResolver{gk: gk, suiteID: "Pulsar-BLAKE3"})
	require.ErrorIs(t, verifier.VerifyPulse(env), ErrPulseVerifyFailed)
}
