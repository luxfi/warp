// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pulsar — message-tag policy + D-binding tests for Quasar envelope
// verification. NOTE: the message-level HashSuiteID tag (here "Pulsar-SHA3")
// is the GENERIC c14n tag, decoupled from the Corona lane suite (the resolver
// returns warp.DefaultCoronaSuiteID).
//
//  1. A corona signature over a "Pulsar-SHA3"-tagged message verifies when
//     the receiver's message-tag policy also expects "Pulsar-SHA3".
//  2. The same envelope, verified while the receiver's message-tag policy
//     expects "Pulsar-BLAKE3", is rejected with ErrEnvelopeBadSuiteID.
//  3. A mutated HashSuiteID (tampered after signing, corona sig byte-identical)
//     MUST reject — D folds HashSuiteID, so the corona sig over the original D
//     no longer verifies under the mutated D.
package pulsar

import (
	"testing"

	"github.com/luxfi/warp"
	"github.com/stretchr/testify/require"
)

func TestVerifyAcceptsMatchingPulsarSHA3(t *testing.T) {
	env := envFixture(t, 7, 11)
	env.Message.HashSuiteID = warp.MessageHashProfileTag
	signing := warp.CoronaSigningBytes(env.Message.ID())

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializeCoronaSig(sig)
	require.NoError(t, err)
	env.CoronaSig = pulse

	verifier := NewRingtailVerifier(&stubResolver{gk: gk, suiteID: string(warp.DefaultCoronaSuiteID)})
	opts := warp.VerifyOptions{
		SkipBeam:     true,
		Corona:        verifier,
		RequireCorona: true,
		HashSuiteID:  warp.MessageHashProfileTag,
	}
	require.NoError(t, warp.VerifyWithOptions(env, opts))
}

func TestVerifyRejectsExpectedSuiteMismatch(t *testing.T) {
	env := envFixture(t, 7, 11)
	env.Message.HashSuiteID = warp.MessageHashProfileTag
	signing := warp.CoronaSigningBytes(env.Message.ID())

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializeCoronaSig(sig)
	require.NoError(t, err)
	env.CoronaSig = pulse

	verifier := NewRingtailVerifier(&stubResolver{gk: gk, suiteID: string(warp.DefaultCoronaSuiteID)})
	opts := warp.VerifyOptions{
		SkipBeam:     true,
		Corona:        verifier,
		RequireCorona: true,
		HashSuiteID:  "Pulsar-BLAKE3", // receiver policy disagrees with the honest envelope
	}
	require.ErrorIs(t, warp.VerifyWithOptions(env, opts), warp.ErrEnvelopeBadSuiteID)
}

func TestVerifyRejectsMutatedHashSuiteIDPostSign(t *testing.T) {
	env := envFixture(t, 7, 11)
	env.Message.HashSuiteID = warp.MessageHashProfileTag
	signing := warp.CoronaSigningBytes(env.Message.ID())

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializeCoronaSig(sig)
	require.NoError(t, err)
	env.CoronaSig = pulse

	// Round-trip through the wire, then mutate HashSuiteID and re-serialise
	// so the Pulse bytes are unchanged but the declared profile is swapped.
	wire, err := env.Bytes()
	require.NoError(t, err)
	parsed, err := warp.ParseEnvelope(wire)
	require.NoError(t, err)

	parsed.Message.HashSuiteID = "Pulsar-BLAKE3"
	mutatedWire, err := parsed.Bytes()
	require.NoError(t, err)
	mutated, err := warp.ParseEnvelope(mutatedWire)
	require.NoError(t, err)

	// Receiver's message-tag policy expects "Pulsar-BLAKE3" (matching the
	// mutated envelope tag) and the corona resolver returns the Corona
	// suite, so BOTH the message-tag and corona-suite checks pass. The
	// kernel still rejects because D bound the original "Pulsar-SHA3" tag.
	verifier := NewRingtailVerifier(&stubResolver{gk: gk, suiteID: string(warp.DefaultCoronaSuiteID)})
	opts := warp.VerifyOptions{
		SkipBeam:     true,
		Corona:        verifier,
		RequireCorona: true,
		HashSuiteID:  "Pulsar-BLAKE3",
	}
	err = warp.VerifyWithOptions(mutated, opts)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCoronaVerifyFailed)
}

func TestRingtailVerifierRejectsHashSuiteFieldMutation(t *testing.T) {
	env := envFixture(t, 7, 11)
	env.Message.HashSuiteID = warp.MessageHashProfileTag
	signing := warp.CoronaSigningBytes(env.Message.ID())

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializeCoronaSig(sig)
	require.NoError(t, err)
	env.CoronaSig = pulse

	// Mutate HashSuiteID after signing; Pulse stays unchanged.
	env.Message.HashSuiteID = "Pulsar-BLAKE3"

	verifier := NewRingtailVerifier(&stubResolver{gk: gk, suiteID: string(warp.DefaultCoronaSuiteID)})
	require.ErrorIs(t, verifier.VerifyRingtailThreshold(coronaInputs(env)), ErrCoronaVerifyFailed)
}
