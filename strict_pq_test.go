// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// strict_pq_test.go is the strict-PQ posture's contract test. It
// extends security_profile_test.go (which pins the gate predicates)
// with cross-layer integration: how the chain's pq.Mode interacts
// with the signature registry's Config.LegacyClassicalEnabled flag
// to deliver "PQ default, classical opt-in" end to end.
//
// The five strict-PQ invariants pinned here:
//
//  1. ModeStrictPQ + classical-only envelope = ErrClassicalAuthForbidden.
//  2. ModeStrictPQ + PQ envelope = accept (PQ evidence is the trust root).
//  3. The default signature registry (NewPQNativeRegistry) cannot
//     install a classical scheme without an explicit opt-in.
//  4. A registry with LegacyClassicalEnabled=true CAN install a
//     classical scheme but the chain-mode gate still refuses the
//     resulting classical envelope under strict-PQ — registry
//     posture is independent of chain posture (decomplected).
//  5. The mode<->registry pairing recommended for each profile.
//
// Together these test that "classical is opt-in" holds at BOTH the
// registry layer (Config.LegacyClassicalEnabled) and the chain
// layer (pq.Mode). Either gate alone would be insufficient.

package warp

import (
	"context"
	"testing"

	"github.com/luxfi/pq"
	sig "github.com/luxfi/warp/crypto/signature"
	"github.com/stretchr/testify/require"
)

// strictPQEnv builds an envelope WITHOUT MLDSACertSet — the
// canonical "classical-only" envelope the strict-PQ gate refuses.
func strictPQEnvClassicalOnly(t *testing.T) *EnvelopeV2 {
	t.Helper()
	return e2eFixture(t, false, false)
}

// strictPQEnvWithPQ builds an envelope WITH MLDSACertSet — the
// canonical "PQ-evidenced" envelope that verifies under every mode.
func strictPQEnvWithPQ(t *testing.T) *EnvelopeV2 {
	t.Helper()
	return e2eFixture(t, true, true)
}

// TestStrictPQ_ClassicalEnvelope_Refused pins invariant (1).
func TestStrictPQ_ClassicalEnvelope_Refused(t *testing.T) {
	env := strictPQEnvClassicalOnly(t)
	err := pq.ValidateMode(pq.ModeStrictPQ, env, nil)
	require.ErrorIs(t, err, pq.ErrClassicalAuthForbidden,
		"strict-PQ accepted classical-only envelope")
}

// TestStrictPQ_PQEnvelope_Accepted pins invariant (2).
func TestStrictPQ_PQEnvelope_Accepted(t *testing.T) {
	env := strictPQEnvWithPQ(t)
	err := pq.ValidateMode(pq.ModeStrictPQ, env, nil)
	require.NoError(t, err, "strict-PQ refused PQ envelope")
}

// TestStrictPQ_DefaultRegistry_ClassicalOptInRequired pins
// invariant (3): the registry's PQ-native default refuses to
// install a classical scheme.
func TestStrictPQ_DefaultRegistry_ClassicalOptInRequired(t *testing.T) {
	r := sig.NewPQNativeRegistry()
	verifier := stubVerifier{scheme: sig.SchemeBLS}
	signer := stubSigner{scheme: sig.SchemeBLS}
	err := r.Register(sig.SchemeBLS, verifier, signer)
	require.ErrorIs(t, err, sig.ErrClassicalRequiresOptIn,
		"PQ-native registry admitted BLS without LegacyClassicalEnabled")
}

// TestStrictPQ_OptInRegistryStillRefusedAtModeGate pins invariant (4):
// even when the registry has classical opt-in enabled and successfully
// installs BLS, the chain-mode gate STILL refuses the resulting
// classical envelope under strict-PQ. Posture is decomplected:
// registry posture (which schemes are installable) is orthogonal to
// chain posture (which schemes the chain trusts).
func TestStrictPQ_OptInRegistryStillRefusedAtModeGate(t *testing.T) {
	// Registry has classical opt-in.
	r := sig.NewRegistryFromConfig(sig.Config{LegacyClassicalEnabled: true})
	err := r.Register(sig.SchemeBLS, stubVerifier{scheme: sig.SchemeBLS}, stubSigner{scheme: sig.SchemeBLS})
	require.NoError(t, err, "opt-in registry must admit BLS")

	// Chain is strict-PQ. The envelope arrives with no MLDSACertSet.
	env := strictPQEnvClassicalOnly(t)
	gateErr := pq.ValidateMode(pq.ModeStrictPQ, env, nil)
	require.ErrorIs(t, gateErr, pq.ErrClassicalAuthForbidden,
		"strict-PQ chain accepted classical envelope even though registry has opt-in")
}

// TestStrictPQ_RecommendedPairings pins invariant (5): the
// canonical pairings of pq.Mode and Config.LegacyClassicalEnabled.
//
//	mode         | LegacyClassicalEnabled | notes
//	-------------|------------------------|-----------------------------
//	classical    | true                   | legacy chain; PQ unused
//	hybrid       | true                   | migration middle; both lanes
//	strict-pq    | false                  | canonical Liquid default
//
// strict-pq with LegacyClassicalEnabled=true is REDUNDANT but not
// incorrect — the registry still installs BLS, but the mode gate
// refuses classical envelopes anyway. The test asserts the gate
// outcome for each pairing on the same envelope set.
func TestStrictPQ_RecommendedPairings(t *testing.T) {
	type pairing struct {
		mode    pq.Mode
		legacy  bool
		envHasPQ bool
		want    error // pq.ErrClassicalAuthForbidden, or nil
	}
	cases := []pairing{
		// Canonical Liquid strict-PQ default.
		{pq.ModeStrictPQ, false, true, nil},
		{pq.ModeStrictPQ, false, false, pq.ErrClassicalAuthForbidden},

		// Strict-PQ with redundant opt-in.
		{pq.ModeStrictPQ, true, true, nil},
		{pq.ModeStrictPQ, true, false, pq.ErrClassicalAuthForbidden},

		// Hybrid: accepts both.
		{pq.ModeHybrid, true, true, nil},
		{pq.ModeHybrid, true, false, nil},

		// Classical: ignores PQ evidence (still accepts both at the gate).
		{pq.ModeClassical, true, true, nil},
		{pq.ModeClassical, true, false, nil},
	}

	for _, tc := range cases {
		t.Run(tc.mode.String(), func(t *testing.T) {
			r := sig.NewRegistryFromConfig(sig.Config{LegacyClassicalEnabled: tc.legacy})
			// The registry's gate is independent of the mode's gate;
			// we just confirm it accepts/refuses BLS install per the flag.
			err := r.Register(sig.SchemeBLS,
				stubVerifier{scheme: sig.SchemeBLS},
				stubSigner{scheme: sig.SchemeBLS})
			if tc.legacy {
				require.NoError(t, err, "legacy=true must admit BLS install")
			} else {
				require.ErrorIs(t, err, sig.ErrClassicalRequiresOptIn,
					"legacy=false must refuse BLS install")
			}

			env := e2eFixture(t, tc.envHasPQ, tc.envHasPQ)
			gateErr := pq.ValidateMode(tc.mode, env, nil)
			if tc.want == nil {
				require.NoError(t, gateErr,
					"mode=%s legacy=%t hasPQ=%t: unexpected gate error",
					tc.mode, tc.legacy, tc.envHasPQ)
			} else {
				require.ErrorIs(t, gateErr, tc.want,
					"mode=%s legacy=%t hasPQ=%t: gate error mismatch",
					tc.mode, tc.legacy, tc.envHasPQ)
			}
		})
	}
}

// TestStrictPQ_LegacyClassicalFlag_Documented confirms the wire-stable
// names of the opt-in flag. Renaming Config.LegacyClassicalEnabled
// would break every operator-facing chain config.
func TestStrictPQ_LegacyClassicalFlag_Documented(t *testing.T) {
	cfg := sig.Config{LegacyClassicalEnabled: true}
	require.True(t, cfg.LegacyClassicalEnabled,
		"field name 'LegacyClassicalEnabled' must remain stable")
}

// TestStrictPQ_DefaultIsPQAware confirms the runtime check used by
// audit pipelines: a chain pinned strict-PQ reports IsPostQuantum=true
// AND IsPQAware=true. Other modes split these.
func TestStrictPQ_DefaultIsPQAware(t *testing.T) {
	require.True(t, pq.ModeStrictPQ.IsPostQuantum(), "strict-PQ must be IsPostQuantum")
	require.True(t, pq.ModeStrictPQ.IsPQAware(), "strict-PQ must be IsPQAware")

	require.False(t, pq.ModeHybrid.IsPostQuantum(), "hybrid must NOT be IsPostQuantum")
	require.True(t, pq.ModeHybrid.IsPQAware(), "hybrid must be IsPQAware")

	require.False(t, pq.ModeClassical.IsPostQuantum(), "classical must NOT be IsPostQuantum")
	require.False(t, pq.ModeClassical.IsPQAware(), "classical must NOT be IsPQAware")
}

// stubVerifier / stubSigner are the minimal Verifier / Signer types
// used by the strict-PQ tests. Mirrors fakeRegVerifier in
// cross_chain_envelope_e2e_test.go but kept local so that file is
// the single source-of-truth for posture e2e plumbing.
type stubVerifier struct{ scheme sig.Scheme }

func (s stubVerifier) Scheme() sig.Scheme { return s.scheme }
func (s stubVerifier) Verify(_ context.Context, _ []byte, _ sig.Signature, _ sig.SignerSet) error {
	return nil
}
func (s stubVerifier) VerifyAggregate(_ context.Context, _ []byte, _ sig.Signature, _ sig.SignerSet) error {
	return nil
}

type stubSigner struct{ scheme sig.Scheme }

func (s stubSigner) Scheme() sig.Scheme { return s.scheme }
func (s stubSigner) Sign(_ context.Context, _ []byte, _ sig.PrivateKey) (sig.Signature, error) {
	return nil, nil
}
func (s stubSigner) AggregateSign(_ context.Context, _ []byte, _ []sig.PrivateKey) (sig.Signature, error) {
	return nil, nil
}
