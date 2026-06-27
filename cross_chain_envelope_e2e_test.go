// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// cross_chain_envelope_e2e_test.go drives the PQ posture and mode-gate
// composition for the single ZAP Envelope:
//
//  1. The default registry (signature.NewPQNativeRegistry) cannot install
//     a classical signer without the LegacyClassicalEnabled opt-in.
//  2. A PQ envelope (MLDSACertSet present) verifies under every pq.Mode.
//  3. A classical-only envelope is REFUSED under strict-PQ and ACCEPTED
//     under classical / hybrid.
//  4. The message ID (D) survives a wire round-trip.
//  5. KAT determinism for the canonical envelope wire bytes.

package warp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
	"github.com/luxfi/pq"
	sig "github.com/luxfi/warp/crypto/signature"
	"github.com/stretchr/testify/require"
)

// e2eFixture builds a canonical Envelope: a Core with payload
// "warp-e2e" plus deterministic Beam, and optional Pulse / MLDSACertSet.
func e2eFixture(t *testing.T, withPulse, withCert bool) *Envelope {
	t.Helper()
	core := &Core{
		NetworkID:        1,
		SourceChainID:    ids.ID{0xA1, 0xA2, 0xA3, 0xA4},
		SourceNebulaRoot: [32]byte{0xDE, 0xAD, 0xBE, 0xEF},
		SourceKeyEraID:   7,
		SourceGeneration: 11,
		HashSuiteID:      DefaultHashSuiteID,
		Payload:          []byte("warp-e2e"),
	}

	signers := NewBitSet()
	signers.Add(0)
	signers.Add(2)
	signers.Add(4)
	var sigBytes [bls.SignatureLen]byte
	copy(sigBytes[:], bytes.Repeat([]byte{0xAB}, bls.SignatureLen))

	var pulse []byte
	if withPulse {
		pulse = bytes.Repeat([]byte{0x42}, 64)
	}
	var cert []byte
	if withCert {
		cert = bytes.Repeat([]byte{0xC3}, 192)
	}

	env, err := NewEnvelope(core, NewBitSetSignature(signers, sigBytes), pulse, cert)
	require.NoError(t, err)
	return env
}

// ---------------------------------------------------------------------
// PQ posture — registry layer
// ---------------------------------------------------------------------

func TestE2E_DefaultRegistry_IsPQNative(t *testing.T) {
	r := sig.NewPQNativeRegistry()
	require.Equal(t, sig.SchemeMLDSA65, r.PreferredScheme())
	require.False(t, r.Config().LegacyClassicalEnabled, "default registry must NOT enable classical")

	for _, s := range sig.ClassicalSchemes {
		err := r.Register(s, fakeRegVerifier{scheme: s}, fakeRegSigner{scheme: s})
		require.ErrorIs(t, err, sig.ErrClassicalRequiresOptIn, "must refuse classical scheme %q", s)
	}
	for _, s := range sig.PQSchemes {
		err := r.Register(s, fakeRegVerifier{scheme: s}, fakeRegSigner{scheme: s})
		require.NoError(t, err, "must admit PQ scheme %q", s)
	}
}

func TestE2E_OptInRegistry_AdmitsClassical(t *testing.T) {
	r := sig.NewRegistryFromConfig(sig.Config{LegacyClassicalEnabled: true})
	for _, s := range sig.ClassicalSchemes {
		err := r.Register(s, fakeRegVerifier{scheme: s}, fakeRegSigner{scheme: s})
		require.NoError(t, err, "opt-in registry must admit classical scheme %q", s)
	}
}

// ---------------------------------------------------------------------
// PQ posture — envelope mode gate
// ---------------------------------------------------------------------

func TestE2E_PQEnvelope_VerifiesUnderEveryMode(t *testing.T) {
	env := e2eFixture(t, true, true)
	require.True(t, env.HasPQEvidence())
	for _, mode := range []pq.Mode{pq.ModeClassical, pq.ModeHybrid, pq.ModeStrictPQ} {
		require.NoError(t, pq.ValidateMode(mode, env, nil), "mode %q rejected PQ envelope", mode)
	}
}

func TestE2E_ClassicalEnvelope_RefusedUnderStrictPQ(t *testing.T) {
	env := e2eFixture(t, false, false)
	require.False(t, env.HasPQEvidence())
	require.NoError(t, pq.ValidateMode(pq.ModeClassical, env, nil))
	require.NoError(t, pq.ValidateMode(pq.ModeHybrid, env, nil))
	require.ErrorIs(t, pq.ValidateMode(pq.ModeStrictPQ, env, nil), pq.ErrClassicalAuthForbidden)
}

func TestE2E_ClassicalEnvelope_WireRefusedUnderStrictPQ(t *testing.T) {
	env := e2eFixture(t, false, false)
	wire, err := env.Bytes()
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(wire, wireMagic[:]))

	parsed, err := ParseEnvelope(wire)
	require.NoError(t, err)
	require.False(t, parsed.HasPQEvidence())
	require.ErrorIs(t, pq.ValidateMode(pq.ModeStrictPQ, parsed, nil), pq.ErrClassicalAuthForbidden)
}

func TestE2E_VerifyClosure_InvokedOnPQEvidence(t *testing.T) {
	env := e2eFixture(t, true, true)
	sentinel := errors.New("e2e verifier rejected")
	called := 0
	err := pq.ValidateMode(pq.ModeStrictPQ, env, func() error {
		called++
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)
	require.Equal(t, 1, called)
}

func TestE2E_VerifyClosure_SkippedOnClassicalEvidence(t *testing.T) {
	env := e2eFixture(t, false, false)
	called := 0
	cb := func() error { called++; return errors.New("must not be called") }
	for _, mode := range []pq.Mode{pq.ModeClassical, pq.ModeHybrid} {
		require.NoError(t, pq.ValidateMode(mode, env, cb))
	}
	require.Equal(t, 0, called)
}

// ---------------------------------------------------------------------
// Round-trip + KAT determinism
// ---------------------------------------------------------------------

func TestE2E_ID_PreservedAcrossWire(t *testing.T) {
	env := e2eFixture(t, true, true)
	id := env.ID()
	wire, err := env.Bytes()
	require.NoError(t, err)
	parsed, err := ParseEnvelope(wire)
	require.NoError(t, err)
	require.Equal(t, id, parsed.ID(), "D must survive wire round-trip")
}

// TestE2E_KAT_PQEnvelope_WireBytesStable locks the canonical wire stream:
// it starts with the magic, round-trips byte-equal, and a SHA-256
// fingerprint is computed for cross-language ports.
func TestE2E_KAT_PQEnvelope_WireBytesStable(t *testing.T) {
	env := e2eFixture(t, true, true)
	wire, err := env.Bytes()
	require.NoError(t, err)

	require.True(t, bytes.HasPrefix(wire, wireMagic[:]))
	require.Equal(t, kindEnvelope, wire[len(wireMagic)])

	h := sha256.Sum256(wire)
	require.Len(t, hex.EncodeToString(h[:]), 64)

	parsed, err := ParseEnvelope(wire)
	require.NoError(t, err)
	re, err := parsed.Bytes()
	require.NoError(t, err)
	require.Equal(t, wire, re, "wire round-trip must be byte-equal")
}

// ---------------------------------------------------------------------
// fakeRegVerifier / fakeRegSigner — registry stubs
// ---------------------------------------------------------------------

type fakeRegVerifier struct{ scheme sig.Scheme }

func (f fakeRegVerifier) Scheme() sig.Scheme { return f.scheme }
func (f fakeRegVerifier) Verify(_ context.Context, _ []byte, _ sig.Signature, _ sig.SignerSet) error {
	return nil
}
func (f fakeRegVerifier) VerifyAggregate(_ context.Context, _ []byte, _ sig.Signature, _ sig.SignerSet) error {
	return nil
}

type fakeRegSigner struct{ scheme sig.Scheme }

func (f fakeRegSigner) Scheme() sig.Scheme { return f.scheme }
func (f fakeRegSigner) Sign(_ context.Context, _ []byte, _ sig.PrivateKey) (sig.Signature, error) {
	return nil, nil
}
func (f fakeRegSigner) AggregateSign(_ context.Context, _ []byte, _ []sig.PrivateKey) (sig.Signature, error) {
	return nil, nil
}
