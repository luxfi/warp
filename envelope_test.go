// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"bytes"
	"errors"
	"testing"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

// envelopeFixture builds a fully-populated Envelope for envelope tests.
func envelopeFixture(t *testing.T) *Envelope {
	t.Helper()
	message := &Message{
		NetworkID:        1,
		SourceChainID:    ids.ID{0xA1, 0xA2, 0xA3, 0xA4},
		SourceNebulaRoot: [32]byte{0xDE, 0xAD, 0xBE, 0xEF},
		SourceKeyEraID:   7,
		SourceGeneration: 11,
		HashSuiteID:      MessageHashProfileTag,
		Payload:          []byte("envelope-test-payload"),
	}

	signers := NewBitSet()
	signers.Add(0)
	signers.Add(2)
	signers.Add(4)

	var sigBytes [bls.SignatureLen]byte
	copy(sigBytes[:], bytes.Repeat([]byte{0xAB}, bls.SignatureLen))

	env, err := NewEnvelope(message, NewBitSetSignature(signers, sigBytes), nil, nil)
	require.NoError(t, err)
	return env
}

func TestEnvelopeRoundTrip(t *testing.T) {
	env := envelopeFixture(t)
	env.CoronaSig = bytes.Repeat([]byte{0x42}, 64)
	env.MLDSACertSet = bytes.Repeat([]byte{0xC3}, 192)

	require.NoError(t, env.Verify())
	require.True(t, env.HasCorona())
	require.True(t, env.HasMLDSACertSet())

	wire, err := env.Bytes()
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(wire, wireMagic[:]), "wire must start with magic")
	require.Equal(t, kindEnvelope, wire[len(wireMagic)])

	parsed, err := ParseEnvelope(wire)
	require.NoError(t, err)
	require.Equal(t, env.Message.SourceKeyEraID, parsed.Message.SourceKeyEraID)
	require.Equal(t, env.Message.SourceGeneration, parsed.Message.SourceGeneration)
	require.Equal(t, env.Message.SourceNebulaRoot, parsed.Message.SourceNebulaRoot)
	require.Equal(t, env.Message.HashSuiteID, parsed.Message.HashSuiteID)
	require.Equal(t, env.CoronaSig, parsed.CoronaSig)
	require.Equal(t, env.MLDSACertSet, parsed.MLDSACertSet)
	require.True(t, env.Beam.Equal(parsed.Beam))
	require.Equal(t, env.ID(), parsed.ID())
	require.True(t, env.Equal(parsed))

	// Re-encode is byte-stable.
	re, err := parsed.Bytes()
	require.NoError(t, err)
	require.Equal(t, wire, re)
}

func TestEnvelopeEmptyOptionalLanes(t *testing.T) {
	env := envelopeFixture(t)
	require.NoError(t, env.Verify())
	require.False(t, env.HasCorona())
	require.False(t, env.HasMLDSACertSet())

	wire, err := env.Bytes()
	require.NoError(t, err)

	parsed, err := ParseEnvelope(wire)
	require.NoError(t, err)
	require.Empty(t, parsed.CoronaSig)
	require.Empty(t, parsed.MLDSACertSet)
	require.True(t, env.Beam.Equal(parsed.Beam))
}

func TestParseEnvelopeRejectsEmpty(t *testing.T) {
	_, err := ParseEnvelope(nil)
	require.ErrorIs(t, err, ErrEnvelopeEmpty)
}

// TestParseEnvelopeRejectsLegacyRLP is the two-barrier replay check at
// the magic level: an old RLP-shaped Beam (lead byte 0xc0..0xff) and the
// legacy 0x02 envelope byte are both rejected before any field is read.
func TestParseEnvelopeRejectsLegacyRLP(t *testing.T) {
	for _, lead := range []byte{0xc0, 0xf8, 0xff, 0x02} {
		body := append([]byte{lead}, bytes.Repeat([]byte{0x00}, 64)...)
		_, err := ParseEnvelope(body)
		require.ErrorIs(t, err, errZapBadMagic, "lead 0x%02x must be rejected at magic", lead)
	}
}

func TestParseEnvelopeRejectsTrailingBytes(t *testing.T) {
	env := envelopeFixture(t)
	wire, err := env.Bytes()
	require.NoError(t, err)
	_, err = ParseEnvelope(append(wire, 0xff))
	require.ErrorIs(t, err, errZapTrailing)
}

// TestParseEnvelopeRejectsNonCanonicalBitset proves a Signers bitset
// with a trailing zero byte is rejected on decode (canonical-form rule 6).
func TestParseEnvelopeRejectsNonCanonicalBitset(t *testing.T) {
	env := envelopeFixture(t)
	wire, err := env.Bytes()
	require.NoError(t, err)

	// Hand-craft an envelope wire with a trailing-zero Signers bitset.
	message := env.Message.marshalZAP()
	var out []byte
	out = append(out, wireMagic[:]...)
	out = appendU8(out, kindEnvelope)
	out = append(out, message...)
	out = appendVar(out, []byte{0x01, 0x00}) // NON-canonical: trailing zero byte
	out = appendFixed(out, env.Beam.Signature[:])
	out = appendVar(out, nil)
	out = appendVar(out, nil)

	require.NotEqual(t, wire, out)
	_, err = ParseEnvelope(out)
	require.ErrorIs(t, err, errZapBitsNonCanon)
}

func TestEnvelopeIDStable(t *testing.T) {
	env := envelopeFixture(t)
	require.Equal(t, env.Message.ID(), env.ID())
	// ID changes when a folded lineage field changes (Beam now binds it).
	mutated := *env
	mutated.Message.SourceKeyEraID = 999
	require.NotEqual(t, env.ID(), mutated.ID())
}

func TestEnvelopeEqualNilSafe(t *testing.T) {
	env := envelopeFixture(t)
	require.False(t, env.Equal(nil))
	require.False(t, (*Envelope)(nil).Equal(env))
	require.True(t, (*Envelope)(nil).Equal(nil))
}

// ---------------------------------------------------------------------
// Lane-verify plumbing.
// ---------------------------------------------------------------------

type stubCoronaVerifier struct {
	called bool
	err    error
	check  func(subject []byte, ev CoronaEvidence) error
}

func (s *stubCoronaVerifier) VerifyRingtailThreshold(subject []byte, ev CoronaEvidence) error {
	s.called = true
	if s.check != nil {
		return s.check(subject, ev)
	}
	return s.err
}

type stubCertSetVerifier struct {
	called bool
	err    error
}

func (s *stubCertSetVerifier) VerifyCertSet(subject []byte, ev CertSetEvidence) error {
	s.called = true
	return s.err
}

// stubValidatorState returns no validators so Beam verification fails;
// lane-plumbing tests use SkipBeam to avoid a full validator set.
type stubValidatorState struct{}

func (stubValidatorState) GetValidatorSet(ids.ID, uint64) (map[ids.NodeID]*Validator, error) {
	return map[ids.NodeID]*Validator{}, nil
}
func (stubValidatorState) GetCurrentHeight() (uint64, error) { return 0, nil }

func TestVerifyWithOptionsRequiresPulseWhenAbsent(t *testing.T) {
	env := envelopeFixture(t)
	err := VerifyWithOptions(env, VerifyOptions{SkipBeam: true, RequireCorona: true})
	require.Error(t, err)
}

func TestVerifyWithOptionsRequiresCertSetWhenAbsent(t *testing.T) {
	env := envelopeFixture(t)
	err := VerifyWithOptions(env, VerifyOptions{SkipBeam: true, RequireCertSet: true})
	require.Error(t, err)
}

func TestVerifyWithOptionsHashSuiteMismatch(t *testing.T) {
	env := envelopeFixture(t)
	env.Message.HashSuiteID = "Pulsar-SHA3-experimental"
	err := VerifyWithOptions(env, VerifyOptions{SkipBeam: true, HashSuiteID: MessageHashProfileTag})
	require.ErrorIs(t, err, ErrEnvelopeBadSuiteID)
}

func TestVerifyWithOptionsInvokesPulseVerifier(t *testing.T) {
	env := envelopeFixture(t)
	env.CoronaSig = bytes.Repeat([]byte{0x99}, 32)

	verifier := &stubCoronaVerifier{
		check: func(subject []byte, ev CoronaEvidence) error {
			if ev.KeyEraID != 7 {
				return errors.New("unexpected key era")
			}
			return nil
		},
	}
	err := VerifyWithOptions(env, VerifyOptions{SkipBeam: true, Corona: verifier, RequireCorona: true})
	require.NoError(t, err)
	require.True(t, verifier.called)
}

func TestVerifyWithOptionsPulseFailurePropagates(t *testing.T) {
	env := envelopeFixture(t)
	env.CoronaSig = bytes.Repeat([]byte{0x99}, 32)
	verifier := &stubCoronaVerifier{err: errors.New("pulse rejected")}
	err := VerifyWithOptions(env, VerifyOptions{SkipBeam: true, Corona: verifier, RequireCorona: true})
	require.Error(t, err)
	require.Contains(t, err.Error(), "pulse rejected")
}

func TestVerifyWithOptionsCertSetFailurePropagates(t *testing.T) {
	env := envelopeFixture(t)
	env.MLDSACertSet = bytes.Repeat([]byte{0x99}, 32)
	verifier := &stubCertSetVerifier{err: errors.New("cert rejected")}
	err := VerifyWithOptions(env, VerifyOptions{SkipBeam: true, CertSet: verifier, RequireCertSet: true})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cert rejected")
}

func TestVerifyPQLanesIndependentEntrypoint(t *testing.T) {
	env := envelopeFixture(t)
	env.CoronaSig = bytes.Repeat([]byte{0xAA}, 16)
	verifier := &stubCoronaVerifier{}
	err := VerifyPQLanes(env, VerifyOptions{Corona: verifier, RequireCorona: true})
	require.NoError(t, err)
	require.True(t, verifier.called)
}

func TestVerifyEnvelopeBeamFailsWithEmptyValidators(t *testing.T) {
	env := envelopeFixture(t)
	err := VerifyEnvelope(env, 1, stubValidatorState{}, 0, 1)
	require.Error(t, err)
}
