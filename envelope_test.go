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

// envelopeFixture builds a fully-populated v1 Message for envelope tests.
func envelopeFixture(t *testing.T) *Message {
	t.Helper()
	const networkID = uint32(1)
	chainID := ids.ID{0xA1, 0xA2, 0xA3, 0xA4}
	payload := []byte("envelope-test-payload")

	unsigned, err := NewUnsignedMessage(networkID, chainID, payload)
	require.NoError(t, err)

	signers := NewBitSet()
	signers.Add(0)
	signers.Add(2)
	signers.Add(4)

	var sigBytes [bls.SignatureLen]byte
	copy(sigBytes[:], bytes.Repeat([]byte{0xAB}, bls.SignatureLen))

	sig := NewBitSetSignature(signers, sigBytes)
	msg, err := NewMessage(unsigned, sig)
	require.NoError(t, err)
	return msg
}

func TestEnvelopeV2RoundTrip(t *testing.T) {
	v1 := envelopeFixture(t)

	pulse := bytes.Repeat([]byte{0x42}, 64)
	cert := bytes.Repeat([]byte{0xC3}, 192)
	nebulaRoot := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}

	env := &EnvelopeV2{
		Message:          v1,
		SourceNebulaRoot: nebulaRoot,
		SourceKeyEraID:   7,
		SourceGeneration: 11,
		HashSuiteID:      DefaultHashSuiteID,
		PulsarPulse:      pulse,
		MLDSACertSet:     cert,
	}

	require.NoError(t, env.Verify())
	require.True(t, env.HasPulse())
	require.True(t, env.HasMLDSACertSet())

	wire, err := env.Bytes()
	require.NoError(t, err)
	require.Equal(t, byte(EnvelopeVersion2), wire[0])

	parsed, err := ParseEnvelopeV2(wire)
	require.NoError(t, err)
	require.Equal(t, env.SourceKeyEraID, parsed.SourceKeyEraID)
	require.Equal(t, env.SourceGeneration, parsed.SourceGeneration)
	require.Equal(t, env.SourceNebulaRoot, parsed.SourceNebulaRoot)
	require.Equal(t, env.HashSuiteID, parsed.HashSuiteID)
	require.Equal(t, env.PulsarPulse, parsed.PulsarPulse)
	require.Equal(t, env.MLDSACertSet, parsed.MLDSACertSet)

	// The embedded v1 Message survives intact.
	require.True(t, parsed.Message.Equal(v1))
	v1ID := v1.ID()
	pID := parsed.ID()
	require.Equal(t, v1ID[:], pID[:])
	require.True(t, env.Equal(parsed))
}

func TestEnvelopeV2EmptyOptionalFields(t *testing.T) {
	v1 := envelopeFixture(t)

	env := &EnvelopeV2{
		Message:        v1,
		SourceKeyEraID: 0,
	}
	require.NoError(t, env.Verify())
	require.False(t, env.HasPulse())
	require.False(t, env.HasMLDSACertSet())
	require.Equal(t, DefaultHashSuiteID, env.HashSuiteOrDefault())

	wire, err := env.Bytes()
	require.NoError(t, err)

	parsed, err := ParseEnvelopeV2(wire)
	require.NoError(t, err)
	require.Empty(t, parsed.PulsarPulse)
	require.Empty(t, parsed.MLDSACertSet)
	require.Equal(t, "", parsed.HashSuiteID)
	require.Equal(t, DefaultHashSuiteID, parsed.HashSuiteOrDefault())
	require.True(t, parsed.Message.Equal(v1))
}

func TestParseEnvelopeForwardCompatV1Bytes(t *testing.T) {
	// A Warp 2.0 receiver decoding Warp 1.x bytes via ParseEnvelope
	// gets back a v2 envelope with only the Beam lane populated.
	v1 := envelopeFixture(t)
	v1Bytes := v1.Bytes()

	env, err := ParseEnvelope(v1Bytes)
	require.NoError(t, err)
	require.NotNil(t, env)
	require.True(t, env.Message.Equal(v1))
	require.False(t, env.HasPulse())
	require.False(t, env.HasMLDSACertSet())
	require.Equal(t, uint64(0), env.SourceKeyEraID)
	require.Equal(t, uint64(0), env.SourceGeneration)
	require.Equal(t, [32]byte{}, env.SourceNebulaRoot)
}

func TestParseEnvelopeBackwardCompatV1RejectsV2Bytes(t *testing.T) {
	// Warp 1.x receivers (calling ParseMessage directly) MUST reject
	// v2 envelopes — the leading 0x02 is not a valid RLP-list prefix
	// for a v1 Message. This is the correct refusal: the v1 verifier
	// cannot validate v2 transcript binding.
	v1 := envelopeFixture(t)
	env := &EnvelopeV2{
		Message:        v1,
		SourceKeyEraID: 1,
	}
	wire, err := env.Bytes()
	require.NoError(t, err)

	_, parseErr := ParseMessage(wire)
	require.Error(t, parseErr)
}

func TestParseEnvelopeRejectsUnknownVersion(t *testing.T) {
	// Any leading byte that is not 0x02 and not a valid RLP list
	// prefix (>= 0xc0) MUST produce an error rather than silently
	// dispatch to the wrong version.
	bad := []byte{0x05, 0x00, 0x00}
	_, err := ParseEnvelope(bad)
	require.Error(t, err)
}

func TestParseEnvelopeRejectsEmpty(t *testing.T) {
	_, err := ParseEnvelope(nil)
	require.ErrorIs(t, err, ErrEnvelopeEmpty)

	_, err = ParseEnvelopeV2(nil)
	require.ErrorIs(t, err, ErrEnvelopeEmpty)
}

func TestParseEnvelopeV2RejectsWrongVersion(t *testing.T) {
	// 0x05 is NOT EnvelopeVersion2 → ErrUnknownEnvelopeVersion.
	_, err := ParseEnvelopeV2([]byte{0x05, 0x00})
	require.ErrorIs(t, err, ErrUnknownEnvelopeVersion)
}

func TestEnvelopeV2HashSuiteDefaulting(t *testing.T) {
	v1 := envelopeFixture(t)

	envEmpty := &EnvelopeV2{Message: v1}
	require.Equal(t, DefaultHashSuiteID, envEmpty.HashSuiteOrDefault())

	envCustom := &EnvelopeV2{Message: v1, HashSuiteID: "Pulsar-SHA3-test"}
	require.Equal(t, "Pulsar-SHA3-test", envCustom.HashSuiteOrDefault())

	var nilEnv *EnvelopeV2
	require.Equal(t, DefaultHashSuiteID, nilEnv.HashSuiteOrDefault())
}

func TestEnvelopeV2VerifyMissingMessage(t *testing.T) {
	env := &EnvelopeV2{Message: nil}
	require.ErrorIs(t, env.Verify(), ErrEnvelopeMissingMessage)

	_, err := env.Bytes()
	require.Error(t, err)
}

func TestEnvelopeV2IDStableAcrossVersions(t *testing.T) {
	v1 := envelopeFixture(t)
	env := &EnvelopeV2{
		Message:        v1,
		SourceKeyEraID: 9,
	}
	// v1 ID and v2 envelope ID share the underlying UnsignedMessage,
	// so they MUST be byte-equal — destination-chain replay protection
	// is uniform across versions.
	envID := env.ID()
	v1ID := v1.ID()
	require.Equal(t, v1ID[:], envID[:])
}

func TestEnvelopeV2EqualNilSafe(t *testing.T) {
	v1 := envelopeFixture(t)
	a := &EnvelopeV2{Message: v1, SourceKeyEraID: 1}
	require.False(t, a.Equal(nil))
	require.False(t, (*EnvelopeV2)(nil).Equal(a))
	require.True(t, (*EnvelopeV2)(nil).Equal(nil))
}

// stubPulseVerifier records the envelope it was called with and
// returns the configured error.
type stubPulseVerifier struct {
	called bool
	err    error
	check  func(env *EnvelopeV2, msgBytes []byte) error
}

func (s *stubPulseVerifier) VerifyPulse(env *EnvelopeV2, msgBytes []byte) error {
	s.called = true
	if s.check != nil {
		return s.check(env, msgBytes)
	}
	return s.err
}

type stubCertSetVerifier struct {
	called bool
	err    error
}

func (s *stubCertSetVerifier) VerifyCertSet(env *EnvelopeV2, msgBytes []byte) error {
	s.called = true
	return s.err
}

// stubValidatorState returns no validators so Beam verification will
// fail; tests that don't care about Beam can route through VerifyV2
// option paths that exercise lane plumbing without touching Beam.
type stubValidatorState struct{}

func (stubValidatorState) GetValidatorSet(ids.ID, uint64) (map[ids.NodeID]*Validator, error) {
	return map[ids.NodeID]*Validator{}, nil
}

func (stubValidatorState) GetCurrentHeight() (uint64, error) { return 0, nil }

func TestVerifyV2RequiresPulseWhenAbsent(t *testing.T) {
	v1 := envelopeFixture(t)
	env := &EnvelopeV2{Message: v1}

	opts := VerifyV2Options{
		SkipBeam:     true,
		RequirePulse: true,
	}
	err := VerifyV2(env, opts)
	require.Error(t, err)
}

func TestVerifyV2RequiresCertSetWhenAbsent(t *testing.T) {
	v1 := envelopeFixture(t)
	env := &EnvelopeV2{Message: v1}

	opts := VerifyV2Options{
		SkipBeam:       true,
		RequireCertSet: true,
	}
	err := VerifyV2(env, opts)
	require.Error(t, err)
}

func TestVerifyV2HashSuiteMismatch(t *testing.T) {
	v1 := envelopeFixture(t)
	env := &EnvelopeV2{
		Message:     v1,
		HashSuiteID: "Pulsar-SHA3-experimental",
	}
	opts := VerifyV2Options{
		SkipBeam:    true,
		HashSuiteID: DefaultHashSuiteID,
	}
	err := VerifyV2(env, opts)
	require.ErrorIs(t, err, ErrEnvelopeBadSuiteID)
}

func TestVerifyV2InvokesPulseVerifierWhenPresent(t *testing.T) {
	v1 := envelopeFixture(t)
	env := &EnvelopeV2{
		Message:        v1,
		SourceKeyEraID: 7,
		PulsarPulse:    bytes.Repeat([]byte{0x99}, 32),
	}

	verifier := &stubPulseVerifier{
		check: func(env *EnvelopeV2, msgBytes []byte) error {
			if env.SourceKeyEraID != 7 {
				return errors.New("unexpected key era")
			}
			if !bytes.Equal(msgBytes, v1.UnsignedMessage.Bytes()) {
				return errors.New("unexpected msg bytes")
			}
			return nil
		},
	}

	opts := VerifyV2Options{
		SkipBeam:     true,
		Pulse:        verifier,
		RequirePulse: true,
	}
	err := VerifyV2(env, opts)
	require.NoError(t, err)
	require.True(t, verifier.called)
}

func TestVerifyV2PulseFailurePropagates(t *testing.T) {
	v1 := envelopeFixture(t)
	env := &EnvelopeV2{
		Message:     v1,
		PulsarPulse: bytes.Repeat([]byte{0x99}, 32),
	}

	bad := errors.New("pulse rejected")
	verifier := &stubPulseVerifier{err: bad}

	opts := VerifyV2Options{
		SkipBeam:     true,
		Pulse:        verifier,
		RequirePulse: true,
	}
	err := VerifyV2(env, opts)
	require.Error(t, err)
	require.Contains(t, err.Error(), "pulse rejected")
}

func TestVerifyV2CertSetFailurePropagates(t *testing.T) {
	v1 := envelopeFixture(t)
	env := &EnvelopeV2{
		Message:      v1,
		MLDSACertSet: bytes.Repeat([]byte{0x99}, 32),
	}

	bad := errors.New("cert rejected")
	verifier := &stubCertSetVerifier{err: bad}

	opts := VerifyV2Options{
		SkipBeam:       true,
		CertSet:        verifier,
		RequireCertSet: true,
	}
	err := VerifyV2(env, opts)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cert rejected")
}

func TestVerifyPQLanesIndependentEntrypoint(t *testing.T) {
	// VerifyPQLanes is the standalone entrypoint for callers that
	// have already validated the Beam through a separate code path.
	v1 := envelopeFixture(t)
	env := &EnvelopeV2{
		Message:     v1,
		PulsarPulse: bytes.Repeat([]byte{0xAA}, 16),
	}

	verifier := &stubPulseVerifier{}
	opts := VerifyV2Options{
		Pulse:        verifier,
		RequirePulse: true,
	}
	err := VerifyPQLanes(env, opts)
	require.NoError(t, err)
	require.True(t, verifier.called)
}

func TestVerifyV2BeamOnlyMatchesV1Behaviour(t *testing.T) {
	// With no PQ-lane verifiers configured and no Required* flags,
	// VerifyV2 (without SkipBeam) reduces to VerifyV1 — equivalent
	// failure shape on the same input. Both fail with empty validator
	// state; the point is that the v2 path does not introduce
	// extraneous errors when the PQ lanes are empty.
	v1 := envelopeFixture(t)
	env := &EnvelopeV2{Message: v1}

	v1Err := VerifyV1(v1, 1, stubValidatorState{}, 0, 1)
	v2Err := VerifyV2(env, VerifyV2Options{
		NetworkID:      1,
		ValidatorState: stubValidatorState{},
		QuorumNum:      0,
		QuorumDen:      1,
	})
	require.Error(t, v1Err)
	require.Error(t, v2Err)
}
