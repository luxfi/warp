// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
	"github.com/stretchr/testify/require"

	corona "github.com/luxfi/corona/threshold"
)

// runPulsarCeremony runs a full t-of-n threshold signing ceremony
// against the given message and returns the resulting Signature plus
// the GroupKey verifiers can match against.
func runPulsarCeremony(t *testing.T, n, threshold int, message string) (*corona.Signature, *corona.GroupKey) {
	t.Helper()

	shares, gk, err := corona.GenerateKeys(threshold, n, rand.Reader)
	require.NoError(t, err)
	require.Len(t, shares, n)

	signers := make([]int, n)
	for i := range signers {
		signers[i] = i
	}
	prfKey := make([]byte, 32)
	_, err = rand.Read(prfKey)
	require.NoError(t, err)

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
		require.NoError(t, err)
		r2[i] = d
	}

	sig, err := parties[0].Finalize(r2)
	require.NoError(t, err)
	require.True(t, corona.Verify(gk, message, sig))
	return sig, gk
}

func envFixture(t *testing.T, eraID, generation uint64) (*warp.EnvelopeV2, *warp.Message) {
	t.Helper()
	const networkID = uint32(1)
	chainID := ids.ID{0xC1, 0xC2, 0xC3, 0xC4}
	payload := []byte("warp-pulsar-roundtrip")

	unsigned, err := warp.NewUnsignedMessage(networkID, chainID, payload)
	require.NoError(t, err)

	signers := warp.NewBitSet()
	signers.Add(0)
	signers.Add(2)

	var sigBytes [bls.SignatureLen]byte
	copy(sigBytes[:], bytes.Repeat([]byte{0xAB}, bls.SignatureLen))
	v1Sig := warp.NewBitSetSignature(signers, sigBytes)
	v1, err := warp.NewMessage(unsigned, v1Sig)
	require.NoError(t, err)

	env := &warp.EnvelopeV2{
		Message:          v1,
		SourceKeyEraID:   eraID,
		SourceGeneration: generation,
		HashSuiteID:      warp.DefaultHashSuiteID,
	}
	return env, v1
}

type stubResolver struct {
	gk      *corona.GroupKey
	suiteID string
	err     error
}

func (s *stubResolver) ResolveGroupKey(_ [32]byte, _ uint64, _ uint64) (*corona.GroupKey, string, error) {
	return s.gk, s.suiteID, s.err
}

func TestSerializeDeserializePulseRoundTrip(t *testing.T) {
	sig, gk := runPulsarCeremony(t, 3, 2, "round-trip")

	wire, err := SerializePulse(sig)
	require.NoError(t, err)
	require.NotEmpty(t, wire)

	parsed, err := DeserializePulse(wire)
	require.NoError(t, err)
	require.True(t, corona.Verify(gk, "round-trip", parsed))
}

func TestKernelVerifierAcceptsValidPulse(t *testing.T) {
	env, _ := envFixture(t, 7, 11)
	msgBytes := env.Message.UnsignedMessage.Bytes()
	signing := BuildSigningBytes(env, msgBytes)

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))

	pulse, err := SerializePulse(sig)
	require.NoError(t, err)
	env.PulsarPulse = pulse

	v := NewKernelVerifier(&stubResolver{gk: gk, suiteID: warp.DefaultHashSuiteID})
	require.NoError(t, v.VerifyPulse(env, msgBytes))
}

func TestKernelVerifierRejectsTamperedEnvelopeFields(t *testing.T) {
	env, _ := envFixture(t, 7, 11)
	msgBytes := env.Message.UnsignedMessage.Bytes()
	signing := BuildSigningBytes(env, msgBytes)

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializePulse(sig)
	require.NoError(t, err)
	env.PulsarPulse = pulse

	// Tamper with KeyEraID after signing — verification MUST fail
	// because BuildSigningBytes binds KeyEraID into the transcript.
	env.SourceKeyEraID = 999

	v := NewKernelVerifier(&stubResolver{gk: gk, suiteID: warp.DefaultHashSuiteID})
	err = v.VerifyPulse(env, msgBytes)
	require.ErrorIs(t, err, ErrPulseVerifyFailed)
}

func TestKernelVerifierRejectsOnAbsentPulse(t *testing.T) {
	env, _ := envFixture(t, 1, 1)
	v := NewKernelVerifier(&stubResolver{suiteID: warp.DefaultHashSuiteID})
	err := v.VerifyPulse(env, env.Message.UnsignedMessage.Bytes())
	require.ErrorIs(t, err, ErrPulseAbsent)
}

func TestKernelVerifierRejectsResolverError(t *testing.T) {
	env, _ := envFixture(t, 1, 1)
	env.PulsarPulse = bytes.Repeat([]byte{0xFF}, 32)
	v := NewKernelVerifier(&stubResolver{err: errors.New("registry down")})
	err := v.VerifyPulse(env, env.Message.UnsignedMessage.Bytes())
	require.ErrorIs(t, err, ErrGroupKeyResolverFailed)
}

func TestKernelVerifierRejectsNilGroupKey(t *testing.T) {
	env, _ := envFixture(t, 1, 1)
	env.PulsarPulse = bytes.Repeat([]byte{0xFF}, 32)
	v := NewKernelVerifier(&stubResolver{gk: nil, suiteID: warp.DefaultHashSuiteID})
	err := v.VerifyPulse(env, env.Message.UnsignedMessage.Bytes())
	require.ErrorIs(t, err, ErrGroupKeyResolverFailed)
}

func TestKernelVerifierRejectsSuiteMismatch(t *testing.T) {
	env, _ := envFixture(t, 1, 1)
	env.PulsarPulse = bytes.Repeat([]byte{0xFF}, 32)

	_, gk := runPulsarCeremony(t, 3, 2, "x")
	v := NewKernelVerifier(&stubResolver{gk: gk, suiteID: "Pulsar-SHA3-experimental"})
	err := v.VerifyPulse(env, env.Message.UnsignedMessage.Bytes())
	require.ErrorIs(t, err, ErrSuiteMismatch)
}

func TestBuildSigningBytesBindsAllTranscriptFields(t *testing.T) {
	env1, _ := envFixture(t, 7, 11)
	env1.SourceNebulaRoot = [32]byte{0x01, 0x02}
	msg1 := env1.Message.UnsignedMessage.Bytes()
	bytes1 := BuildSigningBytes(env1, msg1)

	// Changing each transcript field must change the signing bytes.
	env2 := *env1
	env2.SourceKeyEraID = 8
	require.NotEqual(t, bytes1, BuildSigningBytes(&env2, msg1))

	env3 := *env1
	env3.SourceGeneration = 12
	require.NotEqual(t, bytes1, BuildSigningBytes(&env3, msg1))

	env4 := *env1
	env4.SourceNebulaRoot = [32]byte{0x99}
	require.NotEqual(t, bytes1, BuildSigningBytes(&env4, msg1))

	env5 := *env1
	env5.HashSuiteID = "Pulsar-SHA3-other"
	require.NotEqual(t, bytes1, BuildSigningBytes(&env5, msg1))

	// Different msg bytes → different signing bytes.
	require.NotEqual(t, bytes1, BuildSigningBytes(env1, append([]byte("X"), msg1...)))
}

func TestBuildSigningBytesPrefixIsConstant(t *testing.T) {
	env, _ := envFixture(t, 1, 1)
	out := BuildSigningBytes(env, env.Message.UnsignedMessage.Bytes())
	require.True(t, bytes.HasPrefix(out, []byte(SigningPrefix)))
}

func TestHorizonFromEnvelopePopulatesAllLanes(t *testing.T) {
	env, v1 := envFixture(t, 7, 11)
	env.SourceNebulaRoot = [32]byte{0x42}
	env.PulsarPulse = bytes.Repeat([]byte{0xCC}, 16)
	env.MLDSACertSet = bytes.Repeat([]byte{0xDD}, 192)

	h, err := HorizonFromEnvelope(env)
	require.NoError(t, err)
	require.Equal(t, env.Message.UnsignedMessage.SourceChainID[:], h.SourceChainID[:])
	require.Equal(t, v1.Signature.Bytes(), h.Beam)
	require.Equal(t, env.PulsarPulse, h.Pulse)
	require.Equal(t, env.MLDSACertSet, h.MLDSACertSet)
	require.Equal(t, env.SourceNebulaRoot, h.SourceNebulaRoot)
	require.Equal(t, env.SourceKeyEraID, h.SourceKeyEraID)
	require.Equal(t, env.SourceGeneration, h.SourceGeneration)
	require.Equal(t, env.HashSuiteOrDefault(), h.HashSuiteID)
	require.Equal(t, env.Message.UnsignedMessage.Bytes(), h.UnsignedMessageBytes)
}

func TestHorizonFromEnvelopeRejectsNil(t *testing.T) {
	_, err := HorizonFromEnvelope(nil)
	require.Error(t, err)
}
