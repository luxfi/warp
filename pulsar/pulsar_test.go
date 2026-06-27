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

// runPulsarCeremony runs a full t-of-n threshold signing ceremony against
// the given message and returns the Signature plus the GroupKey.
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

// envFixture builds a Envelope with the given Pulsar lineage.
func envFixture(t *testing.T, eraID, generation uint64) *warp.Envelope {
	t.Helper()
	message := &warp.Message{
		NetworkID:        1,
		SourceChainID:    ids.ID{0xC1, 0xC2, 0xC3, 0xC4},
		SourceKeyEraID:   eraID,
		SourceGeneration: generation,
		HashSuiteID:      warp.DefaultHashSuiteID,
		Payload:          []byte("warp-pulsar-roundtrip"),
	}
	signers := warp.NewBitSet()
	signers.Add(0)
	signers.Add(2)
	var sigBytes [bls.SignatureLen]byte
	copy(sigBytes[:], bytes.Repeat([]byte{0xAB}, bls.SignatureLen))
	env, err := warp.NewEnvelope(message, warp.NewBitSetSignature(signers, sigBytes), nil, nil)
	require.NoError(t, err)
	return env
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
	env := envFixture(t, 7, 11)
	signing := warp.PulseSigningBytes(env.Message.ID())

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializePulse(sig)
	require.NoError(t, err)
	env.PulseSig = pulse

	v := NewKernelVerifier(&stubResolver{gk: gk, suiteID: warp.DefaultHashSuiteID})
	require.NoError(t, v.VerifyPulse(env))
}

func TestKernelVerifierRejectsTamperedEnvelopeFields(t *testing.T) {
	env := envFixture(t, 7, 11)
	signing := warp.PulseSigningBytes(env.Message.ID())

	sig, gk := runPulsarCeremony(t, 3, 2, string(signing))
	pulse, err := SerializePulse(sig)
	require.NoError(t, err)
	env.PulseSig = pulse

	// Tamper with KeyEraID after signing — D changes, so the Pulse over
	// the original D no longer verifies. (The Beam now also binds this
	// field via D, closing the old Beam-unauthenticated-lineage gap.)
	env.Message.SourceKeyEraID = 999

	v := NewKernelVerifier(&stubResolver{gk: gk, suiteID: warp.DefaultHashSuiteID})
	require.ErrorIs(t, v.VerifyPulse(env), ErrPulseVerifyFailed)
}

func TestKernelVerifierRejectsOnAbsentPulse(t *testing.T) {
	env := envFixture(t, 1, 1)
	v := NewKernelVerifier(&stubResolver{suiteID: warp.DefaultHashSuiteID})
	require.ErrorIs(t, v.VerifyPulse(env), ErrPulseAbsent)
}

func TestKernelVerifierRejectsResolverError(t *testing.T) {
	env := envFixture(t, 1, 1)
	env.PulseSig = bytes.Repeat([]byte{0xFF}, 32)
	v := NewKernelVerifier(&stubResolver{err: errors.New("registry down")})
	require.ErrorIs(t, v.VerifyPulse(env), ErrGroupKeyResolverFailed)
}

func TestKernelVerifierRejectsNilGroupKey(t *testing.T) {
	env := envFixture(t, 1, 1)
	env.PulseSig = bytes.Repeat([]byte{0xFF}, 32)
	v := NewKernelVerifier(&stubResolver{gk: nil, suiteID: warp.DefaultHashSuiteID})
	require.ErrorIs(t, v.VerifyPulse(env), ErrGroupKeyResolverFailed)
}

func TestKernelVerifierRejectsSuiteMismatch(t *testing.T) {
	env := envFixture(t, 1, 1)
	env.PulseSig = bytes.Repeat([]byte{0xFF}, 32)
	_, gk := runPulsarCeremony(t, 3, 2, "x")
	v := NewKernelVerifier(&stubResolver{gk: gk, suiteID: "Pulsar-SHA3-experimental"})
	require.ErrorIs(t, v.VerifyPulse(env), ErrSuiteMismatch)
}

// TestPulseSigningBytesBindsAllTranscriptFields proves the Pulse subject
// (PulseSigningBytes(D)) changes when ANY transcript field changes —
// because D folds them all.
func TestPulseSigningBytesBindsAllTranscriptFields(t *testing.T) {
	env := envFixture(t, 7, 11)
	env.Message.SourceNebulaRoot = [32]byte{0x01, 0x02}
	base := warp.PulseSigningBytes(env.Message.ID())

	mutate := func(f func(c *warp.Message)) []byte {
		c := env.Message
		f(&c)
		return warp.PulseSigningBytes(c.ID())
	}
	require.NotEqual(t, base, mutate(func(c *warp.Message) { c.SourceKeyEraID = 8 }))
	require.NotEqual(t, base, mutate(func(c *warp.Message) { c.SourceGeneration = 12 }))
	require.NotEqual(t, base, mutate(func(c *warp.Message) { c.SourceNebulaRoot = [32]byte{0x99} }))
	require.NotEqual(t, base, mutate(func(c *warp.Message) { c.HashSuiteID = "Pulsar-SHA3-other" }))
	require.NotEqual(t, base, mutate(func(c *warp.Message) { c.Payload = append([]byte("X"), c.Payload...) }))
}

// TestPulseSigningBytesPrefix proves the Pulse subject carries the
// PULSE domain-separation tag.
func TestPulseSigningBytesPrefix(t *testing.T) {
	env := envFixture(t, 1, 1)
	out := warp.PulseSigningBytes(env.Message.ID())
	require.True(t, bytes.HasPrefix(out, []byte("LUX-WARP-ZAP-PULSE-v1")))
	d := env.Message.ID()
	require.True(t, bytes.HasSuffix(out, d[:]))
}

func TestHorizonFromEnvelopePopulatesAllLanes(t *testing.T) {
	env := envFixture(t, 7, 11)
	env.Message.SourceNebulaRoot = [32]byte{0x42}
	env.PulseSig = bytes.Repeat([]byte{0xCC}, 16)
	env.MLDSACertSet = bytes.Repeat([]byte{0xDD}, 192)

	h, err := HorizonFromEnvelope(env)
	require.NoError(t, err)
	require.Equal(t, env.Message.SourceChainID[:], h.SourceChainID[:])
	require.Equal(t, env.Beam.Signature[:], h.Beam)
	require.Equal(t, env.PulseSig, h.Pulse)
	require.Equal(t, env.MLDSACertSet, h.MLDSACertSet)
	require.Equal(t, env.Message.SourceNebulaRoot, h.SourceNebulaRoot)
	require.Equal(t, env.Message.SourceKeyEraID, h.SourceKeyEraID)
	require.Equal(t, env.Message.SourceGeneration, h.SourceGeneration)
	require.Equal(t, env.Message.HashSuiteOrDefault(), h.HashSuiteID)
	require.Equal(t, env.Message.Bytes(), h.UnsignedMessageBytes)
}

func TestHorizonFromEnvelopeRejectsNil(t *testing.T) {
	_, err := HorizonFromEnvelope(nil)
	require.Error(t, err)
}
