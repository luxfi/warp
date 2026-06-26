// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"bytes"
	"sort"
	"testing"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

type fixedValidatorState struct {
	vdrs map[ids.NodeID]*Validator
}

func (f fixedValidatorState) GetValidatorSet(ids.ID, uint64) (map[ids.NodeID]*Validator, error) {
	return f.vdrs, nil
}
func (f fixedValidatorState) GetCurrentHeight() (uint64, error) { return 1, nil }

// makeValidators returns n validators sorted in canonical (PublicKeyBytes)
// order, the secret keys aligned to that order, and a ValidatorState that
// serves them — so signer-bitset indices match the canonical set
// VerifyEnvelope recomputes.
func makeValidators(t *testing.T, n int) ([]*Validator, []*bls.SecretKey, ValidatorState) {
	t.Helper()
	type pair struct {
		v  *Validator
		sk *bls.SecretKey
	}
	pairs := make([]pair, 0, n)
	for i := 0; i < n; i++ {
		sk, err := bls.NewSecretKey()
		require.NoError(t, err)
		pk := sk.PublicKey()
		pkb := bls.PublicKeyToCompressedBytes(pk)
		var nid ids.NodeID
		nid[0] = byte(i)
		nid[1] = byte(i >> 8)
		pairs = append(pairs, pair{
			v:  &Validator{PublicKey: pk, PublicKeyBytes: pkb, Weight: 100, NodeID: nid},
			sk: sk,
		})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return bytes.Compare(pairs[i].v.PublicKeyBytes, pairs[j].v.PublicKeyBytes) < 0
	})
	vdrs := make([]*Validator, n)
	sks := make([]*bls.SecretKey, n)
	vmap := make(map[ids.NodeID]*Validator, n)
	for i, p := range pairs {
		vdrs[i] = p.v
		sks[i] = p.sk
		vmap[p.v.NodeID] = p.v
	}
	return vdrs, sks, fixedValidatorState{vdrs: vmap}
}

// TestBeamEndToEndVerify is the happy path: SignMessage signs over the
// Beam domain, VerifyEnvelope accepts.
func TestBeamEndToEndVerify(t *testing.T) {
	vdrs, sks, vs := makeValidators(t, 4)
	core, err := NewSignedCore(1, ids.ID{0xA1}, []byte("beam-e2e"))
	require.NoError(t, err)

	env, err := SignMessage(core, []*bls.SecretKey{sks[0], sks[2]}, vdrs)
	require.NoError(t, err)

	// 2-of-4 validators signed (weight 200/400); quorum 1/2 is met.
	require.NoError(t, VerifyEnvelope(env, 1, vs, 1, 2))

	// Wire round-trip preserves verifiability.
	wire, err := env.Bytes()
	require.NoError(t, err)
	parsed, err := ParseWarpEnvelope(wire)
	require.NoError(t, err)
	require.NoError(t, VerifyEnvelope(parsed, 1, vs, 1, 2))
}

// TestBeamRejectsLegacyDomainSignature is the second replay barrier: a
// Beam forged by signing the BARE core bytes (the pre-fork domain) does
// NOT verify under the new BEAM_MSG = beamDST‖D domain, even though it is
// wrapped in a well-formed ZAP envelope. The first barrier (legacy RLP
// rejected at the magic) is in envelope_test.go.
func TestBeamRejectsLegacyDomainSignature(t *testing.T) {
	vdrs, sks, vs := makeValidators(t, 4)
	core, err := NewSignedCore(1, ids.ID{0xB2}, []byte("legacy-domain"))
	require.NoError(t, err)

	// Forge over the OLD domain (the bare unsigned-message bytes).
	legacyMsg := core.Bytes()
	s0, err := sks[0].Sign(legacyMsg)
	require.NoError(t, err)
	s2, err := sks[2].Sign(legacyMsg)
	require.NoError(t, err)
	agg, err := bls.AggregateSignatures([]*bls.Signature{s0, s2})
	require.NoError(t, err)

	signers := NewBitSet()
	signers.Add(0)
	signers.Add(2)
	var sigb [bls.SignatureLen]byte
	copy(sigb[:], bls.SignatureToBytes(agg))
	env, err := NewWarpEnvelope(core, NewBitSetSignature(signers, sigb), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, vdrs)

	require.ErrorIs(t, VerifyEnvelope(env, 1, vs, 1, 2), ErrInvalidSignature)
}

// TestBeamRejectsForeignDigest proves the Beam binds the exact D: a
// signature over BeamSigningBytes(D') for a DIFFERENT core fails when
// wrapped around this core.
func TestBeamRejectsForeignDigest(t *testing.T) {
	_, sks, vs := makeValidators(t, 4)
	core, err := NewSignedCore(1, ids.ID{0xC3}, []byte("real"))
	require.NoError(t, err)
	other, err := NewSignedCore(1, ids.ID{0xC3}, []byte("other"))
	require.NoError(t, err)

	bm := BeamSigningBytes(other.ID())
	s0, err := sks[0].Sign(bm)
	require.NoError(t, err)
	s1, err := sks[1].Sign(bm)
	require.NoError(t, err)
	agg, err := bls.AggregateSignatures([]*bls.Signature{s0, s1})
	require.NoError(t, err)

	signers := NewBitSet()
	signers.Add(0)
	signers.Add(1)
	var sigb [bls.SignatureLen]byte
	copy(sigb[:], bls.SignatureToBytes(agg))
	env, err := NewWarpEnvelope(core, NewBitSetSignature(signers, sigb), nil, nil)
	require.NoError(t, err)

	require.ErrorIs(t, VerifyEnvelope(env, 1, vs, 1, 2), ErrInvalidSignature)
}
