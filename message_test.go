// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"bytes"
	"testing"

	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

func TestCore(t *testing.T) {
	networkID := uint32(1)
	sourceChainID := ids.ID{31: 1}
	payload := []byte("test payload")

	core, err := NewCore(networkID, sourceChainID, payload)
	require.NoError(t, err)
	require.NotNil(t, core)

	require.Equal(t, networkID, core.NetworkID)
	require.Equal(t, sourceChainID, core.SourceChainID)
	require.Equal(t, payload, core.Payload)
	// NewCore resolves the default suite; lineage is zero.
	require.Equal(t, DefaultHashSuiteID, core.HashSuiteID)
	require.Equal(t, [32]byte{}, core.SourceNebulaRoot)

	// Canonical c14n round-trips.
	b := core.Bytes()
	require.NotEmpty(t, b)
	require.Equal(t, zapKindCore, b[0])

	id := core.ID()
	require.NotEqual(t, ids.Empty, id)

	parsed, err := ParseCore(b)
	require.NoError(t, err)
	require.Equal(t, core.NetworkID, parsed.NetworkID)
	require.Equal(t, core.SourceChainID, parsed.SourceChainID)
	require.Equal(t, core.Payload, parsed.Payload)
	require.Equal(t, core.HashSuiteID, parsed.HashSuiteID)
	// D recomputed from the decoded struct equals the original.
	require.Equal(t, id, parsed.ID())
}

// TestCoreIDIsLegacyKeccak pins D to legacy-keccak over the
// domain-tagged c14n preimage — NOT sha256, NOT NIST SHA3.
func TestCoreIDIsLegacyKeccak(t *testing.T) {
	core := &Core{
		NetworkID:     1,
		SourceChainID: ids.ID{0xA1},
		HashSuiteID:   DefaultHashSuiteID,
		Payload:       []byte("keccak-check"),
	}
	want := keccak256([]byte(coreDST), core.Bytes())
	require.Equal(t, ids.ID(want), core.ID())
}

// TestCoreIDChangesWithEveryField proves D depends on every field
// — including the folded PQ lineage that the Beam now authenticates.
func TestCoreIDChangesWithEveryField(t *testing.T) {
	base := &Core{
		NetworkID:        1,
		SourceChainID:    ids.ID{0xA1, 0xA2},
		SourceNebulaRoot: [32]byte{0xDE, 0xAD},
		SourceKeyEraID:   7,
		SourceGeneration: 11,
		HashSuiteID:      DefaultHashSuiteID,
		Payload:          []byte("base"),
	}
	baseID := base.ID()

	mutate := func(f func(c *Core)) ids.ID {
		c := *base
		f(&c)
		return c.ID()
	}

	require.NotEqual(t, baseID, mutate(func(c *Core) { c.NetworkID = 2 }))
	require.NotEqual(t, baseID, mutate(func(c *Core) { c.SourceChainID = ids.ID{0xFF} }))
	require.NotEqual(t, baseID, mutate(func(c *Core) { c.SourceNebulaRoot = [32]byte{0x99} }))
	require.NotEqual(t, baseID, mutate(func(c *Core) { c.SourceKeyEraID = 8 }))
	require.NotEqual(t, baseID, mutate(func(c *Core) { c.SourceGeneration = 12 }))
	require.NotEqual(t, baseID, mutate(func(c *Core) { c.HashSuiteID = "Pulsar-BLAKE3" }))
	require.NotEqual(t, baseID, mutate(func(c *Core) { c.Payload = []byte("base2") }))
}

// TestCoreNoSignTimeDefaulting proves the codec encodes HashSuiteID
// verbatim: an empty-suite core and a "Pulsar-SHA3" core produce DIFFERENT
// c14n bytes and DIFFERENT D. There is no defaulting inside the marshaler.
func TestCoreNoSignTimeDefaulting(t *testing.T) {
	empty := &Core{NetworkID: 1, SourceChainID: ids.ID{0xA1}, HashSuiteID: "", Payload: []byte("x")}
	resolved := &Core{NetworkID: 1, SourceChainID: ids.ID{0xA1}, HashSuiteID: DefaultHashSuiteID, Payload: []byte("x")}
	require.NotEqual(t, empty.Bytes(), resolved.Bytes())
	require.NotEqual(t, empty.ID(), resolved.ID())
	// HashSuiteOrDefault is a READ helper only — it does not change bytes.
	require.Equal(t, DefaultHashSuiteID, empty.HashSuiteOrDefault())
}

// TestParseCoreRejectsTrailing proves decode rejects trailing bytes.
func TestParseCoreRejectsTrailing(t *testing.T) {
	core, err := NewCore(1, ids.ID{0xA1}, []byte("p"))
	require.NoError(t, err)
	b := core.Bytes()
	_, err = ParseCore(append(b, 0x00))
	require.ErrorIs(t, err, errZapTrailing)
}

// TestParseCoreRejectsBadKind proves the zap kind discriminator is
// enforced.
func TestParseCoreRejectsBadKind(t *testing.T) {
	core, err := NewCore(1, ids.ID{0xA1}, []byte("p"))
	require.NoError(t, err)
	b := core.Bytes()
	b[0] = 0x02 // not zapKindCore
	_, err = ParseCore(b)
	require.ErrorIs(t, err, ErrInvalidMessage)
}

func TestVerifyWeight(t *testing.T) {
	tests := []struct {
		name          string
		signedWeight  uint64
		totalWeight   uint64
		quorumNum     uint64
		quorumDen     uint64
		expectedError bool
	}{
		{"valid 2/3 quorum", 67, 100, 2, 3, false},
		{"exact quorum", 2, 3, 2, 3, false},
		{"insufficient weight", 1, 3, 2, 3, true},
		{"zero signed weight", 0, 100, 2, 3, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyWeight(tt.signedWeight, tt.totalWeight, tt.quorumNum, tt.quorumDen)
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestLaneSigningBytesDistinct proves the per-lane tags are distinct and
// all over the same D, so a signature in one lane cannot be replayed into
// another (distinct domain prefixes).
func TestLaneSigningBytesDistinct(t *testing.T) {
	core, err := NewCore(1, ids.ID{0xA1}, []byte("lanes"))
	require.NoError(t, err)
	d := core.ID()

	beam := BeamSigningBytes(d)
	pulse := PulseSigningBytes(d)
	mldsa := MLDSASigningBytes(d)

	// Each carries its own DST then the SAME D.
	require.True(t, bytes.HasPrefix(beam, []byte(beamDST)))
	require.True(t, bytes.HasPrefix(pulse, []byte(pulseDST)))
	require.True(t, bytes.HasPrefix(mldsa, []byte(mldsaDST)))
	require.True(t, bytes.HasSuffix(beam, d[:]))
	require.True(t, bytes.HasSuffix(pulse, d[:]))
	require.True(t, bytes.HasSuffix(mldsa, d[:]))

	// Pairwise distinct.
	require.NotEqual(t, beam, pulse)
	require.NotEqual(t, beam, mldsa)
	require.NotEqual(t, pulse, mldsa)
}
