// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"bytes"
	"testing"

	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

func TestMessage(t *testing.T) {
	networkID := uint32(1)
	sourceChainID := ids.ID{31: 1}
	payload := []byte("test payload")

	message, err := NewMessage(networkID, sourceChainID, payload)
	require.NoError(t, err)
	require.NotNil(t, message)

	require.Equal(t, networkID, message.NetworkID)
	require.Equal(t, sourceChainID, message.SourceChainID)
	require.Equal(t, payload, message.Payload)
	// NewMessage resolves the default suite; lineage is zero.
	require.Equal(t, DefaultHashSuiteID, message.HashSuiteID)
	require.Equal(t, [32]byte{}, message.SourceNebulaRoot)

	// Canonical c14n round-trips.
	b := message.Bytes()
	require.NotEmpty(t, b)
	require.Equal(t, zapKindMessage, b[0])

	id := message.ID()
	require.NotEqual(t, ids.Empty, id)

	parsed, err := ParseMessage(b)
	require.NoError(t, err)
	require.Equal(t, message.NetworkID, parsed.NetworkID)
	require.Equal(t, message.SourceChainID, parsed.SourceChainID)
	require.Equal(t, message.Payload, parsed.Payload)
	require.Equal(t, message.HashSuiteID, parsed.HashSuiteID)
	// D recomputed from the decoded struct equals the original.
	require.Equal(t, id, parsed.ID())
}

// TestMessageIDIsLegacyKeccak pins D to legacy-keccak over the
// domain-tagged c14n preimage — NOT sha256, NOT NIST SHA3.
func TestMessageIDIsLegacyKeccak(t *testing.T) {
	message := &Message{
		NetworkID:     1,
		SourceChainID: ids.ID{0xA1},
		HashSuiteID:   DefaultHashSuiteID,
		Payload:       []byte("keccak-check"),
	}
	want := keccak256([]byte(messageDST), message.Bytes())
	require.Equal(t, ids.ID(want), message.ID())
}

// TestMessageIDChangesWithEveryField proves D depends on every field
// — including the folded PQ lineage that the Beam now authenticates.
func TestMessageIDChangesWithEveryField(t *testing.T) {
	base := &Message{
		NetworkID:        1,
		SourceChainID:    ids.ID{0xA1, 0xA2},
		SourceNebulaRoot: [32]byte{0xDE, 0xAD},
		SourceKeyEraID:   7,
		SourceGeneration: 11,
		HashSuiteID:      DefaultHashSuiteID,
		Payload:          []byte("base"),
	}
	baseID := base.ID()

	mutate := func(f func(c *Message)) ids.ID {
		c := *base
		f(&c)
		return c.ID()
	}

	require.NotEqual(t, baseID, mutate(func(c *Message) { c.NetworkID = 2 }))
	require.NotEqual(t, baseID, mutate(func(c *Message) { c.SourceChainID = ids.ID{0xFF} }))
	require.NotEqual(t, baseID, mutate(func(c *Message) { c.SourceNebulaRoot = [32]byte{0x99} }))
	require.NotEqual(t, baseID, mutate(func(c *Message) { c.SourceKeyEraID = 8 }))
	require.NotEqual(t, baseID, mutate(func(c *Message) { c.SourceGeneration = 12 }))
	require.NotEqual(t, baseID, mutate(func(c *Message) { c.HashSuiteID = "Pulsar-BLAKE3" }))
	require.NotEqual(t, baseID, mutate(func(c *Message) { c.Payload = []byte("base2") }))
}

// TestMessageNoSignTimeDefaulting proves the codec encodes HashSuiteID
// verbatim: an empty-suite message and a "Pulsar-SHA3" message produce DIFFERENT
// c14n bytes and DIFFERENT D. There is no defaulting inside the marshaler.
func TestMessageNoSignTimeDefaulting(t *testing.T) {
	empty := &Message{NetworkID: 1, SourceChainID: ids.ID{0xA1}, HashSuiteID: "", Payload: []byte("x")}
	resolved := &Message{NetworkID: 1, SourceChainID: ids.ID{0xA1}, HashSuiteID: DefaultHashSuiteID, Payload: []byte("x")}
	require.NotEqual(t, empty.Bytes(), resolved.Bytes())
	require.NotEqual(t, empty.ID(), resolved.ID())
	// HashSuiteOrDefault is a READ helper only — it does not change bytes.
	require.Equal(t, DefaultHashSuiteID, empty.HashSuiteOrDefault())
}

// TestParseMessageRejectsTrailing proves decode rejects trailing bytes.
func TestParseMessageRejectsTrailing(t *testing.T) {
	message, err := NewMessage(1, ids.ID{0xA1}, []byte("p"))
	require.NoError(t, err)
	b := message.Bytes()
	_, err = ParseMessage(append(b, 0x00))
	require.ErrorIs(t, err, errZapTrailing)
}

// TestParseMessageRejectsBadKind proves the zap kind discriminator is
// enforced.
func TestParseMessageRejectsBadKind(t *testing.T) {
	message, err := NewMessage(1, ids.ID{0xA1}, []byte("p"))
	require.NoError(t, err)
	b := message.Bytes()
	b[0] = 0x02 // not zapKindMessage
	_, err = ParseMessage(b)
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
	message, err := NewMessage(1, ids.ID{0xA1}, []byte("lanes"))
	require.NoError(t, err)
	d := message.ID()

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
