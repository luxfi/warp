// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// envelope_negative_test.go — transcript-binding tests over the Message
// fields the digest D commits to. Under the ZAP fork the signed subject is
// D = keccak256("LUX-WARP-ZAP-CORE-v1" ‖ zap_c14n(Message)); folding the
// PQ lineage into the message means every lane (BLS Beam included) binds it.
// For each transcript field we mutate the message and assert:
//
//	1. D changes.
//	2. An honest verifier (D-equality model) rejects the mutated message.
//	3. No two single-field mutations collide on D (orthogonality).

package warp

import (
	"testing"

	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

func negMessageFixture(t *testing.T) *Message {
	t.Helper()
	return &Message{
		NetworkID:        1,
		SourceChainID:    ids.ID{0xA1, 0xA2, 0xA3, 0xA4},
		SourceNebulaRoot: [32]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE},
		SourceKeyEraID:   7,
		SourceGeneration: 11,
		HashSuiteID:      DefaultHashSuiteID,
		Payload:          []byte("envelope-negative-test-payload"),
	}
}

// honestVerifier models a real lane verifier under an unchanged key: it
// accepts iff the candidate message's D equals the baseline's.
func honestVerifier(baseline *Message) func(c *Message) bool {
	d := baseline.ID()
	return func(c *Message) bool { return c.ID() == d }
}

func negMutateField(t *testing.T, base *Message, field string) *Message {
	t.Helper()
	c := *base
	switch field {
	case "network_id":
		c.NetworkID = base.NetworkID + 1000
	case "source_chain_id":
		c.SourceChainID = ids.ID{0xCA, 0xFE, 0xCA, 0xFE}
	case "nebula_root":
		c.SourceNebulaRoot = [32]byte{0x99, 0x88, 0x77, 0x66}
	case "key_era_id":
		c.SourceKeyEraID = base.SourceKeyEraID + 1000
	case "generation":
		c.SourceGeneration = base.SourceGeneration + 1000
	case "hash_suite_id":
		c.HashSuiteID = "Pulsar-BLAKE3"
	case "payload":
		c.Payload = append([]byte("X"), base.Payload...)
	default:
		t.Fatalf("unknown message field: %q", field)
	}
	return &c
}

var negFields = []string{
	"network_id",
	"source_chain_id",
	"nebula_root",
	"key_era_id",
	"generation",
	"hash_suite_id",
	"payload",
}

// TestMessageTranscriptMutationsRejected mutates each field and asserts D
// changes and the honest verifier rejects.
func TestMessageTranscriptMutationsRejected(t *testing.T) {
	base := negMessageFixture(t)
	baseID := base.ID()
	verify := honestVerifier(base)
	require.True(t, verify(base), "baseline must verify")

	for _, f := range negFields {
		t.Run(f, func(t *testing.T) {
			mutated := negMutateField(t, base, f)
			require.NotEqual(t, baseID, mutated.ID(), "mutation of %q did not change D", f)
			require.False(t, verify(mutated), "honest verifier accepted mutated %q", f)
		})
	}
}

// TestMessageTranscriptMutationsDistinct is the orthogonality check: no two
// single-field mutations collide on D.
func TestMessageTranscriptMutationsDistinct(t *testing.T) {
	base := negMessageFixture(t)
	seen := make(map[ids.ID]string, len(negFields))
	for _, f := range negFields {
		id := negMutateField(t, base, f).ID()
		if prev, ok := seen[id]; ok {
			t.Fatalf("D collision: %q and %q produce the same digest", prev, f)
		}
		seen[id] = f
	}
}

// TestHashSuiteExplicitVsEmptyBindDistinctly proves an explicit non-default
// suite produces a different D from the resolved-default message — the suite
// is bound verbatim, no sign-time defaulting.
func TestHashSuiteExplicitVsEmptyBindDistinctly(t *testing.T) {
	base := negMessageFixture(t)
	cp := *base
	cp.HashSuiteID = "Pulsar-BLAKE3"
	require.NotEqual(t, base.ID(), cp.ID())
}
