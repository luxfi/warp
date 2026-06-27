// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// resolver_distinctness_test.go — proves the THREE per-lane key registries are
// structurally DISTINCT types, so no implementation can ever serve two roles
// and Pulsar ↔ Corona ↔ P3Q key material can never be aliased. This lives in
// package pulsar because it is the only place that can see all three at once:
// warp.PulsarKeyEraResolver (one threshold ML-DSA group key),
// pulsar.CoronaGroupKeyResolver (one threshold lattice group key), and
// warp.SignerSetAuthority (independent per-validator keys for P3Q / cert-set).

package pulsar

import (
	"testing"

	corona "github.com/luxfi/corona/threshold"
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
	"github.com/stretchr/testify/require"
)

// Each fake implements EXACTLY ONE of the three resolver interfaces.

type onlyPulsarEra struct{}

func (onlyPulsarEra) ResolvePulsarKeyEra(ids.ID, uint64, uint64) (warp.PulsarKeyEra, error) {
	return warp.PulsarKeyEra{}, nil
}

type onlyCoronaResolver struct{}

func (onlyCoronaResolver) ResolveGroupKey([32]byte, uint64, uint64) (*corona.GroupKey, string, error) {
	return nil, "", nil
}

type onlySignerSet struct{}

func (onlySignerSet) ResolveSignerSet(ids.ID, uint64) ([]warp.ValidatorMLDSAKey, uint64, error) {
	return nil, 0, nil
}

// TestPulsarAndCoronaUseDistinctKeyResolvers proves an implementation of one
// lane's key registry can NEVER satisfy another lane's registry interface.
func TestPulsarAndCoronaUseDistinctKeyResolvers(t *testing.T) {
	var pulsarEra any = onlyPulsarEra{}
	var coronaRes any = onlyCoronaResolver{}
	var signerSet any = onlySignerSet{}

	// Each satisfies its OWN interface.
	_, ok := pulsarEra.(warp.PulsarKeyEraResolver)
	require.True(t, ok, "Pulsar fake must implement PulsarKeyEraResolver")
	_, ok = coronaRes.(CoronaGroupKeyResolver)
	require.True(t, ok, "Corona fake must implement CoronaGroupKeyResolver")
	_, ok = signerSet.(warp.SignerSetAuthority)
	require.True(t, ok, "SignerSet fake must implement SignerSetAuthority")

	// A Pulsar key-era resolver is NEITHER a Corona resolver NOR a signer-set
	// authority — the registries cannot be confused.
	_, ok = pulsarEra.(CoronaGroupKeyResolver)
	require.False(t, ok, "Pulsar resolver must not alias the Corona resolver")
	_, ok = pulsarEra.(warp.SignerSetAuthority)
	require.False(t, ok, "Pulsar resolver must not alias the signer-set authority")

	// A Corona resolver is NEITHER a Pulsar key-era resolver NOR a signer-set
	// authority.
	_, ok = coronaRes.(warp.PulsarKeyEraResolver)
	require.False(t, ok, "Corona resolver must not alias the Pulsar resolver")
	_, ok = coronaRes.(warp.SignerSetAuthority)
	require.False(t, ok, "Corona resolver must not alias the signer-set authority")

	// A signer-set authority (P3Q / cert-set) is NEITHER threshold resolver.
	_, ok = signerSet.(warp.PulsarKeyEraResolver)
	require.False(t, ok, "signer-set authority must not alias the Pulsar resolver")
	_, ok = signerSet.(CoronaGroupKeyResolver)
	require.False(t, ok, "signer-set authority must not alias the Corona resolver")
}
