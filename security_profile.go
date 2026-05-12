// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// security_profile.go — strict-PQ posture gate for Warp envelopes.
//
// Warp 2.0 (EnvelopeV2) ships THREE signature lanes side-by-side:
//
//	1. Classical BLS Beam over BLS12-381 — pairing-based,
//	   Shor-vulnerable. Present in every envelope as the fast
//	   common-case verification path.
//	2. Pulsar Pulse — threshold signature over the same transcript;
//	   classification depends on the Pulsar HashSuiteID.
//	3. ML-DSA cert set — FIPS 204 ML-DSA-65 attestations from the
//	   signing validators (or a Z-Chain Groth16 rollup of them).
//	   Optional today; strict-PQ chains REQUIRE it.
//
// SecurityProfile names the chain's posture so the verifier knows
// which lane MUST be present and which lane SHOULD be ignored. A
// strict-PQ chain REFUSES a Warp envelope without an
// MLDSACertSet, even if the classical BLS Beam verifies — because
// the BLS Beam is not quantum-secure and a strict-PQ chain that
// trusted it would only be strict-PQ until a quantum adversary
// arrived.

package warp

import (
	"errors"
	"fmt"
)

// SecurityProfile is the Warp profile a Liquid chain pins. There
// is no middle ground: a chain is strict-PQ or it isn't.
//
//   - ProfileClassical — verifies BLS Beam; MLDSACertSet
//     ignored if absent. Today's default; equivalent to "Warp 2.0
//     without the PQ lane required".
//
//   - ProfileStrictPQ — REQUIRES MLDSACertSet on every envelope.
//     The BLS Beam still serializes (for cross-profile
//     compatibility during a migration window) but is NOT trusted
//     on its own. An envelope without an MLDSACertSet is refused
//     at the verification boundary with ErrClassicalAuthForbidden.
type SecurityProfile int

const (
	// ProfileClassical accepts envelopes without an MLDSACertSet.
	// Refuses to boot a strict-PQ Liquid chain.
	ProfileClassical SecurityProfile = iota

	// ProfileStrictPQ requires every envelope to carry an
	// MLDSACertSet. Canonical Liquid Warp profile.
	ProfileStrictPQ
)

// String returns the canonical wire name. Audit pipelines match
// on these strings; renaming here breaks every downstream consumer.
func (p SecurityProfile) String() string {
	switch p {
	case ProfileClassical:
		return "classical"
	case ProfileStrictPQ:
		return "strict-pq"
	default:
		return "unknown"
	}
}

// IsPostQuantum reports whether this profile rejects classical-
// only envelopes.
func (p SecurityProfile) IsPostQuantum() bool {
	return p == ProfileStrictPQ
}

// ProfileFromPQFlag lifts a chain-config "pq" boolean (the same
// flag liquidity/operator writes into the EVM, DEX, and FHE chain
// configs) into a Warp SecurityProfile. One JSON flag flips Warp,
// EVM, DEX, and FHE strict-PQ posture in lockstep.
func ProfileFromPQFlag(pq bool) SecurityProfile {
	if pq {
		return ProfileStrictPQ
	}
	return ProfileClassical
}

// ErrClassicalAuthForbidden is returned when a strict-PQ chain is
// handed a Warp envelope without an MLDSACertSet. The error
// message + name match the EVM precompile / DEX SignedOrder
// refusal so audit pipelines grep one identifier across every
// strict-PQ layer.
var ErrClassicalAuthForbidden = errors.New(
	"warp: classical authentication forbidden under strict-PQ profile (MLDSACertSet required)")

// RequireMLDSACertSetForProfile is the single seam every Warp
// verifier should call BEFORE validating the BLS Beam / Pulsar
// Pulse / ML-DSA cert set. It enforces the profile-level
// invariant that strict-PQ envelopes carry their PQ lane.
//
// Classical profile: always returns nil (BLS Beam is sufficient).
// Strict-PQ profile: returns ErrClassicalAuthForbidden if the
// envelope is missing an MLDSACertSet.
//
// Direct calls to Verify / BLS aggregate verification on a
// strict-PQ chain that bypass this gate would silently trust
// classical signatures — that's a bug. Routing through this
// helper keeps the gate at one place.
func RequireMLDSACertSetForProfile(profile SecurityProfile, env *EnvelopeV2) error {
	if !profile.IsPostQuantum() {
		return nil
	}
	if env == nil {
		return fmt.Errorf("warp: nil envelope under %s profile", profile)
	}
	if !env.HasMLDSACertSet() {
		return ErrClassicalAuthForbidden
	}
	return nil
}
