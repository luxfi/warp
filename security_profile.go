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
	// BLS Beam is the trust root. Refuses to boot a strict-PQ
	// Liquid chain. Suitable for legacy Lux/Zoo chains that have
	// not yet generated ML-DSA validator material.
	ProfileClassical SecurityProfile = iota

	// ProfileHybrid runs classical + PQ side-by-side. Every
	// envelope still serializes the BLS Beam (for cross-profile
	// peer compatibility) and SHOULD also carry an MLDSACertSet.
	// The verifier:
	//   - if MLDSACertSet present → MUST verify under ML-DSA-65;
	//     a forged BLS Beam alone CANNOT promote a hybrid-profile
	//     envelope past acceptance.
	//   - if MLDSACertSet absent → falls back to BLS Beam
	//     verification with a "stale-PQ" warning event so audit
	//     pipelines can observe the migration cliff.
	// Hybrid is the safe migration middle: a chain can flip on
	// PQ validation today and turn off classical trust later,
	// without a hard cut-over that strands envelopes already in
	// flight at the migration boundary.
	ProfileHybrid

	// ProfileStrictPQ requires every envelope to carry an
	// MLDSACertSet AND refuses to trust the BLS Beam as the auth
	// root. Canonical Liquid Warp profile. The Beam still
	// serializes (so a strict-PQ chain can ECHO envelopes to a
	// classical chain across a bridge) but the Beam bytes are
	// NEVER the verification root on a strict-PQ chain.
	ProfileStrictPQ
)

// String returns the canonical wire name. Audit pipelines match
// on these strings; renaming here breaks every downstream consumer.
func (p SecurityProfile) String() string {
	switch p {
	case ProfileClassical:
		return "classical"
	case ProfileHybrid:
		return "hybrid"
	case ProfileStrictPQ:
		return "strict-pq"
	default:
		return "unknown"
	}
}

// IsPostQuantum reports whether this profile REJECTS classical-
// only envelopes (no MLDSACertSet → refuse). Hybrid is NOT
// strict-PQ in this sense — it allows classical-only envelopes
// with a stale-PQ warning. Only strict-PQ returns true.
func (p SecurityProfile) IsPostQuantum() bool {
	return p == ProfileStrictPQ
}

// IsPQAware reports whether this profile validates an
// MLDSACertSet WHEN PRESENT. Both Hybrid and StrictPQ return
// true; only Classical ignores the field.
func (p SecurityProfile) IsPQAware() bool {
	return p == ProfileHybrid || p == ProfileStrictPQ
}

// ProfileFromPQFlag lifts a chain-config "pq" boolean (the same
// flag liquidity/operator writes into the EVM, DEX, and FHE chain
// configs) into a Warp SecurityProfile. One JSON flag flips Warp,
// EVM, DEX, and FHE strict-PQ posture in lockstep.
//
// Hybrid is not selectable via the boolean flag — operators that
// want hybrid pin the profile explicitly via ProfileFromString or
// the operator-level config field. The boolean is intentionally
// binary: a chain that wants strict-PQ shouldn't have a fallback
// path opened by a future operator turning the same flag from
// true → "hybrid". Strict-PQ is a one-way door.
func ProfileFromPQFlag(pq bool) SecurityProfile {
	if pq {
		return ProfileStrictPQ
	}
	return ProfileClassical
}

// ProfileFromString parses an operator-supplied profile string.
// Refuses unknown values rather than defaulting; the gate at
// every layer assumes the profile is well-known.
func ProfileFromString(s string) (SecurityProfile, error) {
	switch s {
	case "classical":
		return ProfileClassical, nil
	case "hybrid":
		return ProfileHybrid, nil
	case "strict-pq":
		return ProfileStrictPQ, nil
	default:
		return ProfileClassical, fmt.Errorf("warp: unknown profile %q (want classical|hybrid|strict-pq)", s)
	}
}

// ErrClassicalAuthForbidden is returned when a strict-PQ chain is
// handed a Warp envelope without an MLDSACertSet. The error
// message + name match the EVM precompile / DEX SignedOrder
// refusal so audit pipelines grep one identifier across every
// strict-PQ layer.
var ErrClassicalAuthForbidden = errors.New(
	"warp: classical authentication forbidden under strict-PQ profile (MLDSACertSet required)")

// VerificationLane reports which lane(s) the profile says the
// verifier MUST validate to accept an envelope.
//
//   - LaneClassical: classical BLS Beam.
//   - LanePQ: FIPS 204 ML-DSA-65 attestations in MLDSACertSet.
type VerificationLane int

const (
	LaneClassical VerificationLane = 1 << iota
	LanePQ
)

// LanesForProfile returns the bitwise set of lanes a verifier
// MUST validate. Pass the envelope's HasMLDSACertSet() result
// for the hybrid fall-through: hybrid + MLDSACertSet present →
// LanePQ only (BLS Beam is best-effort); hybrid + absent →
// LaneClassical with a stale-PQ warning the caller should log.
//
//	classical                    → LaneClassical
//	hybrid + MLDSACertSet present → LanePQ
//	hybrid + MLDSACertSet absent  → LaneClassical (with warning)
//	strict-pq                    → LanePQ (envelope MUST have MLDSACertSet)
func LanesForProfile(profile SecurityProfile, hasMLDSACertSet bool) VerificationLane {
	switch profile {
	case ProfileStrictPQ:
		return LanePQ
	case ProfileHybrid:
		if hasMLDSACertSet {
			return LanePQ
		}
		return LaneClassical
	case ProfileClassical:
		return LaneClassical
	default:
		// Unknown profile defaults to classical — but RequireMLDSACertSetForProfile
		// will refuse it explicitly at the gate before we get here.
		return LaneClassical
	}
}

// RequireMLDSACertSetForProfile is the single seam every Warp
// verifier should call BEFORE validating the BLS Beam / Pulsar
// Pulse / ML-DSA cert set. It enforces the profile-level
// invariant about which lane MUST be present.
//
//   - ProfileClassical: returns nil (BLS Beam alone is sufficient).
//   - ProfileHybrid: returns nil regardless — the verifier
//     can fall back to BLS Beam if MLDSACertSet is absent.
//   - ProfileStrictPQ: returns ErrClassicalAuthForbidden if the
//     envelope is missing an MLDSACertSet.
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
