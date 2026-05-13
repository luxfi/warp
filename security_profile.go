// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// security_profile.go — strict-PQ adapter for Warp EnvelopeV2.
//
// Warp 2.0 (EnvelopeV2) ships three signature lanes side-by-side:
//
//   1. Classical BLS Beam over BLS12-381 (pairing-based,
//      Shor-vulnerable, the fast common-case verification path).
//   2. Pulsar Pulse — threshold signature over the same transcript.
//   3. ML-DSA cert set — FIPS 204 ML-DSA-65 attestations from the
//      signing validators (optional today, REQUIRED under strict-PQ).
//
// This file plugs EnvelopeV2 into the canonical pq.Mode gate:
//
//   profile, err := pq.ModeFromString(chainCfg.WarpProfile)
//   if err := pq.ValidateMode(profile, env, verifyFn); err != nil {
//       // strict-PQ refused a classical-only envelope, or the
//       // ML-DSA verification returned a non-nil error
//   }
//
// EnvelopeV2 implements pq.PQEvidencer via HasMLDSACertSet — when
// the envelope carries an MLDSACertSet, the gate dispatches to
// the caller's verify closure; when absent, strict-PQ refuses with
// pq.ErrClassicalAuthForbidden, hybrid falls back to BLS Beam.

package warp

import "github.com/luxfi/pq"

// HasPQEvidence implements pq.PQEvidencer. Warp's PQ lane is the
// optional MLDSACertSet field on EnvelopeV2; presence means
// "validate via ML-DSA-65".
func (e *EnvelopeV2) HasPQEvidence() bool {
	return e.HasMLDSACertSet()
}

// VerificationLane reports which lane(s) the verifier MUST
// validate for a given mode + envelope. Bitwise mask:
//
//   • LaneClassical: BLS Beam.
//   • LanePQ:        MLDSACertSet (ML-DSA-65 attestations).
//
// Routing rules:
//
//   classical                       → LaneClassical
//   hybrid + MLDSACertSet present   → LanePQ
//   hybrid + MLDSACertSet absent    → LaneClassical (stale-PQ warning)
//   strict-pq                       → LanePQ (gate refuses without MLDSACertSet)
type VerificationLane int

const (
	LaneClassical VerificationLane = 1 << iota
	LanePQ
)

// LanesForMode returns the bitwise set of lanes the verifier
// MUST validate. Pass env.HasMLDSACertSet() as hasMLDSACertSet
// for the hybrid fall-through.
func LanesForMode(mode pq.Mode, hasMLDSACertSet bool) VerificationLane {
	switch mode {
	case pq.ModeStrictPQ:
		return LanePQ
	case pq.ModeHybrid:
		if hasMLDSACertSet {
			return LanePQ
		}
		return LaneClassical
	case pq.ModeClassical:
		return LaneClassical
	default:
		return LaneClassical
	}
}
