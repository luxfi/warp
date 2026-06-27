// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// security_profile.go — strict-PQ adapter for the Warp envelope.
//
// A Envelope ships three signature lanes side-by-side:
//
//   1. Classical BLS Beam over BLS12-381 (pairing-based,
//      Shor-vulnerable, the fast common-case verification path).
//   2. Corona Ringtail — Module-LWE lattice THRESHOLD signature over the
//      same transcript (the corona kernel; formerly mislabeled "Pulse").
//   3. ML-DSA cert set — FIPS 204 ML-DSA-65 attestations from the
//      signing validators (optional today, REQUIRED under strict-PQ).
//
// This file plugs Envelope into the canonical pq.Mode gate:
//
//   profile, err := pq.ModeFromString(chainCfg.WarpProfile)
//   if err := pq.ValidateMode(profile, env, verifyFn); err != nil {
//       // strict-PQ refused a classical-only envelope, or the
//       // PQ verification returned a non-nil error
//   }
//
// Warp's post-quantum AUTHORITY is the Corona Ringtail (Module-LWE THRESHOLD)
// lane — one O(1) aggregate over the transcript that scales to any validator
// set. The ML-DSA cert-set is an O(n) fallback (a per-signer attestation set,
// ~3.3 KB each: feasible for tiny sets, infeasible on-chain past ~hundreds of
// vdrs). So strict-PQ is satisfied by the Corona threshold ALONE; the cert-set
// is belt-and-suspenders, never the mandate. When neither PQ lane is present,
// strict-PQ refuses with pq.ErrClassicalAuthForbidden and hybrid falls back to
// the classical BLS Beam.
//
// (The Pulsar threshold ML-DSA lane is a separate, reserved, fail-closed
// evidence kind — see evidence.go — not the corona lane below.)

package warp

import "github.com/luxfi/pq"

// HasPQEvidence implements pq.PQEvidencer. Either PQ lane counts — the Corona
// Ringtail threshold is primary and O(1); the ML-DSA cert-set is the O(n)
// fallback. Repointing this from HasMLDSACertSet to HasCorona is load-bearing:
// without it, strict-PQ wrongly mandated the non-scaling cert-set and refused a
// Corona-only (the common, scalable) envelope.
func (e *Envelope) HasPQEvidence() bool {
	return e.HasCorona() || e.HasMLDSACertSet()
}

// VerificationLane reports which lane(s) the verifier MUST
// validate for a given mode + envelope. Bitwise mask:
//
//   - LaneClassical: BLS Beam.
//   - LanePQ:        the PQ lane(s) — Corona Ringtail threshold primary,
//     ML-DSA cert-set fallback.
//
// Routing rules:
//
//	classical                    → LaneClassical
//	hybrid + PQ evidence present → LanePQ
//	hybrid + no PQ evidence      → LaneClassical (stale-PQ warning)
//	strict-pq                    → LanePQ (gate refuses without PQ evidence)
type VerificationLane int

const (
	LaneClassical VerificationLane = 1 << iota
	LanePQ
)

// LanesForMode returns the bitwise set of lanes the verifier MUST validate.
// Pass env.HasPQEvidence() as hasPQEvidence for the hybrid fall-through (true
// when EITHER the Pulse threshold or the ML-DSA cert-set is present).
func LanesForMode(mode pq.Mode, hasPQEvidence bool) VerificationLane {
	switch mode {
	case pq.ModeStrictPQ:
		return LanePQ
	case pq.ModeHybrid:
		if hasPQEvidence {
			return LanePQ
		}
		return LaneClassical
	case pq.ModeClassical:
		return LaneClassical
	default:
		return LaneClassical
	}
}
