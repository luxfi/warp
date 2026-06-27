// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// classification.go — Horizon-final envelope-SHAPE classifiers. The
// post-quantum lane structure is documented in LP-105 ("Lux stack lexicon",
// Proof-lane classification subsection) and
// proofs/definitions/finality-definitions.tex Definition ref:proof-lane and
// Remark ref:groth16-not-pq.
//
// Two envelope-shape predicates ship here:
//
//   IsPQFinal(envelope) — true iff the envelope carries enough
//     certificate-lane evidence to be Horizon-final under Prism. A
//     Groth16 wrapper alone is NOT enough; a real Corona signature is required.
//
//   HorizonFinalErr(envelope) — returns an error explaining WHY an
//     envelope is not Horizon-final, or nil if it is.
//
// The proof-system PQ classifier IsPQRootOfTrust(provingSystem) is a
// subject-AGNOSTIC policy primitive and now lives in the warp ROOT package
// (warp.IsPQRootOfTrust) so both the warp envelope path AND the quasar
// consensus policy can reuse it without an import cycle. Use it from there.
//
// These helpers do NOT verify signatures; they classify the envelope
// SHAPE. Use VerifyWithOptions / VerifyPQLanes to check the bytes.

package pulsar

import (
	"errors"
	"strings"

	"github.com/luxfi/warp"
)

// ErrNotHorizonFinal is returned when an envelope cannot be lifted into
// a Horizon-final certificate. It typically means the envelope is
// missing one or more of the Beam / ML-DSA / Corona lanes that Prism
// requires (Definition ref:prism in finality-definitions.tex).
var ErrNotHorizonFinal = errors.New("warp pulsar: envelope is not Horizon-final")

// IsPQFinal reports whether the envelope carries enough evidence to
// be Horizon-final under Prism. The required shape, per
// proofs/definitions/finality-definitions.tex Definition
// ref:horizon-cert, is:
//
//   - A v1 Beam (BLS aggregate over the v1 Message). Always present;
//     the v1 Message field is non-nil.
//   - An ML-DSA cert set (either raw FIPS-204 signatures or a
//     compressed Groth16 rollup of those signatures). The shape is
//     the same on the wire.
//   - A Corona Ringtail signature — a real Module-LWE lattice threshold
//     signature over the envelope transcript. This is the PQ root of
//     trust; without it the envelope is not Horizon-final, regardless of
//     how impressive the wrapper proof attached to the ML-DSA lane is.
//
// In particular: an envelope carrying a Groth16 rollup of ML-DSA
// verification but no Corona signature is NOT Horizon-final. The Groth16
// wrapper is a classical compatibility / compression / privacy adapter
// (see warp.IsPQRootOfTrust); it does not contribute PQ liveness on its
// own.
func IsPQFinal(env *warp.Envelope) bool {
	if env == nil {
		return false
	}
	if !env.HasMLDSACertSet() {
		return false
	}
	if !env.HasCorona() {
		return false
	}
	return true
}

// HorizonFinalErr returns nil when env is Horizon-final-shaped, or
// ErrNotHorizonFinal wrapping a structured reason string when it is
// not. Use this in receivers that want to distinguish between
// "envelope shape OK, signature failed" (returned by VerifyV2) and
// "envelope shape inadmissible".
func HorizonFinalErr(env *warp.Envelope) error {
	if env == nil {
		return ErrNotHorizonFinal
	}
	missing := make([]string, 0, 3)
	if !env.HasMLDSACertSet() {
		missing = append(missing, "MLDSACertSet")
	}
	if !env.HasCorona() {
		missing = append(missing, "CoronaRingtail")
	}
	if len(missing) > 0 {
		return errors.New("warp pulsar: envelope missing required lanes: " + strings.Join(missing, ", "))
	}
	return nil
}
