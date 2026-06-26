// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// classification.go — Horizon-final / PQ-root-of-trust classification
// helpers. The post-quantum lane structure is documented in
// LP-105 ("Lux stack lexicon", Proof-lane classification subsection)
// and proofs/definitions/finality-definitions.tex Definition
// ref:proof-lane and Remark ref:groth16-not-pq.
//
// Three classification predicates ship here:
//
//   IsPQFinal(envelope) — true iff the envelope carries enough
//     certificate-lane evidence to be Horizon-final under Prism. A
//     Groth16 wrapper alone is NOT enough; a real Pulse is required.
//
//   IsPQRootOfTrust(provingSystem) — true iff the named succinct-proof
//     wrapper is post-quantum. Groth16 (pairing-based, broken under
//     Shor) returns false. STARK / lattice-based wrappers return true.
//
//   HorizonFinalErr(envelope) — returns an error explaining WHY an
//     envelope is not Horizon-final, or nil if it is.
//
// These helpers do NOT verify signatures; they classify the envelope
// SHAPE. Use VerifyV2 / VerifyPQLanes to check the bytes.

package pulsar

import (
	"errors"
	"strings"

	"github.com/luxfi/warp"
)

// ErrNotHorizonFinal is returned when an envelope cannot be lifted into
// a Horizon-final certificate. It typically means the envelope is
// missing one or more of the Beam / ML-DSA / Pulse lanes that Prism
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
//   - A Pulsar Pulse — a real lattice threshold signature over the
//     envelope transcript. This is the PQ root of trust; without it
//     the envelope is not Horizon-final, regardless of how impressive
//     the wrapper proof attached to the ML-DSA lane is.
//
// In particular: an envelope carrying a Groth16 rollup of ML-DSA
// verification but no Pulse is NOT Horizon-final. The Groth16 wrapper
// is a classical compatibility / compression / privacy adapter (see
// IsPQRootOfTrust below); it does not contribute PQ liveness on its
// own.
func IsPQFinal(env *warp.WarpEnvelope) bool {
	if env == nil {
		return false
	}
	if !env.HasMLDSACertSet() {
		return false
	}
	if !env.HasPulse() {
		return false
	}
	return true
}

// HorizonFinalErr returns nil when env is Horizon-final-shaped, or
// ErrNotHorizonFinal wrapping a structured reason string when it is
// not. Use this in receivers that want to distinguish between
// "envelope shape OK, signature failed" (returned by VerifyV2) and
// "envelope shape inadmissible".
func HorizonFinalErr(env *warp.WarpEnvelope) error {
	if env == nil {
		return ErrNotHorizonFinal
	}
	missing := make([]string, 0, 3)
	if !env.HasMLDSACertSet() {
		missing = append(missing, "MLDSACertSet")
	}
	if !env.HasPulse() {
		missing = append(missing, "PulsarPulse")
	}
	if len(missing) > 0 {
		return errors.New("warp pulsar: envelope missing required lanes: " + strings.Join(missing, ", "))
	}
	return nil
}

// IsPQRootOfTrust classifies a succinct-proof wrapper system by
// post-quantum status. Returns true iff the wrapper is BELIEVED to be
// post-quantum-secure under current cryptanalysis.
//
// Classification (per LP-105 Proof-lane classification table and
// proofs/definitions/finality-definitions.tex Definition
// ref:proof-lane):
//
//   "groth16", "groth16-bls12-381", "snark-pairing"
//     → false. Pairing-based; broken under Shor's algorithm.
//
//   "stark-rescue", "stark-poseidon", "lattice-zk"
//     → true. Hash- or lattice-based; PQ-friendly assumptions.
//
//   "none" or empty string
//     → true. No wrapper means the underlying signature itself is the
//     evidence; if that signature is Pulsar / ML-DSA, the PQ
//     root-of-trust lives in the signature directly.
//
//   anything else → false (conservative).
//
// The function is case-insensitive on the system name.
func IsPQRootOfTrust(provingSystem string) bool {
	switch strings.ToLower(strings.TrimSpace(provingSystem)) {
	case "groth16",
		"groth16-bls12-381",
		"snark-pairing":
		return false
	case "stark-rescue",
		"stark-poseidon",
		"lattice-zk":
		return true
	case "none",
		"":
		return true
	default:
		return false
	}
}
