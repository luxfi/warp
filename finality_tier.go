// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// finality_tier.go — the finality POLICY: typed tiers selecting which lane
// KINDS are required, orthogonal to verification (evidence.go) and to keys
// (pulsar_key.go / p3q.go).
//
// A tier maps to an AND-list of OR-groups of kinds. AcceptQuasarCert admits a
// cert iff EVERY group is satisfied by at least one present-and-verified lane,
// failing closed otherwise. Decomplected:
//
//	RequiredKinds(tier)      — pure policy: which kinds, in what AND/OR shape.
//	VerifyFinalityEvidence   — pure verification: does a lane's bytes check.
//	AcceptQuasarCert         — composes the two + the strict-root guardrails.
//
// Tiers:
//
//	BLS_FAST              → Beam                         (fast/speculative; no PQ)
//	HYBRID_PQ_CHECKPOINT  → Beam ∧ (Pulsar ∨ P3Q)       (PQ checkpoint)
//	STRICT_QUASAR         → Beam ∧ Pulsar ∧ Corona      (full dual-PQ finality)
//	RECOVERY              → Beam ∧ P3Q                   (+ optional cert-set avail.)
//
// GUARDRAILS enforced here:
//   - Pulsar is NOT required for BLS_FAST (fast/speculative blocks never block
//     on the PQ quorum lane).
//   - The raw cert-set is NEVER a required (strict) lane in any tier — it is
//     availability evidence, not a finality root.
//   - P3Q used to satisfy a required PQ lane MUST be a PQ root of trust
//     (P3QStrictRootOK) unless WithAllowClassicalP3QRoot is set — a Groth16
//     rollup can never be the strict-PQ root by default.

package warp

import (
	"errors"
	"fmt"
)

// FinalityTier selects the finality policy a QuasarCert is judged under.
type FinalityTier uint8

const (
	// TierBLSFast requires only the BLS Beam: the fast/speculative path. No PQ
	// lane is required, so a fast block never blocks on the threshold quorum.
	TierBLSFast FinalityTier = iota

	// TierHybridPQCheckpoint requires the Beam and AT LEAST ONE PQ lane
	// (Pulsar OR P3Q): a post-quantum checkpoint over the fast chain.
	TierHybridPQCheckpoint

	// TierStrictQuasar requires the Beam AND Pulsar AND Corona: full dual-PQ
	// (threshold ML-DSA ∧ lattice threshold) finality.
	TierStrictQuasar

	// TierRecovery requires the Beam AND a P3Q rollup: the recovery path that
	// reconstructs PQ finality from a succinct rollup of independent ML-DSA-65
	// signatures (optionally alongside a raw cert-set for availability).
	TierRecovery
)

// String renders the tier name.
func (t FinalityTier) String() string {
	switch t {
	case TierBLSFast:
		return "BLS_FAST"
	case TierHybridPQCheckpoint:
		return "HYBRID_PQ_CHECKPOINT"
	case TierStrictQuasar:
		return "STRICT_QUASAR"
	case TierRecovery:
		return "RECOVERY"
	default:
		return fmt.Sprintf("FinalityTier(%d)", uint8(t))
	}
}

// Policy errors.
var (
	// ErrNilQuasarCert is returned when AcceptQuasarCert is given no cert.
	ErrNilQuasarCert = errors.New("warp: nil quasar cert")

	// ErrUnknownFinalityTier is returned for a tier outside the defined set.
	ErrUnknownFinalityTier = errors.New("warp: unknown finality tier")

	// ErrMissingLane is returned when a required lane group is not satisfied by
	// any present-and-verified lane. Fail closed.
	ErrMissingLane = errors.New("warp: required finality lane absent or unverified")

	// ErrPolicyTierMismatch is returned when a cert's subject PolicyID does not
	// match the tier it is being judged under. Because PolicyID is folded into M,
	// a mismatch ALSO means the lanes' signatures are over a different subject —
	// so a cert minted under one tier can never be admitted under another
	// (tier-downgrade / cross-policy replay fails closed).
	ErrPolicyTierMismatch = errors.New("warp: cert PolicyID does not match the finality tier")
)

// PolicyIDForTier is the canonical PolicyID a QuasarFinalityParams carries when
// the decision is made under tier. It is folded into M (QuasarFinalityParams.
// PolicyID), so a signature commits to its tier and AcceptQuasarCert can reject
// a cert presented under a different tier than it was minted for. PolicyID is
// the tier's enum value (BLS_FAST=0 … RECOVERY=3) — each tier is distinct, and
// the signature over M(PolicyID) is what makes the binding unforgeable.
func PolicyIDForTier(tier FinalityTier) uint64 {
	return uint64(tier)
}

// RequiredKinds returns the tier's requirement as an AND-list of OR-groups.
// The cert must satisfy EVERY inner group with at least one present-and-
// verified lane. The cert-set kind appears in NO group: it is never a strict
// requirement. Returns nil for an unknown tier (AcceptQuasarCert maps that to
// ErrUnknownFinalityTier).
func RequiredKinds(tier FinalityTier) [][]FinalityEvidenceKind {
	switch tier {
	case TierBLSFast:
		return [][]FinalityEvidenceKind{
			{EvidenceBeamBLS},
		}
	case TierHybridPQCheckpoint:
		return [][]FinalityEvidenceKind{
			{EvidenceBeamBLS},
			{EvidencePulsarThresholdMLDSA, EvidenceP3QMLDSARollup},
		}
	case TierStrictQuasar:
		return [][]FinalityEvidenceKind{
			{EvidenceBeamBLS},
			{EvidencePulsarThresholdMLDSA},
			{EvidenceCoronaRingtail},
		}
	case TierRecovery:
		return [][]FinalityEvidenceKind{
			{EvidenceBeamBLS},
			{EvidenceP3QMLDSARollup},
		}
	default:
		return nil
	}
}

// acceptConfig holds AcceptQuasarCert options.
type acceptConfig struct {
	allowClassicalP3QRoot bool
}

// AcceptOption tunes AcceptQuasarCert.
type AcceptOption func(*acceptConfig)

// WithAllowClassicalP3QRoot explicitly opts in to admitting a P3Q root whose
// proof system is NOT post-quantum (e.g. a Groth16 rollup) as a strict-PQ
// finality lane. This is the deliberate, auditable escape hatch the guardrail
// demands: without it, a classical P3Q root is refused as a strict root.
func WithAllowClassicalP3QRoot() AcceptOption {
	return func(c *acceptConfig) { c.allowClassicalP3QRoot = true }
}

// AcceptQuasarCert decides whether cert meets the policy tier. It enumerates
// the cert's typed evidence (present = cert.Evidence()), and for each required
// OR-group verifies lanes over the subject M (cert.SubjectBytes()) using the
// injected verifiers + key resolvers (lanes). It fails closed if any required
// group is absent or unverified.
//
// This is the composition the task names: tier + present []FinalityEvidence +
// resolveKey (lanes.PulsarEra / lanes.SignerSet) + verify
// (VerifyFinalityEvidence). The strict-root guardrail (a classical P3Q root is
// refused) is enforced before a P3Q lane is allowed to satisfy a required PQ
// group, unless WithAllowClassicalP3QRoot is passed.
func AcceptQuasarCert(tier FinalityTier, cert *QuasarCert, lanes LaneVerifierSet, opts ...AcceptOption) error {
	if cert == nil {
		return ErrNilQuasarCert
	}
	groups := RequiredKinds(tier)
	if groups == nil {
		return fmt.Errorf("%w: %s", ErrUnknownFinalityTier, tier)
	}

	// Tier binding: the cert's subject PolicyID MUST be the one for this tier.
	// PolicyID is folded into M, so this is both an explicit policy check AND a
	// guarantee that the lanes' signatures are over THIS tier's subject — a cert
	// minted under a weaker tier cannot be replayed to satisfy a stronger one.
	if want := PolicyIDForTier(tier); cert.Subject.PolicyID != want {
		return fmt.Errorf("%w: cert PolicyID %d, tier %s wants %d",
			ErrPolicyTierMismatch, cert.Subject.PolicyID, tier, want)
	}

	var cfg acceptConfig
	for _, o := range opts {
		o(&cfg)
	}

	subject := cert.SubjectBytes()
	present := make(map[FinalityEvidenceKind]FinalityEvidence)
	for _, ev := range cert.Evidence() {
		present[ev.Kind] = ev
	}

	for _, group := range groups {
		if err := satisfyGroup(group, present, subject[:], lanes, cfg); err != nil {
			return err
		}
	}
	return nil
}

// satisfyGroup returns nil iff at least one kind in the OR-group is present in
// the cert AND verifies (and, for P3Q, passes the strict-PQ-root gate). It
// returns ErrP3QClassicalRoot HARD if a P3Q lane is REACHED as the candidate
// to satisfy a required group while backed by a classical proof system and the
// opt-in is absent — a classical rollup can never be the strict-PQ root by
// default. Otherwise it returns ErrMissingLane wrapping the last lane error.
func satisfyGroup(
	group []FinalityEvidenceKind,
	present map[FinalityEvidenceKind]FinalityEvidence,
	subject []byte,
	lanes LaneVerifierSet,
	cfg acceptConfig,
) error {
	var lastErr error
	anyPresent := false
	for _, k := range group {
		ev, ok := present[k]
		if !ok {
			continue
		}
		anyPresent = true

		// Strict-PQ-root guardrail: a P3Q root being RELIED ON to satisfy a
		// required lane must be PQ unless explicitly opted in. We only reach
		// this when no earlier lane in the group already satisfied the group,
		// so a classical P3Q alongside a valid Pulsar (checked first) is never
		// poisoned — only a P3Q that is actually load-bearing is gated.
		if k == EvidenceP3QMLDSARollup && !cfg.allowClassicalP3QRoot && ev.P3Q != nil {
			if err := P3QStrictRootOK(*ev.P3Q); err != nil {
				return err
			}
		}

		if err := VerifyFinalityEvidence(ev, subject, lanes); err != nil {
			lastErr = err
			continue
		}
		return nil
	}

	if !anyPresent {
		return fmt.Errorf("%w: tier requires one of %v", ErrMissingLane, group)
	}
	return fmt.Errorf("%w: no lane in %v verified: %v", ErrMissingLane, group, lastErr)
}
