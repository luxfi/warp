// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// quasar_cert.go — the QuasarCert: the consensus FINALITY object.
//
// A QuasarCert carries TYPED finality evidence over the consensus subject M —
// NOT a thousand raw validator signatures. Each lane is one compact object:
//
//	Beam     one BLS aggregate over M           (always present; the fast lane)
//	Pulsar   one threshold ML-DSA sig over M    (optional; the PQ quorum lane)
//	Corona   one Ringtail threshold sig over M  (optional; the PQ lattice lane)
//	P3QRoot  one succinct ML-DSA-65 rollup root (optional; recovery/compression)
//	CertSet  raw per-validator ML-DSA-65 certs  (optional; AVAILABILITY only —
//	         never a strict finality root, but auditable + the P3Q input)
//
// The cert is a CARRIER, exactly like the warp Envelope: it computes the
// subject (M) and hands typed lane evidence to the same subject-agnostic
// verifiers. Admissibility under a finality tier is decided by AcceptQuasarCert
// (finality_tier.go); this file only models the value and enumerates it.

package warp

// QuasarCert is the consensus finality certificate for a single decided block.
// Subject is the QuasarFinalitySubject params; Subject.* and the lane evidence
// together are what a receiver verifies and admits.
type QuasarCert struct {
	// Subject identifies the finalized decision. M = QuasarFinalitySubject(Subject)
	// is the digest every present lane signs.
	Subject QuasarFinalityParams

	// Lanes. Beam is structurally always present (the BLS aggregate). The PQ
	// lanes are optional; which combination is REQUIRED is a policy-tier
	// decision (AcceptQuasarCert), not a structural one.
	Beam    BitSetSignature
	Pulsar  *PulsarEvidence
	Corona  *CoronaEvidence
	P3QRoot *P3QRoot

	// CertSet is the optional raw ML-DSA-65 availability artifact. It is the
	// INPUT a P3Q rollup compresses and an accountable audit trail. It is
	// NEVER admissible as a strict finality root (IsStrictFinalityKind ==
	// false), so AcceptQuasarCert never counts it toward a required lane.
	CertSet *CertSetEvidence
}

// SubjectBytes returns M, the 32-byte consensus finality digest every present
// lane is verified over.
func (c *QuasarCert) SubjectBytes() [32]byte {
	return QuasarFinalitySubject(c.Subject)
}

// HasPulsar reports whether the cert carries a Pulsar threshold-ML-DSA lane.
func (c *QuasarCert) HasPulsar() bool { return c != nil && c.Pulsar != nil }

// HasCorona reports whether the cert carries a Corona Ringtail lane.
func (c *QuasarCert) HasCorona() bool { return c != nil && c.Corona != nil }

// HasP3Q reports whether the cert carries a P3Q rollup root.
func (c *QuasarCert) HasP3Q() bool { return c != nil && c.P3QRoot != nil }

// HasCertSet reports whether the cert carries a raw ML-DSA cert-set
// availability artifact.
func (c *QuasarCert) HasCertSet() bool { return c != nil && c.CertSet != nil }

// Evidence enumerates the typed finality-evidence lanes this cert carries,
// correct-by-construction (each lane paired with the suite its kind demands),
// mirroring Envelope.Evidence. The subject for these lanes is M
// (c.SubjectBytes()). Lanes appear only when present; the Beam is always
// present. The raw cert-set IS enumerated (it is recognized evidence), but
// IsStrictFinalityKind(EvidenceMLDSACertSet) is false so policy never admits it
// as a strict root.
func (c *QuasarCert) Evidence() []FinalityEvidence {
	if c == nil {
		return nil
	}
	out := make([]FinalityEvidence, 0, 5)
	out = append(out, FinalityEvidence{
		Kind:  EvidenceBeamBLS,
		Suite: SuiteBeamBLS12381,
		Beam:  &c.Beam,
	})
	if c.HasPulsar() {
		out = append(out, FinalityEvidence{
			Kind:   EvidencePulsarThresholdMLDSA,
			Suite:  c.Pulsar.SuiteID,
			Pulsar: c.Pulsar,
		})
	}
	if c.HasCorona() {
		out = append(out, FinalityEvidence{
			Kind:   EvidenceCoronaRingtail,
			Suite:  SuiteCoronaRingtailSHA3,
			Corona: c.Corona,
		})
	}
	if c.HasP3Q() {
		out = append(out, FinalityEvidence{
			Kind:  EvidenceP3QMLDSARollup,
			Suite: c.P3QRoot.SuiteID,
			P3Q:   c.P3QRoot,
		})
	}
	if c.HasCertSet() {
		out = append(out, FinalityEvidence{
			Kind:    EvidenceMLDSACertSet,
			Suite:   SuiteMLDSA65CertSetSHA3,
			CertSet: c.CertSet,
		})
	}
	return out
}
