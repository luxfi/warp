// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// evidence.go — the typed finality-evidence model. This is the subject-
// AGNOSTIC core shared by BOTH finality contexts:
//
//	warp cross-chain    subject = D  (the Warp Message ID, keccak256 over c14n)
//	quasar consensus    subject = M  (QuasarFinalitySubject, see quasar_subject.go)
//
// A verifier never knows which context it serves; it verifies a lane's
// cryptographic object over an opaque subject []byte. The carrier
// (*Envelope for D, *QuasarCert for M) computes the subject and hands the
// verifier the typed lane evidence.
//
// FIVE finality-evidence KINDS exist. FOUR are STRICT (admissible as a
// finality root); ONE is recognized but NON-strict:
//
//	beam-bls                threshold/aggregate BLS over BLS12-381   STRICT
//	pulsar-threshold-mldsa  threshold ML-DSA — one compact PQ quorum STRICT
//	                        signature; verified as STANDARD FIPS-204
//	                        ML-DSA under a group public key (the TALUS
//	                        machinery is all OFFLINE — see VerifyPulsar)
//	corona-ringtail         Ringtail-derived Module-LWE lattice        STRICT
//	                        threshold (the corona kernel, M=8/N=7)
//	p3q-mldsa-rollup        succinct proof that a weighted quorum of   STRICT
//	                        independent ML-DSA-65 sigs verified (LP-218)
//	                        — STRICT only when its proof stack is PQ
//	mldsa-cert-set          raw independent per-validator ML-DSA-65    NON-STRICT
//	                        certificates — a fallback/audit AVAILABILITY
//	                        artifact and the INPUT to P3Q; NEVER a
//	                        strict finality root
//
// Verifier dispatch is IMPOSSIBLE TO CONFUSE. Two rules, decomplected:
//
//  1. KIND chooses the verifier. A FinalityEvidenceKind maps to exactly one
//     verifier. A SuiteID NEVER selects a verifier.
//  2. SUITE chooses the parameterization. After the verifier is chosen by
//     kind, requireSuite asserts the evidence's SuiteID is the one that kind
//     demands, failing closed with ErrSuiteKindMismatch otherwise.
//
// Historical bug this kills: a single message-level suite string
// ("Pulsar-SHA3") parameterized the corona-backed lane, so the suite string
// implied dispatch and "Pulsar" aliased Corona. Suites are now per-lane,
// typed, and never a verifier selector.

package warp

import (
	"errors"
	"fmt"
	"strings"

	"github.com/luxfi/ids"
)

// FinalityEvidenceKind names a finality-evidence lane. The KIND — never the
// suite — selects the verifier in verifyFinalityEvidence.
type FinalityEvidenceKind string

const (
	// EvidenceBeamBLS is the threshold/aggregate BLS lane (BLS12-381). STRICT.
	EvidenceBeamBLS FinalityEvidenceKind = "beam-bls"

	// EvidencePulsarThresholdMLDSA is the threshold ML-DSA lane: ONE compact
	// PQ signature representing quorum authorization. STRICT. It is verified
	// as a STANDARD FIPS-204 ML-DSA signature under a group public key (see
	// VerifyPulsar); the dealerless TALUS/BCC/CEF/nonce-DKG machinery that
	// PRODUCES it is entirely offline and never appears in the verify path.
	EvidencePulsarThresholdMLDSA FinalityEvidenceKind = "pulsar-threshold-mldsa"

	// EvidenceCoronaRingtail is the Ringtail-derived Module-LWE lattice
	// threshold lane (the corona kernel). STRICT.
	EvidenceCoronaRingtail FinalityEvidenceKind = "corona-ringtail"

	// EvidenceP3QMLDSARollup is the P3Q rollup lane (LP-218): a succinct
	// proof/root that a weighted quorum of independent ML-DSA-65 signatures
	// over the subject verified. STRICT — but ONLY when its underlying proof
	// system is itself post-quantum (see IsPQRootOfTrust / P3QStrictRootOK).
	EvidenceP3QMLDSARollup FinalityEvidenceKind = "p3q-mldsa-rollup"

	// EvidenceMLDSACertSet is the raw independent per-validator ML-DSA-65
	// certificate-set lane. RECOGNIZED but NON-STRICT: it is an availability /
	// audit / fallback artifact and the INPUT to a P3Q rollup. It is NEVER
	// admissible as a strict finality root (see IsStrictFinalityKind).
	EvidenceMLDSACertSet FinalityEvidenceKind = "mldsa-cert-set"
)

// SuiteID names the cryptographic parameterization of a lane. A SuiteID is
// validated AGAINST a kind (requireSuite); it is never used to choose a
// verifier.
type SuiteID string

const (
	// SuiteBeamBLS12381 parameterizes the Beam BLS lane.
	SuiteBeamBLS12381 SuiteID = "Beam-BLS12-381"

	// SuitePulsarThresholdMLDSA65 parameterizes the threshold ML-DSA lane.
	// The "TALUS" token names the offline dealerless threshold construction
	// that produces the signature; the on-wire object the verifier sees is a
	// plain FIPS-204 ML-DSA-65 signature.
	SuitePulsarThresholdMLDSA65 SuiteID = "Lux-Pulsar-TALUS-MLDSA65"

	// SuiteCoronaRingtailSHA3 parameterizes the Corona Ringtail lattice
	// threshold lane.
	SuiteCoronaRingtailSHA3 SuiteID = "Corona-Ringtail-SHA3"

	// SuiteP3QMLDSARollup parameterizes the P3Q ML-DSA-65 rollup lane.
	SuiteP3QMLDSARollup SuiteID = "P3Q-MLDSA65-Rollup-v1"

	// SuiteMLDSA65CertSetSHA3 parameterizes the raw independent ML-DSA-65
	// cert-set lane.
	SuiteMLDSA65CertSetSHA3 SuiteID = "MLDSA65-CertSet-SHA3"
)

// Per-lane suite defaults. These REPLACE the single former DefaultHashSuiteID,
// which conflated the corona lane's suite with the message-level c14n hash
// tag. Each lane is now parameterized by its OWN suite; a corona lane is
// parameterized by DefaultCoronaSuiteID, not by the message's "Pulsar-SHA3"
// c14n tag.
const (
	// DefaultBeamSuiteID is the default Beam lane suite.
	DefaultBeamSuiteID = SuiteBeamBLS12381

	// DefaultPulsarSuiteID is the default threshold ML-DSA lane suite.
	DefaultPulsarSuiteID = SuitePulsarThresholdMLDSA65

	// DefaultCoronaSuiteID is the default Corona Ringtail lane suite. The
	// lattice-threshold lane resolves to THIS, decoupled from the Message's
	// c14n hash tag.
	DefaultCoronaSuiteID = SuiteCoronaRingtailSHA3

	// DefaultP3QSuiteID is the default P3Q ML-DSA-65 rollup lane suite.
	DefaultP3QSuiteID = SuiteP3QMLDSARollup

	// DefaultMLDSACertSetSuiteID is the default raw ML-DSA-65 cert-set suite.
	DefaultMLDSACertSetSuiteID = SuiteMLDSA65CertSetSHA3
)

// strictFinalityKinds is the closed set of evidence kinds admissible as a
// finality ROOT. The cert-set is deliberately absent: it is an availability
// artifact, never a strict root. P3Q is in the set, but its strictness is
// further conditioned on a PQ proof system (P3QStrictRootOK).
var strictFinalityKinds = map[FinalityEvidenceKind]struct{}{
	EvidenceBeamBLS:              {},
	EvidencePulsarThresholdMLDSA: {},
	EvidenceCoronaRingtail:       {},
	EvidenceP3QMLDSARollup:       {},
}

// IsStrictFinalityKind reports whether kind may participate as a finality
// root. EvidenceMLDSACertSet returns false: raw cert sets are availability
// evidence and INPUT to P3Q, never a strict finality root.
func IsStrictFinalityKind(kind FinalityEvidenceKind) bool {
	_, ok := strictFinalityKinds[kind]
	return ok
}

// WeightThreshold is a quorum fraction (Numerator/Denominator) over the
// signer set's stake weight — the same shape VerifyWeight consumes. A lane
// that authorizes via a weighted quorum (Pulsar key-era, P3Q rollup) carries
// the threshold it was issued under so the verifier can re-check it.
type WeightThreshold struct {
	Numerator   uint64
	Denominator uint64
}

// Typed-evidence dispatch errors.
var (
	// ErrUnknownFinalityEvidence is returned when an evidence value carries a
	// kind the dispatcher does not recognize. Fail closed.
	ErrUnknownFinalityEvidence = errors.New("warp: unknown finality-evidence kind")

	// ErrSuiteKindMismatch is returned by requireSuite when an evidence
	// value's SuiteID is not the suite its KIND demands. This keeps suite
	// parameterization honest AFTER kind has chosen the verifier — a suite can
	// never cross-parameterize the wrong lane.
	ErrSuiteKindMismatch = errors.New("warp: finality-evidence suite does not match its kind")

	// ErrNoVerifierForKind is returned when a verifier is required for the
	// evidence's kind but none is configured in the LaneVerifierSet. Fail
	// closed — a missing verifier never silently passes.
	ErrNoVerifierForKind = errors.New("warp: no verifier configured for finality-evidence kind")

	// ErrMissingLaneData is returned when an evidence value's Kind does not
	// have its matching typed lane payload populated.
	ErrMissingLaneData = errors.New("warp: finality-evidence kind has no matching lane data")

	// ErrInvalidSubject is returned when a subject is not the required width
	// (a 32-byte digest: D for warp, M for quasar).
	ErrInvalidSubject = errors.New("warp: finality subject must be a 32-byte digest")

	// ErrWrongEra is returned by VerifyPulsar when the evidence's
	// (KeyEraID, Generation, SignerSetID) do not match the resolved key era.
	ErrWrongEra = errors.New("warp: finality evidence does not match the resolved key era")

	// ErrBadSignature is returned when a lane's signature fails verification.
	ErrBadSignature = errors.New("warp: finality-evidence signature did not verify")

	// ErrPulsarKeyEraUnresolved is returned when the PulsarKeyEraResolver
	// could not produce a key era for the evidence's identifiers.
	ErrPulsarKeyEraUnresolved = errors.New("warp: pulsar key-era resolver failed")

	// ErrCoronaKeyEraUnresolved is returned when the CoronaKeyEraResolver could
	// not produce a key era for the corona evidence's identifiers.
	ErrCoronaKeyEraUnresolved = errors.New("warp: corona key-era resolver failed")
)

// CoronaEvidence is the typed Corona Ringtail lane payload: the routing
// context a CoronaGroupKeyResolver needs (ChainID, KeyEraID, Generation) plus
// the serialized lattice threshold signature. The verifier frames the subject
// as CoronaSigningBytes(subject) and checks the corona kernel signature.
type CoronaEvidence struct {
	ChainID    ids.ID
	KeyEraID   uint64
	Generation uint64
	Sig        []byte
}

// CertSetEvidence is the typed raw ML-DSA-65 cert-set lane payload. EraHandle
// is the era selector the SignerSetAuthority resolves against (the source
// generation for a warp message, the block height for a quasar cert). This
// lane is verified for AVAILABILITY only — it is never a strict finality root
// (IsStrictFinalityKind(EvidenceMLDSACertSet) == false).
type CertSetEvidence struct {
	ChainID   ids.ID
	EraHandle uint64
	CertSet   []byte
}

// FinalityEvidence is ONE typed, carrier-agnostic finality-evidence lane.
// Kind selects the verifier; Suite is validated against the kind; exactly one
// lane payload pointer is non-nil and MUST correspond to Kind. No lane's bytes
// are interpreted by the kind string alone.
type FinalityEvidence struct {
	Kind  FinalityEvidenceKind
	Suite SuiteID

	// Exactly one of the following is set, matching Kind.
	Beam    *BitSetSignature // EvidenceBeamBLS
	Pulsar  *PulsarEvidence  // EvidencePulsarThresholdMLDSA
	Corona  *CoronaEvidence  // EvidenceCoronaRingtail
	P3Q     *P3QRoot         // EvidenceP3QMLDSARollup
	CertSet *CertSetEvidence // EvidenceMLDSACertSet (non-strict)
}

// requireSuite asserts ev.Suite is exactly the suite ev.Kind demands. It runs
// AFTER kind has chosen the verifier and NEVER chooses a verifier itself.
func requireSuite(ev FinalityEvidence, expected SuiteID) error {
	if ev.Suite != expected {
		return fmt.Errorf("%w: kind %q requires suite %q, got %q",
			ErrSuiteKindMismatch, ev.Kind, expected, ev.Suite)
	}
	return nil
}

// BeamVerifier verifies the BLS Beam aggregate over BeamSigningBytes(subject)
// against the lane's bound validator-set context. subject is D (warp) or M
// (quasar).
type BeamVerifier interface {
	VerifyBeam(subject []byte, beam BitSetSignature) error
}

// CoronaVerifier verifies the Corona Ringtail (Module-LWE) lattice-threshold
// lane over CoronaSigningBytes(subject). The implementation lives in
// warp/pulsar (RingtailVerifier) so the root package does not import the
// corona kernel.
type CoronaVerifier interface {
	VerifyRingtailThreshold(subject []byte, ev CoronaEvidence) error
}

// MLDSACertSetVerifier verifies the raw independent ML-DSA-65 cert-set lane
// over MLDSASigningBytes(subject). This proves AVAILABILITY of accountable
// per-validator certificates; admissibility as finality is a POLICY decision
// (it is never a strict root — see IsStrictFinalityKind).
type MLDSACertSetVerifier interface {
	VerifyCertSet(subject []byte, ev CertSetEvidence) error
}

// P3QRollupVerifier verifies a P3Q succinct proof/root (LP-218) that a
// weighted quorum of independent ML-DSA-65 signatures over the subject
// verified, against a signer-set authority. The real verifier (the Plonky3
// FRI rollup at precompile 0x012205) lives ABOVE warp and is injected; the
// warp verify path NEVER imports it.
type P3QRollupVerifier interface {
	// VerifyP3QRollup verifies the succinct rollup proof/root over subject
	// against the signer-set authority and MUST RETURN the proof system it
	// ACTUALLY verified (e.g. "stark-rescue"). The dispatcher rejects the lane
	// if the returned system differs from the evidence's claimed
	// P3QRoot.ProvingSystem — so the strict-PQ gate (P3QStrictRootOK), which
	// keys on that string, can never be fooled by a classical proof relabeled as
	// post-quantum. A verifier that cannot determine the system MUST fail.
	VerifyP3QRollup(subject []byte, root P3QRoot, authority SignerSetAuthority) (provenSystem string, err error)
}

// LaneVerifierSet bundles the lane verifiers + key resolvers a receiver
// injects. There is NO injectable Pulsar VERIFIER: the threshold-ML-DSA kind
// always verifies via the in-package, non-injectable VerifyPulsar (a standard
// FIPS-204 ML-DSA verify), so the verification ALGORITHM can never be swapped
// for a weaker one. Only the Pulsar KEY source (PulsarEra) is injectable. A
// nil verifier/resolver for a dispatched kind fails closed
// (ErrNoVerifierForKind).
//
// SECURITY PRECONDITIONS — the trust this verify path ultimately reduces to.
// They live OUTSIDE these files and MUST be guaranteed by the caller:
//   - Resolver authenticity: VerifyPulsar / VerifyCoronaEra / the P3Q verifier
//     trust the group key / signer set the injected resolver returns. Each
//     resolver MUST be backed by the authenticated on-chain key lineage
//     (Bootstrap/Reshare/Reanchor); a resolver returning an attacker's key
//     forges that lane.
//   - Per-lane key independence: STRICT_QUASAR's dual-PQ guarantee holds ONLY if
//     the Pulsar (ML-DSA) and Corona (lattice) group keys are independently
//     generated — no shared seed. A shared seed collapses dual-PQ to single-PQ.
type LaneVerifierSet struct {
	Beam      BeamVerifier
	Corona    CoronaVerifier
	CertSet   MLDSACertSetVerifier
	P3Q       P3QRollupVerifier
	PulsarEra PulsarKeyEraResolver
	CoronaEra CoronaKeyEraResolver
	SignerSet SignerSetAuthority
}

// verifyFinalityEvidence is the ONE finality-evidence dispatcher. It routes
// STRICTLY by ev.Kind, validates ev.Suite against that kind, requires the
// matching lane payload, and fails closed. A SuiteID alone can never select a
// verifier; subject is the opaque 32-byte digest (D or M) the lane is over.
//
//	EvidenceBeamBLS              → requireSuite(Beam)   → Beam BLS verifier
//	EvidencePulsarThresholdMLDSA → requireSuite(Pulsar) → VerifyPulsar (FIPS-204)
//	EvidenceCoronaRingtail       → requireSuite(Corona) → Ringtail verifier
//	EvidenceP3QMLDSARollup       → requireSuite(P3Q)    → P3Q rollup verifier
//	EvidenceMLDSACertSet         → requireSuite(CertSet)→ cert-set verifier
//	default                      → ErrUnknownFinalityEvidence
//
// This dispatcher verifies BYTES; it does NOT decide strict admissibility —
// that is the policy layer (AcceptQuasarCert). Decomplected: verify(bytes) is
// separate from admit(policy).
func verifyFinalityEvidence(ev FinalityEvidence, subject []byte, lanes LaneVerifierSet) error {
	switch ev.Kind {
	case EvidenceBeamBLS:
		if err := requireSuite(ev, SuiteBeamBLS12381); err != nil {
			return err
		}
		if ev.Beam == nil {
			return fmt.Errorf("%w: %s", ErrMissingLaneData, ev.Kind)
		}
		if lanes.Beam == nil {
			return fmt.Errorf("%w: %s", ErrNoVerifierForKind, ev.Kind)
		}
		return lanes.Beam.VerifyBeam(subject, *ev.Beam)

	case EvidencePulsarThresholdMLDSA:
		if err := requireSuite(ev, SuitePulsarThresholdMLDSA65); err != nil {
			return err
		}
		if ev.Pulsar == nil {
			return fmt.Errorf("%w: %s", ErrMissingLaneData, ev.Kind)
		}
		// INVARIANT: Pulsar verifies ONLY via VerifyPulsar (standard ML-DSA).
		// The verifier is non-injectable; only the key era is resolved.
		if lanes.PulsarEra == nil {
			return fmt.Errorf("%w: pulsar key-era resolver", ErrNoVerifierForKind)
		}
		era, err := lanes.PulsarEra.ResolvePulsarKeyEra(
			ev.Pulsar.SignerSetID, ev.Pulsar.KeyEraID, ev.Pulsar.Generation)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrPulsarKeyEraUnresolved, err)
		}
		return VerifyPulsar(*ev.Pulsar, subject, era)

	case EvidenceCoronaRingtail:
		if err := requireSuite(ev, SuiteCoronaRingtailSHA3); err != nil {
			return err
		}
		if ev.Corona == nil {
			return fmt.Errorf("%w: %s", ErrMissingLaneData, ev.Kind)
		}
		if lanes.Corona == nil {
			return fmt.Errorf("%w: %s", ErrNoVerifierForKind, ev.Kind)
		}
		// Era binding (symmetric with Pulsar): when a Corona key-era resolver is
		// configured, bind the evidence to its resolved era BEFORE the lattice
		// verify. The lattice-signature check itself is the CoronaVerifier's job
		// — it holds the corona kernel; this only pins (chain, era, generation).
		if lanes.CoronaEra != nil {
			era, err := lanes.CoronaEra.ResolveCoronaKeyEra(
				ev.Corona.ChainID, ev.Corona.KeyEraID, ev.Corona.Generation)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrCoronaKeyEraUnresolved, err)
			}
			if err := VerifyCoronaEra(*ev.Corona, era); err != nil {
				return err
			}
		}
		// INVARIANT: Corona verifies ONLY via the Ringtail verifier.
		return lanes.Corona.VerifyRingtailThreshold(subject, *ev.Corona)

	case EvidenceP3QMLDSARollup:
		if err := requireSuite(ev, SuiteP3QMLDSARollup); err != nil {
			return err
		}
		if ev.P3Q == nil {
			return fmt.Errorf("%w: %s", ErrMissingLaneData, ev.Kind)
		}
		if lanes.P3Q == nil {
			return fmt.Errorf("%w: %s", ErrNoVerifierForKind, ev.Kind)
		}
		// Verify the rollup bytes AND bind the proof system: the verifier returns
		// the system it actually proved, and we reject if it differs from the
		// claimed ProvingSystem. This authenticates the string the strict-PQ gate
		// (P3QStrictRootOK) keys on, so a classical proof relabeled "stark-rescue"
		// cannot slip through. Strict admissibility itself stays a policy decision
		// (AcceptQuasarCert).
		proven, err := lanes.P3Q.VerifyP3QRollup(subject, *ev.P3Q, lanes.SignerSet)
		if err != nil {
			return err
		}
		if !strings.EqualFold(strings.TrimSpace(proven), strings.TrimSpace(ev.P3Q.ProvingSystem)) {
			return fmt.Errorf("%w: claimed %q, verifier proved %q",
				ErrP3QProvingSystemMismatch, ev.P3Q.ProvingSystem, proven)
		}
		return nil

	case EvidenceMLDSACertSet:
		if err := requireSuite(ev, SuiteMLDSA65CertSetSHA3); err != nil {
			return err
		}
		if ev.CertSet == nil {
			return fmt.Errorf("%w: %s", ErrMissingLaneData, ev.Kind)
		}
		if lanes.CertSet == nil {
			return fmt.Errorf("%w: %s", ErrNoVerifierForKind, ev.Kind)
		}
		// INVARIANT: the cert-set verifies ONLY via the independent-cert
		// verifier — never via Pulsar. Availability only; never a strict root.
		return lanes.CertSet.VerifyCertSet(subject, *ev.CertSet)

	default:
		return fmt.Errorf("%w: %q", ErrUnknownFinalityEvidence, ev.Kind)
	}
}

// Evidence enumerates the typed finality-evidence lanes this warp envelope
// carries, correct-by-construction: each lane is paired with the suite its
// kind demands and the routing context a verifier needs. The subject for these
// lanes is the envelope's D (e.Message.ID()).
//
// The Beam (BLS) lane is structurally always present; the Corona and
// MLDSACertSet lanes appear only when their bytes are present. The Pulsar
// (threshold ML-DSA) and P3Q lanes are CONSENSUS lanes (over M) and have NO
// warp-envelope wire field — they are never enumerated here; see
// QuasarCert.Evidence.
func (e *Envelope) Evidence() []FinalityEvidence {
	if e == nil {
		return nil
	}
	out := make([]FinalityEvidence, 0, 3)
	out = append(out, FinalityEvidence{
		Kind:  EvidenceBeamBLS,
		Suite: SuiteBeamBLS12381,
		Beam:  &e.Beam,
	})
	if e.HasCorona() {
		out = append(out, FinalityEvidence{
			Kind:  EvidenceCoronaRingtail,
			Suite: SuiteCoronaRingtailSHA3,
			Corona: &CoronaEvidence{
				ChainID:    e.Message.SourceChainID,
				KeyEraID:   e.Message.SourceKeyEraID,
				Generation: e.Message.SourceGeneration,
				Sig:        e.CoronaSig,
			},
		})
	}
	if e.HasMLDSACertSet() {
		out = append(out, FinalityEvidence{
			Kind:  EvidenceMLDSACertSet,
			Suite: SuiteMLDSA65CertSetSHA3,
			CertSet: &CertSetEvidence{
				ChainID:   e.Message.SourceChainID,
				EraHandle: e.Message.SourceGeneration,
				CertSet:   e.MLDSACertSet,
			},
		})
	}
	return out
}
