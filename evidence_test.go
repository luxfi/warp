// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// evidence_test.go — the typed finality-evidence dispatch + policy tests.
// These pin the non-confusability invariants (KIND chooses the verifier, SUITE
// only parameterizes, a lane can NEVER route to the wrong verifier), the REAL
// Pulsar ML-DSA verify, the P3Q strict-root guardrail, the cert-set
// inadmissibility, the policy tiers, the canonical M subject, and the
// distinctness of the per-lane key registries.
//
// The spy verifiers (stubCoronaVerifier / stubCertSetVerifier) live in
// envelope_test.go and record whether they were called, so a "does not
// dispatch to X" test proves it by asserting X's spy was never invoked.

package warp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/luxfi/crypto/bls"
	mldsa65 "github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------
// Test fakes for the subject-agnostic lanes.
// ---------------------------------------------------------------------

type fakeBeamVerifier struct {
	called bool
	err    error
}

func (f *fakeBeamVerifier) VerifyBeam(_ []byte, _ BitSetSignature) error {
	f.called = true
	return f.err
}

type fakePulsarEraResolver struct {
	era PulsarKeyEra
	err error
}

func (f *fakePulsarEraResolver) ResolvePulsarKeyEra(_ ids.ID, _ uint64, _ uint64) (PulsarKeyEra, error) {
	return f.era, f.err
}

type fakeP3QVerifier struct {
	called bool
	err    error
	proven string // proof system the fake "verified"; empty → echoes root.ProvingSystem
}

func (f *fakeP3QVerifier) VerifyP3QRollup(_ []byte, root P3QRoot, _ SignerSetAuthority) (string, error) {
	f.called = true
	if f.err != nil {
		return "", f.err
	}
	if f.proven != "" {
		return f.proven, nil
	}
	return root.ProvingSystem, nil
}

type fakeSignerSetAuthority struct{}

func (fakeSignerSetAuthority) ResolveSignerSet(_ ids.ID, _ uint64) ([]ValidatorMLDSAKey, uint64, error) {
	return nil, 0, nil
}

// fullEvidenceEnvelope builds a Quasar envelope carrying all THREE wire lanes
// (Beam + Corona + MLDSACertSet) with deterministic opaque PQ-lane bytes.
func fullEvidenceEnvelope(t *testing.T) *Envelope {
	t.Helper()
	env := envelopeFixture(t) // Beam populated, message tag = MessageHashProfileTag
	env.CoronaSig = bytes.Repeat([]byte{0x42}, 64)
	env.MLDSACertSet = bytes.Repeat([]byte{0xC3}, 192)
	require.NoError(t, env.Verify())
	return env
}

// envSubject returns the warp subject D for an envelope.
func envSubject(e *Envelope) []byte {
	id := e.Message.ID()
	return id[:]
}

// ---------------------------------------------------------------------
// v1 invariants: non-confusable dispatch.
// ---------------------------------------------------------------------

// TestPulsarThresholdMLDSADoesNotDispatchToCorona proves Pulsar evidence
// routes ONLY to the (non-injectable) VerifyPulsar path — never to the corona
// verifier. With no Pulsar key-era resolver wired it fails closed, and the
// corona/cert-set spies are never touched.
func TestPulsarThresholdMLDSADoesNotDispatchToCorona(t *testing.T) {
	corona := &stubCoronaVerifier{err: errors.New("corona MUST NOT be called for Pulsar evidence")}
	certset := &stubCertSetVerifier{err: errors.New("cert-set MUST NOT be called for Pulsar evidence")}

	ev := FinalityEvidence{
		Kind:   EvidencePulsarThresholdMLDSA,
		Suite:  SuitePulsarThresholdMLDSA65,
		Pulsar: &PulsarEvidence{SuiteID: SuitePulsarThresholdMLDSA65, Signature: []byte{0x01}},
	}
	// No PulsarEra resolver → fail closed; corona/cert-set verifiers present but
	// must never be reached.
	err := verifyFinalityEvidence(ev, make([]byte, 32), LaneVerifierSet{Corona: corona, CertSet: certset})

	require.ErrorIs(t, err, ErrNoVerifierForKind,
		"Pulsar evidence must fail closed without a key-era resolver")
	require.False(t, corona.called, "Pulsar evidence dispatched to the corona verifier")
	require.False(t, certset.called, "Pulsar evidence dispatched to the cert-set verifier")
}

// TestPulsarThresholdMLDSADoesNotDispatchToCertSet is the cert-set-facing half
// of the same invariant.
func TestPulsarThresholdMLDSADoesNotDispatchToCertSet(t *testing.T) {
	certset := &stubCertSetVerifier{err: errors.New("cert-set MUST NOT be called for Pulsar evidence")}

	ev := FinalityEvidence{
		Kind:   EvidencePulsarThresholdMLDSA,
		Suite:  SuitePulsarThresholdMLDSA65,
		Pulsar: &PulsarEvidence{SuiteID: SuitePulsarThresholdMLDSA65, Signature: []byte{0x01}},
	}
	err := verifyFinalityEvidence(ev, make([]byte, 32), LaneVerifierSet{CertSet: certset})

	require.ErrorIs(t, err, ErrNoVerifierForKind)
	require.False(t, certset.called, "Pulsar evidence dispatched to the cert-set verifier")
}

// TestCoronaRingtailDoesNotDispatchToPulsar proves Corona evidence routes to
// the Ringtail verifier and never returns a Pulsar-domain error.
func TestCoronaRingtailDoesNotDispatchToPulsar(t *testing.T) {
	sentinel := errors.New("corona-verifier-reached")
	corona := &stubCoronaVerifier{err: sentinel}

	ev := FinalityEvidence{
		Kind:   EvidenceCoronaRingtail,
		Suite:  SuiteCoronaRingtailSHA3,
		Corona: &CoronaEvidence{Sig: bytes.Repeat([]byte{0x42}, 64)},
	}
	err := verifyFinalityEvidence(ev, make([]byte, 32), LaneVerifierSet{Corona: corona})

	require.True(t, corona.called, "corona evidence did not reach the corona verifier")
	require.ErrorIs(t, err, sentinel, "corona evidence must route to the corona verifier")
	require.NotErrorIs(t, err, ErrWrongEra, "corona evidence must NEVER produce a Pulsar-domain error")
	require.NotErrorIs(t, err, ErrBadSignature)
}

// TestMLDSACertSetDoesNotDispatchToPulsar proves cert-set evidence routes to
// the independent-cert verifier, never to the Pulsar path.
func TestMLDSACertSetDoesNotDispatchToPulsar(t *testing.T) {
	sentinel := errors.New("certset-verifier-reached")
	certset := &stubCertSetVerifier{err: sentinel}

	ev := FinalityEvidence{
		Kind:    EvidenceMLDSACertSet,
		Suite:   SuiteMLDSA65CertSetSHA3,
		CertSet: &CertSetEvidence{CertSet: bytes.Repeat([]byte{0xC3}, 192)},
	}
	err := verifyFinalityEvidence(ev, make([]byte, 32), LaneVerifierSet{CertSet: certset})

	require.True(t, certset.called, "cert-set evidence did not reach the cert-set verifier")
	require.ErrorIs(t, err, sentinel)
	require.NotErrorIs(t, err, ErrWrongEra,
		"cert-set evidence must NEVER produce a Pulsar-domain error")
}

// TestQuasarEnvelopeCarriesTypedEvidenceKinds pins Envelope.Evidence(): every
// carried lane is enumerated with the correct (kind, suite) pairing, and the
// reserved Pulsar/P3Q consensus kinds are NOT carried on the warp wire.
func TestQuasarEnvelopeCarriesTypedEvidenceKinds(t *testing.T) {
	env := fullEvidenceEnvelope(t)
	evs := env.Evidence()

	suiteByKind := make(map[FinalityEvidenceKind]SuiteID, len(evs))
	for _, ev := range evs {
		_, dup := suiteByKind[ev.Kind]
		require.False(t, dup, "duplicate evidence kind %q", ev.Kind)
		suiteByKind[ev.Kind] = ev.Suite
	}

	require.Equal(t, SuiteBeamBLS12381, suiteByKind[EvidenceBeamBLS])
	require.Equal(t, SuiteCoronaRingtailSHA3, suiteByKind[EvidenceCoronaRingtail])
	require.Equal(t, SuiteMLDSA65CertSetSHA3, suiteByKind[EvidenceMLDSACertSet])
	require.Len(t, evs, 3, "Beam + Corona + MLDSACertSet expected")
	require.NotContains(t, suiteByKind, EvidencePulsarThresholdMLDSA,
		"Pulsar is a consensus lane with NO warp wire field; it must not be enumerated")
	require.NotContains(t, suiteByKind, EvidenceP3QMLDSARollup,
		"P3Q is a consensus lane with NO warp wire field; it must not be enumerated")

	// The carried lanes hold their routing context, not an envelope back-ref.
	for _, ev := range evs {
		switch ev.Kind {
		case EvidenceBeamBLS:
			require.NotNil(t, ev.Beam)
		case EvidenceCoronaRingtail:
			require.NotNil(t, ev.Corona)
			require.Equal(t, env.Message.SourceKeyEraID, ev.Corona.KeyEraID)
			require.Equal(t, env.CoronaSig, ev.Corona.Sig)
		case EvidenceMLDSACertSet:
			require.NotNil(t, ev.CertSet)
			require.Equal(t, env.MLDSACertSet, ev.CertSet.CertSet)
		}
	}

	// A Beam-only envelope carries exactly one lane.
	beamOnly := envelopeFixture(t)
	beamEvs := beamOnly.Evidence()
	require.Len(t, beamEvs, 1)
	require.Equal(t, EvidenceBeamBLS, beamEvs[0].Kind)
}

// TestDefaultPulsarSuiteIsThresholdMLDSA pins the typed default — the NEW TALUS
// suite value.
func TestDefaultPulsarSuiteIsThresholdMLDSA(t *testing.T) {
	require.Equal(t, SuitePulsarThresholdMLDSA65, DefaultPulsarSuiteID)
	require.Equal(t, SuiteID("Lux-Pulsar-TALUS-MLDSA65"), DefaultPulsarSuiteID)
	// The Pulsar suite is distinct from every other lane suite.
	require.NotEqual(t, SuiteID(DefaultCoronaSuiteID), SuiteID(DefaultPulsarSuiteID))
	require.NotEqual(t, SuiteBeamBLS12381, DefaultPulsarSuiteID)
	require.NotEqual(t, SuiteMLDSA65CertSetSHA3, DefaultPulsarSuiteID)
	require.NotEqual(t, SuiteP3QMLDSARollup, DefaultPulsarSuiteID)
}

// TestDefaultCoronaSuiteIsRingtail pins the typed default and that it is NOT
// the legacy "Pulsar-SHA3" message tag — the decoupling that kills the alias.
func TestDefaultCoronaSuiteIsRingtail(t *testing.T) {
	require.Equal(t, SuiteCoronaRingtailSHA3, DefaultCoronaSuiteID)
	require.Equal(t, SuiteID("Corona-Ringtail-SHA3"), DefaultCoronaSuiteID)
	require.NotEqual(t, SuiteID(MessageHashProfileTag), SuiteID(DefaultCoronaSuiteID),
		"the corona lane suite must NOT be the message-level Pulsar-SHA3 tag")
}

// TestSuiteKindMismatchRejects proves requireSuite fails closed when a suite
// does not match its kind — and that a verifier is NOT reached when the suite
// guard fires (suite never selects a verifier; it only validates one).
func TestSuiteKindMismatchRejects(t *testing.T) {
	corona := &stubCoronaVerifier{}

	// Corona kind carrying the Beam suite: structurally inadmissible.
	ev := FinalityEvidence{
		Kind:   EvidenceCoronaRingtail,
		Suite:  SuiteBeamBLS12381,
		Corona: &CoronaEvidence{Sig: bytes.Repeat([]byte{0x42}, 64)},
	}
	err := verifyFinalityEvidence(ev, make([]byte, 32), LaneVerifierSet{Corona: corona})
	require.ErrorIs(t, err, ErrSuiteKindMismatch)
	require.False(t, corona.called, "the suite guard must fire BEFORE the verifier is reached")

	// Pulsar kind carrying the corona suite: rejected before any verify.
	evP := FinalityEvidence{
		Kind:   EvidencePulsarThresholdMLDSA,
		Suite:  SuiteCoronaRingtailSHA3,
		Pulsar: &PulsarEvidence{},
	}
	errP := verifyFinalityEvidence(evP, make([]byte, 32), LaneVerifierSet{})
	require.ErrorIs(t, errP, ErrSuiteKindMismatch)
	require.NotErrorIs(t, errP, ErrNoVerifierForKind)

	// An unknown kind fails closed too.
	evU := FinalityEvidence{Kind: "bogus-kind", Suite: SuiteBeamBLS12381}
	require.ErrorIs(t, verifyFinalityEvidence(evU, make([]byte, 32), LaneVerifierSet{}), ErrUnknownFinalityEvidence)
}

// goldenQuasarTypedEvidenceWireSHA256 is the SHA-256 of the canonical wire
// bytes of the golden full-evidence envelope below. The envelope wire is
// UNCHANGED by the typed-evidence refactor (the renames are Go-level; the
// message c14n / D / magic / kind bytes are byte-stable), so this fingerprint
// pins that stability.
const goldenQuasarTypedEvidenceWireSHA256 = "3747d25a12703f2cd20f1ebb370e582017b7a33a1f68afd7e72a48200542380b"

// TestGoldenQuasarTypedEvidenceRoundTrip pins a golden full-evidence envelope:
// its canonical wire bytes round-trip byte-equally, its typed evidence
// enumeration is stable, and the wire SHA-256 matches the golden fingerprint.
func TestGoldenQuasarTypedEvidenceRoundTrip(t *testing.T) {
	message := &Message{
		NetworkID:        1,
		SourceChainID:    ids.ID{0xA1, 0xA2, 0xA3, 0xA4},
		SourceNebulaRoot: [32]byte{0xDE, 0xAD, 0xBE, 0xEF},
		SourceKeyEraID:   7,
		SourceGeneration: 11,
		HashSuiteID:      MessageHashProfileTag,
		Payload:          []byte("quasar-typed-evidence-golden"),
	}
	signers := NewBitSet()
	signers.Add(0)
	signers.Add(2)
	signers.Add(4)
	var sig [bls.SignatureLen]byte
	copy(sig[:], bytes.Repeat([]byte{0xAB}, bls.SignatureLen))
	env, err := NewEnvelope(
		message,
		NewBitSetSignature(signers, sig),
		bytes.Repeat([]byte{0x42}, 64),  // Corona lane
		bytes.Repeat([]byte{0xC3}, 192), // MLDSACertSet lane
	)
	require.NoError(t, err)

	wire, err := env.Bytes()
	require.NoError(t, err)

	parsed, err := ParseEnvelope(wire)
	require.NoError(t, err)
	re, err := parsed.Bytes()
	require.NoError(t, err)
	require.Equal(t, wire, re, "envelope wire must round-trip byte-equal")
	require.Equal(t, env.ID(), parsed.ID(), "D must survive the round-trip")

	want := []struct {
		kind  FinalityEvidenceKind
		suite SuiteID
	}{
		{EvidenceBeamBLS, SuiteBeamBLS12381},
		{EvidenceCoronaRingtail, SuiteCoronaRingtailSHA3},
		{EvidenceMLDSACertSet, SuiteMLDSA65CertSetSHA3},
	}
	evs := parsed.Evidence()
	require.Len(t, evs, len(want))
	for i, w := range want {
		require.Equal(t, w.kind, evs[i].Kind)
		require.Equal(t, w.suite, evs[i].Suite)
	}

	gotSum := sha256.Sum256(wire)
	require.Equal(t, goldenQuasarTypedEvidenceWireSHA256, hex.EncodeToString(gotSum[:]),
		"golden Quasar envelope wire bytes changed")
}

// ---------------------------------------------------------------------
// Pulsar: REAL FIPS-204 ML-DSA-65 verify under a group public key.
// ---------------------------------------------------------------------

const (
	testPulsarKeyEraID   = uint64(5)
	testPulsarGeneration = uint64(2)
)

var testPulsarSignerSet = ids.ID{0x5A, 0x5A, 0x5A, 0x5A}

// signPulsar produces a real ML-DSA-65 quorum signature over subject under a
// fresh group key, plus the matching (era, evidence). It models exactly what
// the chain sees: an ordinary ML-DSA public key + an ordinary ML-DSA signature.
func signPulsar(t *testing.T, subject []byte) (PulsarEvidence, PulsarKeyEra, *mldsa65.PublicKey) {
	t.Helper()
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sig, err := mldsa65.Sign(sk, subject, pulsarLaneContext, false)
	require.NoError(t, err)

	ev := PulsarEvidence{
		SignerSetID: testPulsarSignerSet,
		KeyEraID:    testPulsarKeyEraID,
		Generation:  testPulsarGeneration,
		SuiteID:     SuitePulsarThresholdMLDSA65,
		Signature:   sig,
	}
	era := PulsarKeyEra{
		ChainID:     ids.ID{0xC0},
		SignerSetID: testPulsarSignerSet,
		KeyEraID:    testPulsarKeyEraID,
		Generation:  testPulsarGeneration,
		MLDSAPubKey: pk.Bytes(),
		SchemeID:    SuitePulsarThresholdMLDSA65,
		KeygenMode:  "talus-mpc",
	}
	return ev, era, pk
}

// TestPulsarVerifierAcceptsStandardMLDSAUnderGroupKey proves the Pulsar lane is
// a plain FIPS-204 ML-DSA verify: a real ML-DSA-65 signature over the subject,
// under the era's group public key, verifies — with NO threshold machinery in
// the path.
func TestPulsarVerifierAcceptsStandardMLDSAUnderGroupKey(t *testing.T) {
	subject := make([]byte, 32)
	copy(subject, []byte("pulsar-real-mldsa-subject"))
	ev, era, _ := signPulsar(t, subject)
	require.NoError(t, VerifyPulsar(ev, subject, era))

	// And through the dispatcher, with the era supplied by a resolver.
	fe := FinalityEvidence{Kind: EvidencePulsarThresholdMLDSA, Suite: SuitePulsarThresholdMLDSA65, Pulsar: &ev}
	require.NoError(t, verifyFinalityEvidence(fe, subject, LaneVerifierSet{
		PulsarEra: &fakePulsarEraResolver{era: era},
	}))
}

// TestPulsarRejectsWrongEra proves the era-identifier check fires before the
// signature check: evidence whose (keyEraID, generation, signerSetID) do not
// match the resolved era is rejected with ErrWrongEra.
func TestPulsarRejectsWrongEra(t *testing.T) {
	subject := make([]byte, 32)
	copy(subject, []byte("pulsar-wrong-era"))
	ev, era, _ := signPulsar(t, subject)

	wrong := ev
	wrong.KeyEraID = ev.KeyEraID + 1 // valid signature, wrong era handle
	require.ErrorIs(t, VerifyPulsar(wrong, subject, era), ErrWrongEra)

	wrongGen := ev
	wrongGen.Generation = ev.Generation + 1
	require.ErrorIs(t, VerifyPulsar(wrongGen, subject, era), ErrWrongEra)

	wrongSet := ev
	wrongSet.SignerSetID = ids.ID{0xFF}
	require.ErrorIs(t, VerifyPulsar(wrongSet, subject, era), ErrWrongEra)
}

// TestPulsarRejectsWrongGroupKey proves a valid signature under one group key
// does NOT verify under a different group key: the era identifiers match, but
// the ML-DSA verify fails closed with ErrBadSignature.
func TestPulsarRejectsWrongGroupKey(t *testing.T) {
	subject := make([]byte, 32)
	copy(subject, []byte("pulsar-wrong-key"))
	ev, era, _ := signPulsar(t, subject)

	// Swap in a DIFFERENT group public key (same era identifiers).
	otherPk, _, err := mldsa65.GenerateKey(rand.Reader)
	require.NoError(t, err)
	era.MLDSAPubKey = otherPk.Bytes()

	require.ErrorIs(t, VerifyPulsar(ev, subject, era), ErrBadSignature)

	// A wrong subject also fails closed under the right key.
	ev2, era2, _ := signPulsar(t, subject)
	other := make([]byte, 32)
	copy(other, []byte("a-completely-different-subject!!!"))
	require.ErrorIs(t, VerifyPulsar(ev2, other, era2), ErrBadSignature)
}

// ---------------------------------------------------------------------
// Policy: tiers, P3Q strict-root guardrail, cert-set inadmissibility.
// ---------------------------------------------------------------------

// quasarCertFixture builds a QuasarCert with a Beam plus a REAL Pulsar lane
// over M, returning the cert and the LaneVerifierSet that admits it (Beam and
// Corona verifiers accept; the Pulsar era resolves the real key).
func quasarCertFixture(t *testing.T) (*QuasarCert, LaneVerifierSet) {
	t.Helper()
	signers := NewBitSet()
	signers.Add(0)
	signers.Add(1)
	var beamSig [bls.SignatureLen]byte
	copy(beamSig[:], bytes.Repeat([]byte{0xAB}, bls.SignatureLen))

	cert := &QuasarCert{
		Subject: QuasarFinalityParams{
			ChainID:     ids.ID{0xC1, 0xC2},
			Height:      4242,
			Round:       7,
			BlockID:     ids.ID{0xB1, 0xB2},
			StateRoot:   [32]byte{0x57, 0xA7},
			SignerSetID: testPulsarSignerSet,
			KeyEraID:    testPulsarKeyEraID,
			PolicyID:    uint64(TierStrictQuasar),
		},
		Beam: NewBitSetSignature(signers, beamSig),
	}
	m := cert.SubjectBytes()
	ev, era, _ := signPulsar(t, m[:])
	cert.Pulsar = &ev
	cert.Corona = &CoronaEvidence{
		ChainID:    cert.Subject.ChainID,
		KeyEraID:   testPulsarKeyEraID,
		Generation: testPulsarGeneration,
		Sig:        bytes.Repeat([]byte{0x42}, 64),
	}

	lanes := LaneVerifierSet{
		Beam:      &fakeBeamVerifier{},
		Corona:    &stubCoronaVerifier{}, // err nil → accepts
		PulsarEra: &fakePulsarEraResolver{era: era},
	}
	return cert, lanes
}

// TestStrictQuasarRequiresBeamPulsarCorona proves the strict tier admits a cert
// carrying Beam ∧ Pulsar ∧ Corona, and fails closed (ErrMissingLane) when any
// required lane is dropped.
func TestStrictQuasarRequiresBeamPulsarCorona(t *testing.T) {
	require.Equal(t, [][]FinalityEvidenceKind{
		{EvidenceBeamBLS},
		{EvidencePulsarThresholdMLDSA},
		{EvidenceCoronaRingtail},
	}, RequiredKinds(TierStrictQuasar))

	cert, lanes := quasarCertFixture(t)
	require.NoError(t, AcceptQuasarCert(TierStrictQuasar, cert, lanes))

	// Drop Corona → strict tier fails closed.
	noCorona := *cert
	noCorona.Corona = nil
	require.ErrorIs(t, AcceptQuasarCert(TierStrictQuasar, &noCorona, lanes), ErrMissingLane)

	// Drop Pulsar → strict tier fails closed.
	noPulsar := *cert
	noPulsar.Pulsar = nil
	require.ErrorIs(t, AcceptQuasarCert(TierStrictQuasar, &noPulsar, lanes), ErrMissingLane)
}

// TestRecoveryTierAcceptsP3Q proves the recovery tier admits Beam ∧ P3Q when
// the P3Q rollup's proof system is post-quantum.
func TestRecoveryTierAcceptsP3Q(t *testing.T) {
	cert, lanes := quasarCertFixture(t)
	cert.Pulsar = nil
	cert.Corona = nil
	cert.P3QRoot = &P3QRoot{
		SignerSetID:   testPulsarSignerSet,
		ProvingSystem: "stark-rescue", // PQ root of trust
		SuiteID:       SuiteP3QMLDSARollup,
		Root:          bytes.Repeat([]byte{0x01}, 32),
		Proof:         bytes.Repeat([]byte{0x02}, 64),
	}
	lanes.P3Q = &fakeP3QVerifier{}
	lanes.SignerSet = fakeSignerSetAuthority{}
	cert.Subject.PolicyID = PolicyIDForTier(TierRecovery)

	require.NoError(t, AcceptQuasarCert(TierRecovery, cert, lanes))
	require.True(t, lanes.P3Q.(*fakeP3QVerifier).called, "recovery tier must reach the P3Q verifier")
}

// TestP3QClassicalRootRejectedAsStrictRoot proves a P3Q root backed by a
// CLASSICAL proof system (Groth16) is refused as a strict-PQ finality root —
// the bytes verifier is never even reached — unless policy explicitly opts in.
func TestP3QClassicalRootRejectedAsStrictRoot(t *testing.T) {
	cert, lanes := quasarCertFixture(t)
	cert.Pulsar = nil
	cert.Corona = nil
	p3qVerifier := &fakeP3QVerifier{}
	cert.P3QRoot = &P3QRoot{
		SignerSetID:   testPulsarSignerSet,
		ProvingSystem: "groth16", // classical — NOT a PQ root of trust
		SuiteID:       SuiteP3QMLDSARollup,
		Root:          bytes.Repeat([]byte{0x01}, 32),
	}
	lanes.P3Q = p3qVerifier
	lanes.SignerSet = fakeSignerSetAuthority{}
	cert.Subject.PolicyID = PolicyIDForTier(TierRecovery)

	err := AcceptQuasarCert(TierRecovery, cert, lanes)
	require.ErrorIs(t, err, ErrP3QClassicalRoot,
		"a Groth16 P3Q root must be refused as a strict-PQ finality root")
	require.False(t, p3qVerifier.called,
		"the strict-root guardrail must fire BEFORE the P3Q bytes verifier")

	// The deliberate, auditable opt-in admits it (and now reaches the verifier).
	require.NoError(t, AcceptQuasarCert(TierRecovery, cert, lanes, WithAllowClassicalP3QRoot()))
	require.True(t, p3qVerifier.called)

	// Direct gate check.
	require.ErrorIs(t, P3QStrictRootOK(*cert.P3QRoot), ErrP3QClassicalRoot)
	require.NoError(t, P3QStrictRootOK(P3QRoot{ProvingSystem: "lattice-zk"}))
}

// TestRawCertSetInadmissibleAsStrictFinality proves a raw ML-DSA cert-set is
// recognized but NEVER admissible as a strict finality root: it is in no tier's
// required kinds, so a cert carrying only Beam + CertSet fails every PQ tier.
func TestRawCertSetInadmissibleAsStrictFinality(t *testing.T) {
	require.False(t, IsStrictFinalityKind(EvidenceMLDSACertSet),
		"raw cert-set must never be a strict finality kind")
	require.True(t, IsStrictFinalityKind(EvidenceBeamBLS))
	require.True(t, IsStrictFinalityKind(EvidencePulsarThresholdMLDSA))
	require.True(t, IsStrictFinalityKind(EvidenceCoronaRingtail))
	require.True(t, IsStrictFinalityKind(EvidenceP3QMLDSARollup))

	// No tier's required kinds include the cert-set.
	for _, tier := range []FinalityTier{TierBLSFast, TierHybridPQCheckpoint, TierStrictQuasar, TierRecovery} {
		for _, group := range RequiredKinds(tier) {
			for _, k := range group {
				require.NotEqual(t, EvidenceMLDSACertSet, k,
					"tier %s must not require the cert-set as a strict lane", tier)
			}
		}
	}

	cert, lanes := quasarCertFixture(t)
	cert.Pulsar = nil
	cert.Corona = nil
	cert.CertSet = &CertSetEvidence{ChainID: cert.Subject.ChainID, CertSet: bytes.Repeat([]byte{0xC3}, 192)}
	lanes.CertSet = &stubCertSetVerifier{} // would accept the bytes if ever asked

	// Even though the cert-set verifies for AVAILABILITY, it cannot satisfy any
	// strict/PQ finality tier. Bind the cert's PolicyID to each tier so the
	// tier-check passes and the failure is specifically ErrMissingLane (the
	// strict lane is absent), not a policy mismatch.
	for _, tier := range []FinalityTier{TierStrictQuasar, TierRecovery, TierHybridPQCheckpoint} {
		cert.Subject.PolicyID = PolicyIDForTier(tier)
		require.ErrorIs(t, AcceptQuasarCert(tier, cert, lanes), ErrMissingLane, "tier %s", tier)
	}
}

// ---------------------------------------------------------------------
// The consensus subject M.
// ---------------------------------------------------------------------

// TestQuasarFinalitySubjectIsCanonical pins M's transcript: fixed length,
// lossless round-trip, deterministic digest, and total-order binding (changing
// ANY field changes M).
func TestQuasarFinalitySubjectIsCanonical(t *testing.T) {
	p := QuasarFinalityParams{
		ChainID:     ids.ID{0x01, 0x02, 0x03},
		Height:      99,
		Round:       3,
		BlockID:     ids.ID{0x0B, 0x0C},
		StateRoot:   [32]byte{0x57, 0xA7, 0xE0},
		SignerSetID: ids.ID{0x55},
		KeyEraID:    8,
		PolicyID:    uint64(TierStrictQuasar),
	}

	transcript := p.MarshalTranscript()
	require.Len(t, transcript, quasarFinalityTranscriptLen)

	// Lossless round-trip; re-marshal is byte-equal.
	parsed, err := ParseQuasarFinalityTranscript(transcript)
	require.NoError(t, err)
	require.Equal(t, p, parsed)
	require.Equal(t, transcript, parsed.MarshalTranscript())

	// Deterministic digest.
	require.Equal(t, QuasarFinalitySubject(p), QuasarFinalitySubject(p))

	// Non-canonical lengths are rejected.
	_, err = ParseQuasarFinalityTranscript(transcript[:len(transcript)-1])
	require.Error(t, err)
	_, err = ParseQuasarFinalityTranscript(append(transcript, 0x00))
	require.Error(t, err)

	// Total-order binding: every field changes M.
	base := QuasarFinalitySubject(p)
	mutators := []func(*QuasarFinalityParams){
		func(q *QuasarFinalityParams) { q.ChainID = ids.ID{0xFF} },
		func(q *QuasarFinalityParams) { q.Height++ },
		func(q *QuasarFinalityParams) { q.Round++ },
		func(q *QuasarFinalityParams) { q.BlockID = ids.ID{0xFF} },
		func(q *QuasarFinalityParams) { q.StateRoot = [32]byte{0xFF} },
		func(q *QuasarFinalityParams) { q.SignerSetID = ids.ID{0xFF} },
		func(q *QuasarFinalityParams) { q.KeyEraID++ },
		func(q *QuasarFinalityParams) { q.Generation++ },
		func(q *QuasarFinalityParams) { q.PChainHeight++ },
		func(q *QuasarFinalityParams) { q.PolicyID++ },
	}
	for i, mut := range mutators {
		q := p
		mut(&q)
		require.NotEqual(t, base, QuasarFinalitySubject(q), "field %d does not bind into M", i)
	}

	// M is domain-separated from the warp message digest D: an all-zero
	// transcript still differs from a raw keccak over the same zero bytes.
	require.NotEqual(t, keccak256(p.MarshalTranscript()), QuasarFinalitySubject(p))
}
