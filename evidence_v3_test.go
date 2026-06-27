// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/luxfi/ids"
)

// --- v3 fakes (uniquely named to avoid colliding with other test helpers) ---

type v3RecBeam struct {
	got    []byte
	accept bool
}

func (r *v3RecBeam) VerifyBeam(subject []byte, _ BitSetSignature) error {
	r.got = append([]byte(nil), subject...)
	if r.accept {
		return nil
	}
	return ErrBadSignature
}

type v3RecP3Q struct {
	got    []byte
	accept bool
}

func (r *v3RecP3Q) VerifyP3QRollup(subject []byte, _ P3QRoot, _ SignerSetAuthority) error {
	r.got = append([]byte(nil), subject...)
	if r.accept {
		return nil
	}
	return ErrBadSignature
}

type v3StubPulsarEra struct{}

func (v3StubPulsarEra) ResolvePulsarKeyEra(ids.ID, uint64, uint64) (PulsarKeyEra, error) {
	return PulsarKeyEra{}, nil
}

type v3StubCoronaEra struct{}

func (v3StubCoronaEra) ResolveCoronaKeyEra(ids.ID, uint64, uint64) (CoronaKeyEra, error) {
	return CoronaKeyEra{}, nil
}

// TestPulsarVerifierHasNoThresholdImports proves the load-bearing invariant
// "Pulsar verification is boring; Pulsar signing is where TALUS lives": the
// package that holds VerifyPulsar (the root warp package) must NOT transitively
// import any of the offline threshold machinery — corona kernel, TALUS, BCC,
// CEF, CSCP, nonce pool, DKG, blame, reshare, pulsard/coronad. The only crypto
// the Pulsar verify needs is standard FIPS-204 ML-DSA (mldsa65).
func TestPulsarVerifierHasNoThresholdImports(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable in this environment: %v\n%s", err, out)
	}
	forbidden := []string{
		"corona", "talus", "pulsard", "coronad",
		"/dkg", "reshare", "noncepool", "/bcc", "/cef", "cscp", "blame",
	}
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.ToLower(strings.TrimSpace(line))
		if dep == "" {
			continue
		}
		for _, f := range forbidden {
			if strings.Contains(dep, f) {
				t.Errorf("package warp (holds VerifyPulsar) transitively imports %q (matched forbidden %q); "+
					"Pulsar verification must be standard ML-DSA only — threshold/TALUS machinery is offline-signer-side", dep, f)
			}
		}
	}
}

// TestPolicyIDSignedIntoSubjectDowngradeReplayFails proves a cert minted under a
// weaker tier cannot be replayed to satisfy a stronger one: PolicyID is folded
// into M and bound to the tier, so AcceptQuasarCert refuses a tier/PolicyID
// mismatch closed.
func TestPolicyIDSignedIntoSubjectDowngradeReplayFails(t *testing.T) {
	cert := &QuasarCert{
		Subject: QuasarFinalityParams{
			ChainID:  ids.GenerateTestID(),
			Height:   42,
			PolicyID: PolicyIDForTier(TierHybridPQCheckpoint),
		},
	}
	// Presented for STRICT acceptance → policy/tier mismatch, fail closed.
	if err := AcceptQuasarCert(TierStrictQuasar, cert, LaneVerifierSet{}); !errors.Is(err, ErrPolicyTierMismatch) {
		t.Fatalf("downgrade replay must fail with ErrPolicyTierMismatch, got %v", err)
	}
	// Control: under its OWN tier the policy check passes (it then fails for a
	// DIFFERENT reason — missing lanes — never ErrPolicyTierMismatch).
	if err := AcceptQuasarCert(TierHybridPQCheckpoint, cert, LaneVerifierSet{}); errors.Is(err, ErrPolicyTierMismatch) {
		t.Fatalf("cert under its own tier must not be a policy mismatch, got %v", err)
	}
}

// TestSubjectMismatchAcrossLanesFailsClosed proves every required lane is
// verified over the byte-identical subject (the cert's M), and that a lane whose
// signature is over a different subject makes the whole cert inadmissible.
func TestSubjectMismatchAcrossLanesFailsClosed(t *testing.T) {
	cert := &QuasarCert{
		Subject: QuasarFinalityParams{
			ChainID:  ids.GenerateTestID(),
			Height:   7,
			PolicyID: PolicyIDForTier(TierHybridPQCheckpoint),
		},
		Beam: BitSetSignature{},
		P3QRoot: &P3QRoot{
			ProvingSystem: "stark-rescue", // a PQ proof system → passes the strict gate
			SuiteID:       SuiteP3QMLDSARollup,
		},
	}
	M := cert.SubjectBytes()

	// Positive: Beam ∧ P3Q both verify over the IDENTICAL subject == cert M.
	beam := &v3RecBeam{accept: true}
	p3q := &v3RecP3Q{accept: true}
	if err := AcceptQuasarCert(TierHybridPQCheckpoint, cert, LaneVerifierSet{Beam: beam, P3Q: p3q}); err != nil {
		t.Fatalf("hybrid cert with valid lanes must accept, got %v", err)
	}
	if !bytes.Equal(beam.got, M[:]) {
		t.Fatalf("Beam lane verified over %x, want cert subject %x", beam.got, M[:])
	}
	if !bytes.Equal(p3q.got, M[:]) {
		t.Fatalf("P3Q lane verified over %x, want cert subject %x", p3q.got, M[:])
	}
	if !bytes.Equal(beam.got, p3q.got) {
		t.Fatal("Beam and P3Q lanes verified over DIFFERENT subjects; all required lanes must verify over the identical M")
	}

	// Fails closed: a lane that does not accept the cert's subject (its signature
	// was over a different subject) makes the cert inadmissible.
	if err := AcceptQuasarCert(TierHybridPQCheckpoint, cert, LaneVerifierSet{Beam: &v3RecBeam{accept: false}, P3Q: p3q}); err == nil {
		t.Fatal("a lane signed over a different subject must fail the cert closed")
	}
}

// TestCoronaAndPulsarKeyErasAreDistinctTypes proves the key registries cannot be
// aliased: a resolver for one threshold lane can never satisfy another's
// interface, so Pulsar, Corona and P3Q key material can never be confused.
func TestCoronaAndPulsarKeyErasAreDistinctTypes(t *testing.T) {
	var pr PulsarKeyEraResolver = v3StubPulsarEra{}
	if _, ok := any(pr).(CoronaKeyEraResolver); ok {
		t.Fatal("a PulsarKeyEraResolver must not also satisfy CoronaKeyEraResolver")
	}
	if _, ok := any(pr).(SignerSetAuthority); ok {
		t.Fatal("a PulsarKeyEraResolver must not also satisfy SignerSetAuthority")
	}
	var cr CoronaKeyEraResolver = v3StubCoronaEra{}
	if _, ok := any(cr).(PulsarKeyEraResolver); ok {
		t.Fatal("a CoronaKeyEraResolver must not also satisfy PulsarKeyEraResolver")
	}
	if _, ok := any(cr).(SignerSetAuthority); ok {
		t.Fatal("a CoronaKeyEraResolver must not also satisfy SignerSetAuthority")
	}
}
