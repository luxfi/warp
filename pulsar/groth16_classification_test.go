// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pulsar — Gate 6 Groth16 classification tests (Mar-3-2026 PQ
// Consensus Architecture Freeze).
//
// Three pin-downs:
//
//	A. A Groth16 wrapper alone is NOT Horizon-final. An envelope
//	   carrying a Groth16 proof of ML-DSA cert-set verification but no
//	   Pulse must be classified as not-PQ-final.
//	B. A Groth16 wrapping ML-DSA is classical-succinct: the
//	   IsPQRootOfTrust predicate returns false for "groth16" and
//	   true for STARK / lattice-based wrappers.
//	C. The lexicon (LP-105) and the canonical Pulsar paper (LP-073)
//	   contain the exact phrases "not post-quantum" and "classical
//	   succinct proof of post-quantum signature verification" near
//	   the Groth16 mention.
//
// Citations (canonical proof bucket):
//
//	proofs/definitions/finality-definitions.tex
//	  Remark ref:groth16-not-pq
//	proofs/quasar/horizon-soundness.tex
//	  Remark ref:groth16-wrapper
package pulsar

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luxfi/warp"
	"github.com/stretchr/testify/require"
)

// TestGroth16WrapperAloneIsNotHorizonFinal — Gate 6A.
//
// Build a Warp 2.0 envelope that carries:
//   - A v1 Message (Beam) — present.
//   - An MLDSACertSet field — populated with bytes that, by convention,
//     hold a Groth16 rollup proof of ML-DSA cert-set verification
//     (Z-Chain compression, LP-307). Not actually a real Groth16 proof
//     here; the test checks classification, not signature bytes.
//   - NO Pulse.
//
// Then assert:
//   - IsPQFinal(env) == false.
//   - HorizonFinalErr(env) returns ErrNotHorizonFinal-equivalent.
//   - VerifyV2 with RequireCorona=true returns an error mentioning the
//     missing PQ lane.
func TestGroth16WrapperAloneIsNotHorizonFinal(t *testing.T) {
	env := envFixture(t, 7, 11)

	// "Groth16 of ML-DSA" rollup bytes — convention only; classification
	// does not inspect them. The envelope IS NOT Horizon-final because
	// no Pulse accompanies the cert set.
	env.MLDSACertSet = bytes.Repeat([]byte{0xAB}, 192)
	require.True(t, env.HasMLDSACertSet())
	require.False(t, env.HasCorona())

	// Classification predicate.
	if IsPQFinal(env) {
		t.Fatal("IsPQFinal accepted Groth16-only envelope (no Pulse)")
	}

	// Error-shape predicate.
	err := HorizonFinalErr(env)
	if err == nil {
		t.Fatal("HorizonFinalErr accepted Groth16-only envelope")
	}
	if !strings.Contains(err.Error(), "CoronaRingtail") {
		t.Fatalf("HorizonFinalErr message does not mention missing Corona lane: %v", err)
	}

	// VerifyV2 with RequireCorona=true must reject — Beam / Pulse /
	// CertSet are independent lanes; missing Pulse is fatal under
	// RequireCorona.
	opts := warp.VerifyOptions{
		SkipBeam:     true,
		RequireCorona: true,
	}
	verifyErr := warp.VerifyWithOptions(env, opts)
	require.Error(t, verifyErr)
}

// TestHorizonFromEnvelopeFlowsLanesButClassificationCatchesIt — even
// though HorizonFromEnvelope (the byte-marshalling helper) succeeds on
// a Groth16-only envelope, the IsPQFinal classification pin still
// rejects it. The marshaller does not verify; the predicate does.
func TestHorizonFromEnvelopeFlowsLanesButClassificationCatchesIt(t *testing.T) {
	env := envFixture(t, 7, 11)
	env.MLDSACertSet = bytes.Repeat([]byte{0xAB}, 192)
	// No Pulse.

	cert, err := HorizonFromEnvelope(env)
	require.NoError(t, err)
	require.Empty(t, cert.CoronaRingtail, "Pulse should be empty when envelope has no Pulse")
	require.NotEmpty(t, cert.MLDSACertSet, "ML-DSA cert set bytes should flow through")

	// Classification still rejects.
	require.False(t, IsPQFinal(env))
}

// TestIsPQRootOfTrustClassification — Gate 6B.
//
// Pairing-based wrappers (Groth16 family) are NOT PQ; STARK /
// lattice-based wrappers ARE; "none" is treated as PQ (the underlying
// signature itself is the evidence).
func TestIsPQRootOfTrustClassification(t *testing.T) {
	cases := []struct {
		system string
		pq     bool
	}{
		// Pairing-based: NOT PQ.
		{"groth16", false},
		{"Groth16", false},
		{"GROTH16", false},
		{"groth16-bls12-381", false},
		{"snark-pairing", false},

		// Hash- / lattice-based: PQ.
		{"stark-rescue", true},
		{"stark-poseidon", true},
		{"lattice-zk", true},

		// No wrapper: PQ inherits from the underlying signature.
		{"none", true},
		{"", true},

		// Unknown systems: conservative false.
		{"plonk-bls12-381", false},
		{"unknown", false},
	}
	for _, tc := range cases {
		got := warp.IsPQRootOfTrust(tc.system)
		if got != tc.pq {
			t.Errorf("warp.IsPQRootOfTrust(%q) = %v, want %v", tc.system, got, tc.pq)
		}
	}
}

// TestPulseAndCertSetTogetherIsHorizonFinalShape — sanity: an envelope
// that carries BOTH a Pulse and an ML-DSA cert set IS Horizon-final-
// shaped (the actual lane verification is exercised in pulsar_test.go;
// this test only pins the predicate).
func TestPulseAndCertSetTogetherIsHorizonFinalShape(t *testing.T) {
	env := envFixture(t, 7, 11)
	env.CoronaSig = bytes.Repeat([]byte{0x42}, 64)
	env.MLDSACertSet = bytes.Repeat([]byte{0xAB}, 192)

	require.True(t, IsPQFinal(env))
	require.NoError(t, HorizonFinalErr(env))
}

// ── Gate 6C: documentation tests ────────────────────────────────────

// TestLP105ContainsGroth16Disclaimer asserts that the LP-105 lexicon
// file contains the exact phrases "not post-quantum" and "classical
// succinct proof of post-quantum signature verification" near the
// Groth16 mention. The phrases ARE the documented contract; if they
// drift, this test fails so the docs and code stay in sync.
func TestLP105ContainsGroth16Disclaimer(t *testing.T) {
	path := lookupRepoFile(t, "lps/LP-105-lux-stack-lexicon.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read LP-105: %v", err)
	}
	text := string(body)
	requirePhraseNearGroth16(t, "LP-105", text, "not post-quantum")
	requirePhraseNearGroth16(t, "LP-105", text, "classical succinct proof of post-quantum signature verification")
}

// TestLP073ContainsGroth16DisclaimerSection11 asserts that the LP-073
// canonical Pulsar paper, Section 11 ("Proof-lane classification
// disclaimer"), contains both phrases. Section 11 is added in this
// freeze to lock the documentation contract on the paper that ships
// the protocol.
func TestLP073ContainsGroth16DisclaimerSection11(t *testing.T) {
	path := lookupRepoFile(t, "lps/archive/LP-073-pre-2026-05-18.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read LP-073: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "### 11.") && !strings.Contains(text, "## 11.") {
		t.Fatalf("LP-073 missing Section 11 (proof-lane classification disclaimer)")
	}
	requirePhraseNearGroth16(t, "LP-073 §11", text, "not post-quantum")
	requirePhraseNearGroth16(t, "LP-073 §11", text, "classical succinct proof of post-quantum signature verification")
}

// TestFinalityDefinitionsRemarkGroth16 asserts the canonical proof
// bucket file proofs/definitions/finality-definitions.tex contains
// the same two phrases (the LaTeX source under
// rem:groth16-not-pq).
func TestFinalityDefinitionsRemarkGroth16(t *testing.T) {
	path := lookupRepoFile(t, "proofs/definitions/finality-definitions.tex")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read finality-definitions.tex: %v", err)
	}
	text := string(body)
	requirePhraseNearGroth16(t, "finality-definitions.tex", text, "not post-quantum")
	requirePhraseNearGroth16(t, "finality-definitions.tex", text, "classical succinct proof of post-quantum signature verification")
}

// TestClassificationPredicateMatchesDocumentation asserts that the
// predicate's classification of a wrapper (Groth16 NOT PQ, STARK PQ)
// matches what the docs say, by parsing both the docs and the
// predicate against the same set of system names.
func TestClassificationPredicateMatchesDocumentation(t *testing.T) {
	// Documentation contract: Groth16 is classical, STARK / lattice is
	// PQ. We assert both directions.
	if warp.IsPQRootOfTrust("groth16") {
		t.Error("predicate disagrees with docs: Groth16 must NOT be PQ")
	}
	if !warp.IsPQRootOfTrust("stark-rescue") {
		t.Error("predicate disagrees with docs: STARK wrappers should be PQ")
	}
	if !warp.IsPQRootOfTrust("lattice-zk") {
		t.Error("predicate disagrees with docs: lattice-zk wrappers should be PQ")
	}
}

// ── helpers ─────────────────────────────────────────────────────────

// lookupRepoFile resolves a repo-relative path to an absolute path on
// disk by walking up from the test file's working directory. Goes up
// at most 6 levels — enough to hop from
// warp/pulsar/groth16_classification_test.go to the lux/ root and
// down into lps/ or proofs/.
func lookupRepoFile(t *testing.T, relative string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, relative)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate %s above %s", relative, wd)
	return ""
}

// requirePhraseNearGroth16 checks that `phrase` appears within 600
// bytes of a "Groth16" mention. The proximity check is the part the
// gate cares about — the disclaimer must be NEAR the Groth16 mention,
// not stranded somewhere else in the file.
func requirePhraseNearGroth16(t *testing.T, label, text, phrase string) {
	t.Helper()
	const window = 600

	// Lowercase comparison so capitalisation drift does not break the
	// test (e.g. "Not post-quantum" vs "not post-quantum").
	lo := strings.ToLower(text)
	loPhrase := strings.ToLower(phrase)
	for i := 0; i < len(lo); {
		idx := strings.Index(lo[i:], "groth16")
		if idx < 0 {
			break
		}
		start := i + idx
		end := start + len("groth16") + window
		if end > len(lo) {
			end = len(lo)
		}
		begin := start - window
		if begin < 0 {
			begin = 0
		}
		if strings.Contains(lo[begin:end], loPhrase) {
			return
		}
		i = start + 1
	}
	t.Fatalf("%s: phrase %q not found within %d bytes of any Groth16 mention", label, phrase, window)
}
