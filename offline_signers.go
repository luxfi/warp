// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// offline_signers.go — the OFFLINE signer-side boundary.
//
// Everything in this file is BELOW the verification boundary. The chain NEVER
// sees any of it: the verify path (evidence.go / pulsar_key.go / p3q.go /
// finality_tier.go) does not — and MUST not — import or call these. They are
// declared here only to NAME the boundary and document what produces each
// lane's compact, standard-shaped evidence.
//
// The asymmetry is the whole point of the design:
//
//	PRODUCE (offline, here)                         VERIFY (on chain, elsewhere)
//	  dealerless nonce DKG, BCC, CEF, blame,    ──►   one FIPS-204 ML-DSA verify
//	  nonce pool, reshare/refresh (Pulsar)            (VerifyPulsar)
//	  dealerless DKG2 lattice ceremony (Corona) ──►   one Ringtail kernel verify
//	  ML-DSA-65 quorum + FRI proving (P3Q)      ──►   one succinct rollup verify
//
// These interfaces are intentionally UNIMPLEMENTED in warp. Concrete signers
// (pulsard, the corona DKG2 signer, the P3Q prover) live in their own modules,
// run by validators/provers, and emit the typed evidence the verifiers consume.
//
// Guardrail: if any symbol in this file ever appears in an import of the verify
// path, the boundary has been violated — the offline threshold machinery has
// leaked into on-chain verification.

package warp

// PulsarThresholdSigner is the OFFLINE dealerless threshold-ML-DSA signer
// (pulsard). It runs the TALUS construction — nonce DKG, BCC commitment carry,
// CEF carry-elimination, CSCP, blame rounds, the nonce pool, and proactive
// reshare/refresh — to produce ONE ordinary FIPS-204 ML-DSA-65 signature over
// a subject. The chain receives only that signature (as PulsarEvidence) and
// verifies it with VerifyPulsar; none of the methods below are ever invoked on
// chain.
type PulsarThresholdSigner interface {
	// ThresholdSign drives a signing session over subject and returns the
	// PulsarEvidence the chain will verify. signerSetID/keyEraID/generation
	// pin the era; the returned signature is a standard ML-DSA-65 signature.
	ThresholdSign(subject []byte) (PulsarEvidence, error)

	// Reshare runs a proactive refresh/reshare, advancing the era's Generation
	// while preserving the group public key (so PulsarKeyEra.MLDSAPubKey is
	// stable across the refresh and old signatures still verify).
	Reshare() error
}

// CoronaDKG2Signer (coronad) is the OFFLINE dealerless Corona (Ringtail /
// Module-LWE) threshold signer. It runs the lattice DKG2 ceremony and per-round threshold
// signing to produce ONE corona kernel threshold signature over a subject. The
// chain receives only that signature (as CoronaEvidence) and verifies it via
// the Corona kernel; the ceremony never appears on chain.
type CoronaDKG2Signer interface {
	// ThresholdSign produces the CoronaEvidence (serialized lattice threshold
	// signature + routing) the chain will verify over CoronaSigningBytes(subject).
	ThresholdSign(subject []byte) (CoronaEvidence, error)
}

// P3QProver is the OFFLINE P3Q prover (the Plonky3 FRI rollup behind precompile
// 0x012205). It takes a set of INDEPENDENT ML-DSA-65 signatures over a subject
// — the raw cert-set (CertSetEvidence) is its input — and produces a succinct
// P3QRoot attesting a weighted quorum verified. The chain receives only the
// compact root and verifies it via an injected P3QRollupVerifier; the prover is
// never imported by the verify path.
type P3QProver interface {
	// Prove rolls up the per-validator ML-DSA-65 certificates in certSet over
	// subject into a succinct P3QRoot.
	Prove(subject []byte, certSet CertSetEvidence) (P3QRoot, error)
}
