// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// p3q.go — the P3Q rollup lane (LP-218, "Post-Quantum Pulsar Proof") and the
// proof-system PQ classification that gates it.
//
// A P3Q root is a succinct proof that a weighted quorum of INDEPENDENT
// ML-DSA-65 signatures over the subject verified. It compresses an O(n)
// cert-set (EvidenceMLDSACertSet — its INPUT) into an O(1) root. The real
// prover/verifier is the Plonky3 FRI rollup at precompile 0x012205; it lives
// ABOVE warp (the precompile module imports warp + consensus) and is INJECTED
// as a P3QRollupVerifier. The warp verify path NEVER imports it — doing so
// would invert the dependency DAG (warp → precompile → warp).
//
// CRITICAL fail-closed rule: a P3Q root is only a POST-QUANTUM root of trust
// when its underlying proof SYSTEM is post-quantum. A Groth16 (pairing-based,
// Shor-broken) wrapper of ML-DSA verification is a CLASSICAL succinct proof of
// post-quantum signature verification — it is NOT a PQ root of trust. Such a
// root may satisfy a non-strict tier, but is REFUSED as a strict-PQ finality
// root unless policy explicitly opts in (P3QStrictRootOK / AcceptQuasarCert).

package warp

import (
	"errors"
	"strings"

	"github.com/luxfi/ids"
)

// P3Q errors.
var (
	// ErrP3QClassicalRoot is returned when a P3Q root backed by a classical
	// (non-PQ) proof system is offered as a strict-PQ finality root without an
	// explicit policy opt-in. The canonical case is a Groth16 rollup.
	ErrP3QClassicalRoot = errors.New("warp: P3Q root proof system is not post-quantum; refused as strict-PQ finality root")

	// ErrP3QVerifierUnavailable is the fail-closed result of the in-package
	// P3Q stub verifier. The real FRI rollup verifier is injected from above
	// warp; until one is wired, P3Q verification fails closed.
	ErrP3QVerifierUnavailable = errors.New("warp: no P3Q rollup verifier wired (real verifier is injected above warp)")

	// ErrSignerSetUnresolved is returned when a P3Q verifier could not resolve
	// the signer set / weights it must check the rollup threshold against.
	ErrSignerSetUnresolved = errors.New("warp: signer-set authority failed")
)

// P3QRoot is the typed P3Q rollup lane payload: the succinct root + proof, the
// proof system that produced it, and the quorum context the verifier checks
// against. The chain sees a compact root, not the underlying ML-DSA cert set.
type P3QRoot struct {
	// SignerSetID identifies the validator set the rolled-up ML-DSA-65 keys
	// belong to. Folded into M so the subject commits to it.
	SignerSetID ids.ID

	// EraHandle selects the signer-set snapshot (e.g. block height) the
	// SignerSetAuthority resolves keys + weights against.
	EraHandle uint64

	// Root is the succinct commitment the proof opens (e.g. a Merkle/FRI root
	// over the verified-signer set).
	Root []byte

	// Proof is the succinct argument bytes (e.g. a FRI/STARK proof).
	Proof []byte

	// ProvingSystem names the proof system — "stark-rescue", "lattice-zk",
	// "groth16", … — and is the input to IsPQRootOfTrust. It determines
	// whether this root can be a STRICT-PQ finality root.
	ProvingSystem string

	// Threshold is the weighted quorum the rollup attests was met among the
	// independent ML-DSA-65 signers.
	Threshold WeightThreshold

	// SuiteID pins the lane suite (SuiteP3QMLDSARollup).
	SuiteID SuiteID
}

// ValidatorMLDSAKey is one accountable signer in a P3Q / cert-set signer set:
// a validator identity, its ML-DSA-65 public key, and its stake weight.
type ValidatorMLDSAKey struct {
	NodeID    ids.NodeID
	PublicKey []byte
	Weight    uint64
}

// SignerSetAuthority resolves the per-validator ML-DSA-65 public keys and stake
// weights for a (signerSetID, eraHandle). It is the key registry for the P3Q
// rollup lane AND the raw cert-set lane (both authorize via INDEPENDENT
// per-validator keys, NOT a threshold group key). It is a DISTINCT type from
// PulsarKeyEraResolver (one threshold group key) and from the corona group-key
// resolver — so an implementation can never alias Pulsar ↔ Corona ↔ P3Q key
// material.
type SignerSetAuthority interface {
	ResolveSignerSet(
		signerSetID ids.ID,
		eraHandle uint64,
	) (signers []ValidatorMLDSAKey, totalWeight uint64, err error)
}

// IsPQRootOfTrust classifies a succinct-proof wrapper system by post-quantum
// status. Returns true iff the wrapper is BELIEVED post-quantum-secure under
// current cryptanalysis. This is the SHARED, subject-agnostic policy primitive
// (it lives in the warp root, not in warp/pulsar, so both the warp envelope
// path and the quasar consensus policy can reuse it without an import cycle).
//
//	"groth16", "groth16-bls12-381", "snark-pairing"
//	  → false. Pairing-based; broken under Shor's algorithm.
//	"stark-rescue", "stark-poseidon", "lattice-zk"
//	  → true. Hash- or lattice-based; PQ-friendly assumptions.
//	"none" or empty string
//	  → true. No wrapper means the underlying signature itself is the evidence;
//	  if that signature is ML-DSA / Corona, the PQ root lives in it directly.
//	anything else → false (conservative).
//
// Case-insensitive on the system name.
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

// P3QStrictRootOK reports whether a P3Q root may serve as a STRICT-PQ finality
// root. It returns nil iff the root's proof system is post-quantum; otherwise
// ErrP3QClassicalRoot. Policy that explicitly accepts a classical P3Q root
// (e.g. a non-strict tier) MUST NOT call this — it is the strict gate.
func P3QStrictRootOK(root P3QRoot) error {
	if !IsPQRootOfTrust(root.ProvingSystem) {
		return ErrP3QClassicalRoot
	}
	return nil
}

// unavailableP3QVerifier is the in-package fail-closed P3Q verifier. It is the
// default when no real (injected) FRI rollup verifier is wired, so a P3Q lane
// can never silently pass without a verifier.
type unavailableP3QVerifier struct{}

// UnavailableP3QVerifier returns a P3QRollupVerifier that always fails closed
// with ErrP3QVerifierUnavailable. Receivers wire the real verifier (the
// 0x012205 FRI rollup) from above warp; this is the safe default until they do.
func UnavailableP3QVerifier() P3QRollupVerifier { return unavailableP3QVerifier{} }

func (unavailableP3QVerifier) VerifyP3QRollup([]byte, P3QRoot, SignerSetAuthority) error {
	return ErrP3QVerifierUnavailable
}
