// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// pulsar_key.go — the Pulsar (threshold ML-DSA) lane: its on-wire evidence,
// its key-era registry, and the REAL verifier.
//
// THE BOUNDARY. Pulsar's threshold magic — dealerless nonce DKG, BCC
// (Beaver-style commitment carry), CEF (carry-elimination), blame rounds, the
// nonce pool, reshare/refresh — is ALL OFFLINE, below the verification
// boundary (see offline_signers.go). What the chain sees, and all this file
// verifies, is:
//
//	{ an ORDINARY ML-DSA-65 public key (carried in the key era),
//	  an ORDINARY FIPS-204 ML-DSA-65 signature,
//	  keyEraID, generation, signerSetID, suiteID }
//
// VerifyPulsar is therefore a plain FIPS-204 ML-DSA-65 verify under a group
// public key. There is NO TALUS/BCC/CEF/nonce/MPC code in the verify path,
// and verification does NOT depend on a TEE — KeygenMode may record how the
// key was produced ("talus-mpc" / "ceremony" / "tee" / "p3q-rollup-fallback")
// but it never changes the verify, which is always just ML-DSA.
//
// This decouples "how the quorum signature was produced" (offline, evolving,
// possibly TEE-assisted) from "is this a valid quorum signature" (a fixed,
// standard, auditable ML-DSA check).

package warp

import (
	"fmt"

	mldsa65 "github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/luxfi/ids"
)

// pulsarLaneContext is the FIPS-204 §5.2 domain-separation context bound into
// every Pulsar ML-DSA signature. It prevents a Pulsar quorum signature from
// being replayed as any other ML-DSA signature (and vice versa). The offline
// signer MUST sign with this exact ctx; VerifyPulsar checks with it. Its value
// is a stable protocol constant — changing it is a coordinated upgrade.
var pulsarLaneContext = []byte("LUX-QUASAR-PULSAR-MLDSA65-v1")

// PulsarEvidence is the typed Pulsar lane payload the chain sees: the standard
// FIPS-204 ML-DSA-65 quorum signature plus the identifiers that select the
// group public key it must verify under. NONE of the offline threshold
// machinery (nonces, partials, commitments) appears here.
type PulsarEvidence struct {
	// SignerSetID identifies the validator set / quorum the group key
	// authorizes for. Folded into M so the signature commits to it.
	SignerSetID ids.ID

	// KeyEraID and Generation select the group key's lifecycle epoch:
	// KeyEraID advances on a fresh dealerless keygen; Generation advances on a
	// proactive refresh/reshare that preserves the public key.
	KeyEraID   uint64
	Generation uint64

	// SuiteID pins the scheme parameterization (SuitePulsarThresholdMLDSA65).
	SuiteID SuiteID

	// Signature is the ordinary FIPS-204 ML-DSA-65 signature over the subject.
	Signature []byte
}

// PulsarKeyEra is the resolved threshold-ML-DSA group public-key record for a
// (SignerSetID, KeyEraID, Generation). It is a DISTINCT type from the Corona
// group-key record (corona.GroupKey, resolved by the warp/pulsar
// CoronaGroupKeyResolver) and from the P3Q signer-set authority: the three key
// materials must never be aliased. The verify path consumes only MLDSAPubKey,
// SchemeID, and the identifiers.
type PulsarKeyEra struct {
	// ChainID is the chain whose validators hold the threshold key.
	ChainID ids.ID

	// SignerSetID / KeyEraID / Generation identify this era; VerifyPulsar
	// requires the evidence to match them exactly.
	SignerSetID ids.ID
	KeyEraID    uint64
	Generation  uint64

	// PChainHeight anchors the era to a P-chain height (the validator-set
	// snapshot the threshold key was dealt over). Informational for the verify
	// path; load-bearing for the era registry that resolves it.
	PChainHeight uint64

	// MLDSAPubKey is the encoded FIPS-204 ML-DSA-65 group public key
	// (mldsa65.PublicKeySize bytes). This is the ONLY key material the verifier
	// uses — an ordinary single ML-DSA public key, not a share set.
	MLDSAPubKey []byte

	// Threshold is the weighted quorum the offline ceremony required to produce
	// a signature under this key. Recorded for audit; the ML-DSA verify proves
	// possession of the group key, which the ceremony only yields at quorum.
	Threshold WeightThreshold

	// SchemeID pins the suite the era was issued under
	// (SuitePulsarThresholdMLDSA65). VerifyPulsar rejects evidence whose
	// SuiteID does not equal this.
	SchemeID SuiteID

	// KeygenMode records HOW the key was produced — "talus-mpc", "ceremony",
	// "tee", or "p3q-rollup-fallback". It is METADATA: it NEVER changes the
	// verify (which is always plain ML-DSA) and verification NEVER depends on a
	// TEE being present.
	KeygenMode string

	// ActivationCert is the (opaque) certificate that activated this era on
	// chain — the audit trail linking the era to its dealerless keygen /
	// reshare. Not consumed by the ML-DSA verify.
	ActivationCert []byte
}

// PulsarKeyEraResolver resolves the Pulsar (threshold ML-DSA) group key era
// for a (signerSetID, keyEraID, generation). It is the Pulsar-lane key
// registry and is a DISTINCT type from the Corona group-key resolver
// (warp/pulsar.CoronaGroupKeyResolver) and the P3Q SignerSetAuthority — an
// implementation can never satisfy two of these by accident, so Pulsar, Corona
// and P3Q key material can never be confused.
type PulsarKeyEraResolver interface {
	ResolvePulsarKeyEra(
		signerSetID ids.ID,
		keyEraID uint64,
		generation uint64,
	) (PulsarKeyEra, error)
}

// VerifyPulsar verifies a Pulsar (threshold ML-DSA) lane: a STANDARD FIPS-204
// ML-DSA-65 signature over subject, under the era's group public key. subject
// is the opaque finality digest (D for warp, M for quasar consensus).
//
// The check is exactly:
//
//  1. The evidence's SuiteID must equal the era's SchemeID.
//  2. The evidence's (KeyEraID, Generation, SignerSetID) must match the era.
//  3. mldsa65.Verify(era.MLDSAPubKey, subject, pulsarLaneContext, sig).
//
// No TALUS/BCC/CEF/nonce/MPC machinery and no TEE are consulted — that is all
// offline. This is a pure function of (evidence, subject, era).
func VerifyPulsar(ev PulsarEvidence, subject []byte, era PulsarKeyEra) error {
	if len(subject) != ids.IDLen {
		return fmt.Errorf("%w: got %d bytes", ErrInvalidSubject, len(subject))
	}
	if ev.SuiteID != era.SchemeID {
		return fmt.Errorf("%w: evidence suite %q, era scheme %q",
			ErrSuiteKindMismatch, ev.SuiteID, era.SchemeID)
	}
	if ev.KeyEraID != era.KeyEraID ||
		ev.Generation != era.Generation ||
		ev.SignerSetID != era.SignerSetID {
		return fmt.Errorf("%w: evidence (signerSet=%s era=%d gen=%d) vs key era (signerSet=%s era=%d gen=%d)",
			ErrWrongEra, ev.SignerSetID, ev.KeyEraID, ev.Generation,
			era.SignerSetID, era.KeyEraID, era.Generation)
	}

	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(era.MLDSAPubKey); err != nil {
		// A malformed group key cannot verify anything — fail closed.
		return fmt.Errorf("%w: malformed group public key: %v", ErrBadSignature, err)
	}
	if !mldsa65.Verify(&pk, subject, pulsarLaneContext, ev.Signature) {
		return ErrBadSignature
	}
	return nil
}
