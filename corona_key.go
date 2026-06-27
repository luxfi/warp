// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// corona_key.go — the Corona (Ringtail / Module-LWE lattice threshold) lane's
// key-era registry and era-binding. It is the SYMMETRIC counterpart of
// pulsar_key.go: Corona and Pulsar are BOTH threshold lanes, so each has a
// group-key-per-era record and resolver of the same shape — but as DISTINCT Go
// types, so one resolver can never serve both and alias their key material.
//
// THE BOUNDARY (mirrors Pulsar). Corona's dealerless DKG2 lattice ceremony and
// per-round threshold signing are OFFLINE (see offline_signers.go,
// CoronaDKG2Signer). What the chain sees, and what this file binds, is:
//
//	{ a SERIALIZED corona group key (carried in the key era),
//	  a serialized lattice threshold signature (CoronaEvidence.Sig),
//	  chainID, keyEraID, generation }
//
// The root warp package never imports the corona kernel, so the group key is
// held as opaque bytes here — exactly as PulsarKeyEra holds MLDSAPubKey as
// bytes. The lattice-signature verify itself is performed by the CoronaVerifier
// (warp/pulsar.RingtailVerifier), which deserializes the bytes into the kernel
// type. Era-binding lives here so it is UNIFORM with the Pulsar lane and
// independent of the lattice crypto.

package warp

import (
	"fmt"

	"github.com/luxfi/ids"
)

// CoronaKeyEra is the resolved Corona group-key record for a
// (ChainID, KeyEraID, Generation). It mirrors PulsarKeyEra field-for-field so
// the two threshold lanes share a symmetric key-management model, while
// remaining a DISTINCT type so Corona and Pulsar key material can never be
// aliased by a single resolver.
type CoronaKeyEra struct {
	// ChainID is the chain whose validators hold the threshold key.
	ChainID ids.ID

	// SignerSetID / KeyEraID / Generation identify this era.
	SignerSetID ids.ID
	KeyEraID    uint64
	Generation  uint64

	// PChainHeight anchors the era to the P-chain validator-set snapshot the
	// lattice key was dealt over.
	PChainHeight uint64

	// CoronaGroupKey is the SERIALIZED corona group key (the kernel's GroupKey
	// wire bytes). It is the only key material the lane needs; the warp/pulsar
	// CoronaVerifier deserializes it into the corona kernel type for the lattice
	// verify. Held as opaque bytes here so the root package never imports the
	// corona kernel (mirrors PulsarKeyEra.MLDSAPubKey).
	CoronaGroupKey []byte

	// Threshold is the weighted quorum the offline ceremony required.
	Threshold WeightThreshold

	// SchemeID pins the suite the era was issued under (SuiteCoronaRingtailSHA3).
	// VerifyCoronaEra rejects any era whose SchemeID is not the Corona suite.
	SchemeID SuiteID

	// KeygenMode records HOW the key was produced ("dkg2-dealerless",
	// "ceremony", …). Metadata: it never changes the verify.
	KeygenMode string

	// ActivationCert is the (opaque) certificate that activated this era on
	// chain. Audit trail; not consumed by the lattice verify.
	ActivationCert []byte
}

// CoronaKeyEraResolver resolves the Corona group-key era for a
// (chainID, keyEraID, generation). It is the Corona-lane key registry — the
// SYMMETRIC counterpart of PulsarKeyEraResolver, and a DISTINCT type from it
// and from SignerSetAuthority. An implementation can never satisfy two of these
// by accident, so Corona, Pulsar and P3Q key material can never be confused.
type CoronaKeyEraResolver interface {
	ResolveCoronaKeyEra(
		chainID ids.ID,
		keyEraID uint64,
		generation uint64,
	) (CoronaKeyEra, error)
}

// VerifyCoronaEra binds a Corona lane's evidence to its resolved key era: it
// asserts the era is a Corona-suite era and that the evidence's
// (ChainID, KeyEraID, Generation) match the era exactly. It is the Corona
// counterpart of VerifyPulsar's era-match preamble; the lattice-signature check
// itself is the CoronaVerifier's job (warp/pulsar). Keeping era-binding here
// makes it uniform with the Pulsar lane and independent of the lattice crypto.
func VerifyCoronaEra(ev CoronaEvidence, era CoronaKeyEra) error {
	if era.SchemeID != SuiteCoronaRingtailSHA3 {
		return fmt.Errorf("%w: corona era scheme %q is not the Corona suite %q",
			ErrSuiteKindMismatch, era.SchemeID, SuiteCoronaRingtailSHA3)
	}
	if ev.ChainID != era.ChainID ||
		ev.KeyEraID != era.KeyEraID ||
		ev.Generation != era.Generation {
		return fmt.Errorf("%w: evidence (chain=%s era=%d gen=%d) vs corona key era (chain=%s era=%d gen=%d)",
			ErrWrongEra, ev.ChainID, ev.KeyEraID, ev.Generation,
			era.ChainID, era.KeyEraID, era.Generation)
	}
	return nil
}
