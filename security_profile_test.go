// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"errors"
	"testing"

	"github.com/luxfi/pq"
)

// TestEnvelopeV2_HasPQEvidence pins the contract: HasPQEvidence
// returns true iff the envelope carries an MLDSACertSet. That's
// the single predicate pq.ValidateMode dispatches on.
func TestEnvelopeV2_HasPQEvidence(t *testing.T) {
	without := &EnvelopeV2{}
	with := &EnvelopeV2{MLDSACertSet: []byte{0xde, 0xad}}
	if without.HasPQEvidence() {
		t.Error("EnvelopeV2 without MLDSACertSet reported HasPQEvidence=true")
	}
	if !with.HasPQEvidence() {
		t.Error("EnvelopeV2 with MLDSACertSet reported HasPQEvidence=false")
	}
}

// TestValidateMode_StrictPQ_RefusesMissingCert exercises the
// integration: strict-PQ + envelope-without-MLDSACertSet routed
// through pq.ValidateMode returns ErrClassicalAuthForbidden.
// This is the runtime invariant Warp depends on — the gate
// lives in lux/pq, the predicate lives on EnvelopeV2.
func TestValidateMode_StrictPQ_RefusesMissingCert(t *testing.T) {
	env := &EnvelopeV2{}
	err := pq.ValidateMode(pq.ModeStrictPQ, env, nil)
	if !errors.Is(err, pq.ErrClassicalAuthForbidden) {
		t.Errorf("StrictPQ accepted classical envelope: %v", err)
	}
}

// TestValidateMode_StrictPQ_AcceptsPQEnvelope pins the happy path.
func TestValidateMode_StrictPQ_AcceptsPQEnvelope(t *testing.T) {
	env := &EnvelopeV2{MLDSACertSet: []byte{0xde, 0xad}}
	if err := pq.ValidateMode(pq.ModeStrictPQ, env, nil); err != nil {
		t.Errorf("StrictPQ refused PQ envelope: %v", err)
	}
}

// TestValidateMode_Hybrid_AcceptsBoth pins the migration middle:
// hybrid accepts envelopes with or without MLDSACertSet.
func TestValidateMode_Hybrid_AcceptsBoth(t *testing.T) {
	for _, env := range []*EnvelopeV2{{}, {MLDSACertSet: []byte{0xde, 0xad}}} {
		if err := pq.ValidateMode(pq.ModeHybrid, env, nil); err != nil {
			t.Errorf("Hybrid refused envelope: %v", err)
		}
	}
}

func TestLanesForMode(t *testing.T) {
	for _, tc := range []struct {
		mode    pq.Mode
		hasCert bool
		want    VerificationLane
	}{
		{pq.ModeClassical, false, LaneClassical},
		{pq.ModeClassical, true, LaneClassical},
		{pq.ModeHybrid, true, LanePQ},
		{pq.ModeHybrid, false, LaneClassical},
		{pq.ModeStrictPQ, true, LanePQ},
		{pq.ModeStrictPQ, false, LanePQ},
	} {
		got := LanesForMode(tc.mode, tc.hasCert)
		if got != tc.want {
			t.Errorf("LanesForMode(%s, hasCert=%t) = %d, want %d",
				tc.mode, tc.hasCert, got, tc.want)
		}
	}
}
