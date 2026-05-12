// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"errors"
	"testing"
)

func TestSecurityProfile_StringAndPQFlag(t *testing.T) {
	if ProfileClassical.String() != "classical" {
		t.Errorf("ProfileClassical = %q", ProfileClassical.String())
	}
	if ProfileStrictPQ.String() != "strict-pq" {
		t.Errorf("ProfileStrictPQ = %q", ProfileStrictPQ.String())
	}
	if !ProfileStrictPQ.IsPostQuantum() {
		t.Error("ProfileStrictPQ.IsPostQuantum() = false")
	}
	if ProfileClassical.IsPostQuantum() {
		t.Error("ProfileClassical.IsPostQuantum() = true")
	}
	if ProfileFromPQFlag(true) != ProfileStrictPQ {
		t.Error("ProfileFromPQFlag(true) != StrictPQ")
	}
	if ProfileFromPQFlag(false) != ProfileClassical {
		t.Error("ProfileFromPQFlag(false) != Classical")
	}
}

// TestRequireMLDSACertSetForProfile_ClassicalAcceptsBoth pins the
// migration-window invariant: a classical chain accepts envelopes
// with or without an MLDSACertSet. The gate is a no-op under
// ProfileClassical.
func TestRequireMLDSACertSetForProfile_ClassicalAcceptsBoth(t *testing.T) {
	withoutCert := &EnvelopeV2{}
	withCert := &EnvelopeV2{MLDSACertSet: []byte{0xde, 0xad}}
	for _, env := range []*EnvelopeV2{withoutCert, withCert} {
		if err := RequireMLDSACertSetForProfile(ProfileClassical, env); err != nil {
			t.Errorf("ProfileClassical refused envelope: %v", err)
		}
	}
}

// TestRequireMLDSACertSetForProfile_StrictPQRefusesClassical pins
// the security invariant: a strict-PQ chain MUST refuse an
// envelope without an MLDSACertSet. Trusting the BLS Beam under
// strict-PQ would silently keep the chain quantum-vulnerable.
func TestRequireMLDSACertSetForProfile_StrictPQRefusesClassical(t *testing.T) {
	env := &EnvelopeV2{} // no MLDSACertSet
	err := RequireMLDSACertSetForProfile(ProfileStrictPQ, env)
	if !errors.Is(err, ErrClassicalAuthForbidden) {
		t.Errorf("StrictPQ accepted classical envelope: err=%v, want ErrClassicalAuthForbidden", err)
	}
}

func TestRequireMLDSACertSetForProfile_StrictPQAcceptsPQ(t *testing.T) {
	env := &EnvelopeV2{MLDSACertSet: []byte{0xde, 0xad}}
	if err := RequireMLDSACertSetForProfile(ProfileStrictPQ, env); err != nil {
		t.Errorf("StrictPQ refused PQ envelope: %v", err)
	}
}

func TestRequireMLDSACertSetForProfile_StrictPQRefusesNil(t *testing.T) {
	if err := RequireMLDSACertSetForProfile(ProfileStrictPQ, nil); err == nil {
		t.Error("StrictPQ accepted nil envelope")
	}
}

// TestProfileHybrid_AwareNotPQ pins the semantic split: hybrid
// IsPQAware (validates MLDSACertSet when present) but is NOT
// IsPostQuantum (doesn't REFUSE classical-only envelopes).
func TestProfileHybrid_AwareNotPQ(t *testing.T) {
	if !ProfileHybrid.IsPQAware() {
		t.Error("ProfileHybrid.IsPQAware() = false")
	}
	if ProfileHybrid.IsPostQuantum() {
		t.Error("ProfileHybrid.IsPostQuantum() = true (should be false)")
	}
	if !ProfileStrictPQ.IsPQAware() {
		t.Error("ProfileStrictPQ.IsPQAware() = false")
	}
	if ProfileClassical.IsPQAware() {
		t.Error("ProfileClassical.IsPQAware() = true")
	}
}

func TestLanesForProfile(t *testing.T) {
	for _, tc := range []struct {
		profile SecurityProfile
		hasCert bool
		want    VerificationLane
	}{
		{ProfileClassical, false, LaneClassical},
		{ProfileClassical, true, LaneClassical},
		{ProfileHybrid, true, LanePQ},
		{ProfileHybrid, false, LaneClassical},
		{ProfileStrictPQ, true, LanePQ},
		{ProfileStrictPQ, false, LanePQ}, // gate refuses before reaching here
	} {
		got := LanesForProfile(tc.profile, tc.hasCert)
		if got != tc.want {
			t.Errorf("LanesForProfile(%s, hasCert=%t) = %d, want %d",
				tc.profile, tc.hasCert, got, tc.want)
		}
	}
}

func TestRequireMLDSACertSetForProfile_HybridAcceptsBoth(t *testing.T) {
	// Hybrid is permissive at the gate; a classical-only envelope
	// is accepted (falls back to BLS Beam verification).
	without := &EnvelopeV2{}
	with := &EnvelopeV2{MLDSACertSet: []byte{0xde, 0xad}}
	for _, env := range []*EnvelopeV2{without, with} {
		if err := RequireMLDSACertSetForProfile(ProfileHybrid, env); err != nil {
			t.Errorf("Hybrid refused envelope: %v", err)
		}
	}
}

func TestProfileFromString(t *testing.T) {
	for _, tc := range []struct {
		input   string
		want    SecurityProfile
		wantErr bool
	}{
		{"classical", ProfileClassical, false},
		{"hybrid", ProfileHybrid, false},
		{"strict-pq", ProfileStrictPQ, false},
		{"strict_pq", 0, true},
		{"", 0, true},
		{"PQ", 0, true},
	} {
		got, err := ProfileFromString(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("ProfileFromString(%q) err=%v, wantErr=%t", tc.input, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ProfileFromString(%q) = %s, want %s", tc.input, got, tc.want)
		}
	}
}
