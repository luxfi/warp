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
