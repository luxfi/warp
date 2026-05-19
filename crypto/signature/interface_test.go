// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// interface_test.go pins the PQ-native posture of the signature
// registry. The registry is the ONE place where schemes are
// classified PQ-vs-classical and composed into a runtime selector;
// every property in this file is a contract downstream consumers
// rely on for strict-PQ enforcement.
//
// Tests are organised by concern:
//
//   - Default posture       (TestDefaultConfig_*, TestNewPQNativeRegistry_*)
//   - Classical opt-in      (TestRegister_Classical_Refused, TestRegister_Classical_OptIn)
//   - PQ classification     (TestIsPQ_*, TestIsClassical_*)
//   - Preferred-scheme gate (TestSetPreferred_*)
//   - Audit ordering        (TestSchemes_DeterministicOrder)
//   - Context binding       (TestSignContextWarpV1_Stable)
//
// Each test should fail loudly if the posture changes — these are
// the invariants the auditor signed off on.

package signature

import (
	"context"
	"errors"
	"testing"
)

// fakeVerifier and fakeSigner are minimal Verifier/Signer
// implementations used to install schemes in the registry under
// test. The cryptographic work is faked because we are testing the
// registry's policy gate, not the underlying primitives.
type fakeVerifier struct{ scheme Scheme }

func (f fakeVerifier) Scheme() Scheme { return f.scheme }
func (f fakeVerifier) Verify(ctx context.Context, _ []byte, _ Signature, _ SignerSet) error {
	return nil
}
func (f fakeVerifier) VerifyAggregate(ctx context.Context, _ []byte, _ Signature, _ SignerSet) error {
	return nil
}

type fakeSigner struct{ scheme Scheme }

func (f fakeSigner) Scheme() Scheme { return f.scheme }
func (f fakeSigner) Sign(_ context.Context, _ []byte, _ PrivateKey) (Signature, error) {
	return nil, nil
}
func (f fakeSigner) AggregateSign(_ context.Context, _ []byte, _ []PrivateKey) (Signature, error) {
	return nil, nil
}

func pair(s Scheme) (Verifier, Signer) {
	return fakeVerifier{scheme: s}, fakeSigner{scheme: s}
}

// ---------------------------------------------------------------------
// Default posture
// ---------------------------------------------------------------------

// TestDefaultConfig_IsPQNative pins the zero-knob behaviour:
// DefaultConfig has LegacyClassicalEnabled=false and prefers
// SchemeMLDSA65. If this flips, every operator who relies on the
// default suddenly opens a classical-fallback hole — refuse silently.
func TestDefaultConfig_IsPQNative(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.LegacyClassicalEnabled {
		t.Error("DefaultConfig().LegacyClassicalEnabled = true, want false (PQ-only default)")
	}
	if cfg.PreferredScheme != SchemeMLDSA65 {
		t.Errorf("DefaultConfig().PreferredScheme = %q, want %q", cfg.PreferredScheme, SchemeMLDSA65)
	}
}

// TestNewPQNativeRegistry_RefusesClassical confirms that the
// canonical constructor cannot install a classical scheme without
// an explicit opt-in. This is the ONE check the auditor cares
// about — every classical primitive on a strict-PQ chain MUST be
// gated.
func TestNewPQNativeRegistry_RefusesClassical(t *testing.T) {
	r := NewPQNativeRegistry()
	for _, scheme := range ClassicalSchemes {
		v, s := pair(scheme)
		err := r.Register(scheme, v, s)
		if !errors.Is(err, ErrClassicalRequiresOptIn) {
			t.Errorf("Register(%q) = %v, want ErrClassicalRequiresOptIn", scheme, err)
		}
	}
}

// TestNewPQNativeRegistry_AdmitsPQ pins the happy path: every PQ
// scheme installs on the default registry without any opt-in.
func TestNewPQNativeRegistry_AdmitsPQ(t *testing.T) {
	r := NewPQNativeRegistry()
	for _, scheme := range PQSchemes {
		v, s := pair(scheme)
		if err := r.Register(scheme, v, s); err != nil {
			t.Errorf("Register(%q) = %v, want nil", scheme, err)
		}
	}
}

// TestNewPQNativeRegistry_AdmitsHybrid: SchemeHybrid is NOT
// classical (it composes BLS + Corona — both lanes verify), so it
// installs on the default registry even without LegacyClassicalEnabled.
// This is the migration path: a chain pinned to ModeHybrid can run
// the default registry and still verify hybrid envelopes.
func TestNewPQNativeRegistry_AdmitsHybrid(t *testing.T) {
	r := NewPQNativeRegistry()
	v, s := pair(SchemeHybrid)
	if err := r.Register(SchemeHybrid, v, s); err != nil {
		t.Errorf("Register(hybrid) on PQ-native registry = %v, want nil", err)
	}
}

// TestNewPQNativeRegistry_PreferredIsMLDSA65 confirms the default
// preferred scheme is ML-DSA-65. Tests downstream of this (envelope
// negotiation) assume this default.
func TestNewPQNativeRegistry_PreferredIsMLDSA65(t *testing.T) {
	r := NewPQNativeRegistry()
	if got := r.PreferredScheme(); got != SchemeMLDSA65 {
		t.Errorf("PreferredScheme() = %q, want %q", got, SchemeMLDSA65)
	}
}

// ---------------------------------------------------------------------
// Classical opt-in
// ---------------------------------------------------------------------

// TestRegister_Classical_OptIn pins the opt-in path: with
// LegacyClassicalEnabled=true every classical scheme installs.
func TestRegister_Classical_OptIn(t *testing.T) {
	r := NewRegistryFromConfig(Config{LegacyClassicalEnabled: true})
	for _, scheme := range ClassicalSchemes {
		v, s := pair(scheme)
		if err := r.Register(scheme, v, s); err != nil {
			t.Errorf("Register(%q) on opt-in registry = %v, want nil", scheme, err)
		}
	}
}

// TestRegister_SchemeMismatch pins the contract: Verifier.Scheme()
// MUST equal Signer.Scheme() MUST equal the scheme argument.
// Catching this at Register time prevents a registry where the
// verifier and signer disagree (which would silently miss a real
// signature mismatch at runtime).
func TestRegister_SchemeMismatch(t *testing.T) {
	r := NewPQNativeRegistry()
	v := fakeVerifier{scheme: SchemeMLDSA65}
	s := fakeSigner{scheme: SchemePulsar}
	err := r.Register(SchemeMLDSA65, v, s)
	if !errors.Is(err, ErrSchemeMismatch) {
		t.Errorf("Register(mismatch) = %v, want ErrSchemeMismatch", err)
	}
}

// ---------------------------------------------------------------------
// PQ classification
// ---------------------------------------------------------------------

// TestIsPQ pins the set of schemes we consider post-quantum. This
// is the predicate the pq.Mode gate uses to decide "MUST refuse"
// under strict-PQ.
func TestIsPQ(t *testing.T) {
	pqExpected := map[Scheme]bool{
		SchemeMLDSA65:   true,
		SchemePulsar:    true,
		SchemeCorona:    true,
		SchemeSLHDSA:    true,
		SchemeBLS:       false,
		SchemeEd25519:   false,
		SchemeSecp256k1: false,
		SchemeHybrid:    false, // hybrid is PQ-AWARE, not PQ-only
	}
	for s, want := range pqExpected {
		if got := IsPQ(s); got != want {
			t.Errorf("IsPQ(%q) = %t, want %t", s, got, want)
		}
	}
}

// TestIsClassical pins the set of schemes the registry treats as
// requiring opt-in. SchemeHybrid is NOT classical (it composes
// BLS + Corona over the same transcript) — both lanes verify.
func TestIsClassical(t *testing.T) {
	classicalExpected := map[Scheme]bool{
		SchemeBLS:       true,
		SchemeEd25519:   true,
		SchemeSecp256k1: true,
		SchemeMLDSA65:   false,
		SchemePulsar:    false,
		SchemeCorona:    false,
		SchemeSLHDSA:    false,
		SchemeHybrid:    false,
	}
	for s, want := range classicalExpected {
		if got := IsClassical(s); got != want {
			t.Errorf("IsClassical(%q) = %t, want %t", s, got, want)
		}
	}
}

// ---------------------------------------------------------------------
// Preferred-scheme gate
// ---------------------------------------------------------------------

// TestSetPreferred_UnknownScheme refuses a SetPreferred call for
// a scheme that has not been Registered. Prevents the registry from
// returning a verifier that doesn't exist.
func TestSetPreferred_UnknownScheme(t *testing.T) {
	r := NewPQNativeRegistry()
	err := r.SetPreferred(SchemeMLDSA65)
	if !errors.Is(err, ErrUnknownScheme) {
		t.Errorf("SetPreferred(unregistered) = %v, want ErrUnknownScheme", err)
	}
}

// TestSetPreferred_ClassicalRefusedWithoutOptIn confirms that even
// after a classical scheme has been Registered on an opt-in registry,
// a registry WITHOUT LegacyClassicalEnabled cannot SetPreferred to
// it. This is the second gate — Register might be bypassed by a
// future code path but SetPreferred still refuses.
func TestSetPreferred_ClassicalRefusedWithoutOptIn(t *testing.T) {
	// Build a registry with classical opt-in, register BLS, then
	// copy the verifiers map into a no-opt-in registry to simulate
	// the gate.
	r := NewRegistryFromConfig(Config{LegacyClassicalEnabled: false})
	// Manually inject (bypassing Register) to simulate a hostile
	// build that wires schemes directly.
	v, s := pair(SchemeBLS)
	r.verifiers[SchemeBLS] = v
	r.signers[SchemeBLS] = s
	err := r.SetPreferred(SchemeBLS)
	if !errors.Is(err, ErrClassicalRequiresOptIn) {
		t.Errorf("SetPreferred(bls) on PQ-native = %v, want ErrClassicalRequiresOptIn", err)
	}
}

// TestSetPreferred_PQOK pins the happy path.
func TestSetPreferred_PQOK(t *testing.T) {
	r := NewPQNativeRegistry()
	v, s := pair(SchemePulsar)
	if err := r.Register(SchemePulsar, v, s); err != nil {
		t.Fatalf("Register(pulsar) = %v", err)
	}
	if err := r.SetPreferred(SchemePulsar); err != nil {
		t.Errorf("SetPreferred(pulsar) = %v, want nil", err)
	}
	if got := r.PreferredScheme(); got != SchemePulsar {
		t.Errorf("PreferredScheme() = %q, want %q", got, SchemePulsar)
	}
}

// ---------------------------------------------------------------------
// Audit ordering
// ---------------------------------------------------------------------

// TestSchemes_DeterministicOrder pins the order Schemes returns:
// PQ first (by PQSchemes order), then classical (by ClassicalSchemes
// order), then hybrid. Audit tooling diffs the returned slice
// against a declared config.
func TestSchemes_DeterministicOrder(t *testing.T) {
	r := NewRegistryFromConfig(Config{LegacyClassicalEnabled: true})
	// Register everything in reverse to confirm Schemes re-orders.
	all := []Scheme{SchemeHybrid, SchemeSecp256k1, SchemeEd25519, SchemeBLS, SchemeSLHDSA, SchemeCorona, SchemePulsar, SchemeMLDSA65}
	for _, s := range all {
		v, sig := pair(s)
		if err := r.Register(s, v, sig); err != nil {
			t.Fatalf("Register(%q) = %v", s, err)
		}
	}
	want := []Scheme{SchemeMLDSA65, SchemePulsar, SchemeCorona, SchemeSLHDSA, SchemeBLS, SchemeEd25519, SchemeSecp256k1, SchemeHybrid}
	got := r.Schemes()
	if len(got) != len(want) {
		t.Fatalf("len(Schemes()) = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Schemes()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// ---------------------------------------------------------------------
// Context binding
// ---------------------------------------------------------------------

// TestSignContextWarpV1_Stable pins the FIPS 204 §5.2 context
// string for Warp envelopes. Renaming this is a breaking change to
// every ML-DSA / SLH-DSA signature byte produced for a Warp
// envelope — KAT vectors would no longer round-trip.
func TestSignContextWarpV1_Stable(t *testing.T) {
	const expected = "lux-warp-cross-chain-v1"
	if SignContextWarpV1 != expected {
		t.Errorf("SignContextWarpV1 = %q, want %q (changing this invalidates every KAT)", SignContextWarpV1, expected)
	}
}
