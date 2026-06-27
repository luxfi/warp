// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// signature_scheme_fuzz_test.go fuzzes the ZAP envelope decoder against
// the PQ-native posture. Properties:
//
//	A. ParseEnvelope MUST NOT panic on any byte string.
//	B. HasPQEvidence ⇔ len(MLDSACertSet) > 0.
//	C. HasPQEvidence == false ⇒ strict-PQ gate returns ErrClassicalAuthForbidden.
//	D. HasPQEvidence == true  ⇒ strict-PQ gate accepts (presence dispatch).

package warp

import (
	"bytes"
	"testing"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
	"github.com/luxfi/pq"
)

func makeSchemeFuzzSeed(t testing.TB, hasPulse, hasCert bool) []byte {
	t.Helper()
	core := &Core{
		NetworkID:        1,
		SourceChainID:    ids.ID{0xA1, 0xA2, 0xA3, 0xA4},
		SourceNebulaRoot: [32]byte{0xDE, 0xAD, 0xBE, 0xEF},
		SourceKeyEraID:   7,
		SourceGeneration: 11,
		HashSuiteID:      DefaultHashSuiteID,
		Payload:          []byte("scheme-fuzz"),
	}
	signers := NewBitSet()
	signers.Add(0)
	signers.Add(2)
	var sigBytes [bls.SignatureLen]byte
	copy(sigBytes[:], bytes.Repeat([]byte{0xAB}, bls.SignatureLen))

	var pulse []byte
	if hasPulse {
		pulse = bytes.Repeat([]byte{0x42}, 64)
	}
	var cert []byte
	if hasCert {
		cert = bytes.Repeat([]byte{0xC3}, 192)
	}
	env, err := NewEnvelope(core, NewBitSetSignature(signers, sigBytes), pulse, cert)
	if err != nil {
		t.Fatalf("new envelope: %v", err)
	}
	wire, err := env.Bytes()
	if err != nil {
		t.Fatalf("env bytes: %v", err)
	}
	return wire
}

func FuzzSignatureSchemeLegParser(f *testing.F) {
	f.Add(makeSchemeFuzzSeed(f, false, false))
	f.Add(makeSchemeFuzzSeed(f, true, false))
	f.Add(makeSchemeFuzzSeed(f, false, true))
	f.Add(makeSchemeFuzzSeed(f, true, true))
	f.Add([]byte{})
	f.Add(append(wireMagic[:], kindEnvelope))
	f.Add([]byte{0x05})

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Property A: never panics.
		env, err := ParseEnvelope(raw)
		if err != nil {
			return
		}

		// Property B: predicate matches the PQ lanes. PQ evidence = the Pulse
		// (Corona threshold, primary) OR the ML-DSA cert-set (fallback).
		hasField := len(env.PulseSig) > 0 || len(env.MLDSACertSet) > 0
		hasPredicate := env.HasPQEvidence()
		if hasField != hasPredicate {
			t.Fatalf("HasPQEvidence drift: field=%t predicate=%t", hasField, hasPredicate)
		}

		gateErr := pq.ValidateMode(pq.ModeStrictPQ, env, nil)
		if !hasPredicate {
			// Property C.
			if gateErr == nil {
				t.Fatalf("strict-PQ accepted classical-only envelope (raw=%x)", raw)
			}
			if !errorMatches(gateErr, pq.ErrClassicalAuthForbidden) {
				t.Fatalf("classical-only refused with wrong error: %v", gateErr)
			}
		} else {
			// Property D.
			if gateErr != nil {
				t.Fatalf("strict-PQ refused PQ-evidenced envelope: %v", gateErr)
			}
		}

		// Canonical round-trip stability.
		wire, err := env.Bytes()
		if err != nil {
			t.Fatalf("re-encode failed: %v", err)
		}
		if !bytes.Equal(raw, wire) {
			t.Fatalf("wire not stable across round-trip:\n  in =%x\n  out=%x", raw, wire)
		}
	})
}

// FuzzCorruptedMLDSACertSet flips a byte of an otherwise-valid envelope.
// The decoder MUST refuse or produce a self-consistent envelope, never
// read into adjacent memory.
func FuzzCorruptedMLDSACertSet(f *testing.F) {
	f.Add(makeSchemeFuzzSeed(f, false, true), uint16(0))
	f.Add(makeSchemeFuzzSeed(f, true, true), uint16(64))
	f.Add(makeSchemeFuzzSeed(f, false, true), uint16(0xFFFF))

	f.Fuzz(func(t *testing.T, raw []byte, mutateAt uint16) {
		if len(raw) < 10 {
			return
		}
		corrupted := make([]byte, len(raw))
		copy(corrupted, raw)
		pos := int(mutateAt) % len(corrupted)
		corrupted[pos] ^= 0xFF

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParseEnvelope panicked: %v", r)
				}
			}()
			env, err := ParseEnvelope(corrupted)
			if err == nil {
				_ = env.Verify()
			}
		}()
	})
}

// errorMatches walks err's unwrap chain looking for target.
func errorMatches(err error, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
