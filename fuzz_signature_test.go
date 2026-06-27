// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// ZAP signature / envelope decoder fuzz harnesses.
//
// FuzzBeamCodec       — Beam (Signers bitset + [96] sig) decode never panics.
// FuzzEnvelopeRaw  — ParseEnvelope never panics; legacy RLP / 0x02
//                        lead bytes are rejected at the magic.

package warp

import (
	"bytes"
	"fmt"
	"testing"
)

const fuzzMaxRawSize = 64 * 1024

// fuzzBeamCodec decodes raw bytes through parseBeam. Property: 0 panics.
func fuzzBeamCodec(raw []byte) (err error) {
	if len(raw) > fuzzMaxRawSize {
		return fmt.Errorf("input exceeds fuzzMaxRawSize")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decode panic recovered: %v", r)
		}
	}()
	_, derr := parseBeam(newZapReader(raw))
	return derr
}

func addSmallSeeds(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	f.Add(wireMagic[:])
	f.Add(append([]byte{0xc0}, bytes.Repeat([]byte{0x00}, 64)...)) // legacy RLP lead
}

// FuzzBeamCodec fuzzes the Beam decoder.
func FuzzBeamCodec(f *testing.F) {
	addSmallSeeds(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if err := fuzzBeamCodec(raw); err != nil &&
			!bytes.Contains([]byte(err.Error()), []byte("warp zap")) &&
			!bytes.Contains([]byte(err.Error()), []byte("beam")) {
			// Any decode error is acceptable; only a recovered panic
			// (reported via the recover path) is a failure.
			if bytes.Contains([]byte(err.Error()), []byte("panic")) {
				t.Fatalf("beam decode panicked: %v", err)
			}
		}
	})
}

// FuzzEnvelopeRaw fuzzes ParseEnvelope. Property: never panics,
// and legacy RLP / 0x02 lead bytes never parse as a valid envelope.
func FuzzEnvelopeRaw(f *testing.F) {
	addSmallSeeds(f)
	f.Add(makeFuzzSeed(1, 1, true, true))

	f.Fuzz(func(t *testing.T, raw []byte) {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParseEnvelope panicked: %v", r)
				}
			}()
			_, _ = ParseEnvelope(raw)
		}()

		// Legacy-format safety: any byte stream whose first byte is an
		// RLP list lead (0xc0..0xff) or the legacy 0x02 envelope byte
		// MUST NOT parse as a valid ZAP envelope.
		if len(raw) > 0 && (raw[0] >= 0xc0 || raw[0] == 0x02) {
			if _, err := ParseEnvelope(raw); err == nil {
				t.Fatalf("ParseEnvelope accepted legacy-lead bytes: %x", raw[:1])
			}
		}
	})
}

// TestFuzzCorpus_SignatureReplay replays the small-seed corpus and the
// explicit legacy-rejection check.
func TestFuzzCorpus_SignatureReplay(t *testing.T) {
	for _, raw := range [][]byte{{}, {0x00}, bytes.Repeat([]byte{0xff}, 32)} {
		_ = fuzzBeamCodec(raw)
	}
	// A 0x02-prefixed random body must be rejected.
	hostile := append([]byte{0x02}, bytes.Repeat([]byte{0xab}, 64)...)
	if _, err := ParseEnvelope(hostile); err == nil {
		t.Fatalf("ParseEnvelope accepted 0x02-prefixed bytes")
	}
	// An RLP list-prefixed body must be rejected.
	rlpish := append([]byte{0xf8, 0x40}, bytes.Repeat([]byte{0xcd}, 64)...)
	if _, err := ParseEnvelope(rlpish); err == nil {
		t.Fatalf("ParseEnvelope accepted RLP-shaped bytes")
	}
}
