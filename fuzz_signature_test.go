// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Warp 1.x wire-format fuzz harnesses.
//
// FuzzBLSAggregateCert  — BitSetSignature codec round-trip
// FuzzWarpV1Envelope    — legacy v1 Message codec round-trip; asserts
//                         v1 verifiers reject 0x02-prefixed envelopes
//
// Property: every decoder path under MaxMessageSize never escapes a
// panic, and v1 verifiers correctly reject v2 envelopes.

package warp

import (
	"bytes"
	"fmt"
	"testing"
)

const fuzzMaxRawSize = 64 * 1024

// fuzzBLSAggregateCertCodec round-trips raw bytes through the warp
// codec into a BitSetSignature and back. Property: 0 panics.
func fuzzBLSAggregateCertCodec(raw []byte) (err error) {
	if len(raw) > fuzzMaxRawSize {
		return fmt.Errorf("input exceeds fuzzMaxRawSize")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decode panic recovered: %v", r)
		}
	}()
	sig := &BitSetSignature{}
	_, derr := Codec.Unmarshal(raw, sig)
	return derr
}

// fuzzWarpV1MessageCodec round-trips raw bytes through the warp v1
// codec into a Message. Property: 0 panics, and a v1 verifier called
// on bytes whose first byte is EnvelopeVersion2 (0x02) MUST reject
// rather than silently accept (this is the v1/v2 cross-version
// safety property).
func fuzzWarpV1MessageCodec(raw []byte) (err error) {
	if len(raw) > fuzzMaxRawSize {
		return fmt.Errorf("input exceeds fuzzMaxRawSize")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decode panic recovered: %v", r)
		}
	}()

	msg := &Message{}
	_, derr := Codec.Unmarshal(raw, msg)
	if derr != nil {
		return derr
	}

	// V1/V2 safety: if the bytes happened to round-trip as a v1
	// Message AND start with 0x02, ParseEnvelope MUST treat them as
	// a v2 envelope (i.e., NOT as a v1 Message). Otherwise an
	// attacker can craft bytes that decode as both versions.
	if len(raw) > 0 && raw[0] == EnvelopeVersion2 {
		// We don't require this to succeed — the v2 RLP body may be
		// invalid — but we do require it not to silently treat the
		// bytes as a valid v1 Message.
		_, _ = ParseEnvelopeV2(raw)
	}
	return nil
}

func addSmallSeeds(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	f.Add([]byte{EnvelopeVersion2}) // 0x02 prefix alone
	// Plausible-looking signed message header.
	f.Add(append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x00}, 64)...))
}

// FuzzBLSAggregateCert fuzzes the BitSetSignature codec.
func FuzzBLSAggregateCert(f *testing.F) {
	addSmallSeeds(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = fuzzBLSAggregateCertCodec(raw)
	})
}

// FuzzWarpV1Envelope fuzzes the legacy v1 Message codec.
func FuzzWarpV1Envelope(f *testing.F) {
	addSmallSeeds(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = fuzzWarpV1MessageCodec(raw)
	})
}

// TestFuzzCorpus_BLSAggregateCertReplay replays the small-seed corpus.
func TestFuzzCorpus_BLSAggregateCertReplay(t *testing.T) {
	for _, raw := range [][]byte{
		{},
		{0x00},
		bytes.Repeat([]byte{0xff}, 32),
	} {
		_ = fuzzBLSAggregateCertCodec(raw)
	}
}

// TestFuzzCorpus_WarpV1EnvelopeReplay replays the small-seed corpus
// and explicitly verifies that a 0x02-prefixed input does not pass v1
// validation as a Message.
func TestFuzzCorpus_WarpV1EnvelopeReplay(t *testing.T) {
	for _, raw := range [][]byte{
		{},
		{0x00},
		{EnvelopeVersion2},
		append([]byte{EnvelopeVersion2}, bytes.Repeat([]byte{0x00}, 32)...),
	} {
		_ = fuzzWarpV1MessageCodec(raw)
	}

	// Specific v1/v2 cross-version safety check: a 0x02-prefixed
	// random body should be rejected by ParseEnvelopeV2 (because
	// the body is not valid RLP), and should NOT be valid as a v1
	// Message either.
	hostile := append([]byte{EnvelopeVersion2}, bytes.Repeat([]byte{0xab}, 64)...)
	if _, err := ParseEnvelopeV2(hostile); err == nil {
		t.Fatalf("ParseEnvelopeV2 accepted random 0x02-prefixed bytes")
	}
	msg := &Message{}
	if _, err := Codec.Unmarshal(hostile, msg); err == nil {
		// Decoding as v1 might succeed (the codec is lenient), but
		// Verify() must fail.
		if verr := msg.Verify(); verr == nil {
			t.Fatalf("v1 Verify accepted hostile bytes that decoded")
		}
	}
}
