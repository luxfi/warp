// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"bytes"
	"testing"
)

// TestZapIntRoundTrip proves fixed-width big-endian round-trips for every
// integer width, and that the on-wire bytes are big-endian (rule 1).
func TestZapIntRoundTrip(t *testing.T) {
	// u8
	for _, v := range []uint8{0, 1, 0x7f, 0x80, 0xff} {
		buf := appendU8(nil, v)
		if len(buf) != 1 || buf[0] != v {
			t.Fatalf("u8 %d wire %x", v, buf)
		}
		r := newZapReader(buf)
		got, err := r.u8()
		if err != nil || got != v {
			t.Fatalf("u8 readback %d got %d err %v", v, got, err)
		}
		if err := r.end(); err != nil {
			t.Fatalf("u8 end: %v", err)
		}
	}
	// u16 big-endian
	if got := appendU16(nil, 0x0102); !bytes.Equal(got, []byte{0x01, 0x02}) {
		t.Fatalf("u16 not big-endian: %x", got)
	}
	// u32 big-endian
	if got := appendU32(nil, 0x01020304); !bytes.Equal(got, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("u32 not big-endian: %x", got)
	}
	// u64 big-endian
	if got := appendU64(nil, 0x0102030405060708); !bytes.Equal(got, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("u64 not big-endian: %x", got)
	}
	for _, v := range []uint64{0, 1, 1<<32 - 1, 1 << 32, 1<<64 - 1} {
		r := newZapReader(appendU64(nil, v))
		got, err := r.u64()
		if err != nil || got != v {
			t.Fatalf("u64 %d got %d err %v", v, got, err)
		}
	}
}

// TestZapBoolDomain proves bool encodes to {0x00,0x01} and decode rejects
// any other byte (rule 5).
func TestZapBoolDomain(t *testing.T) {
	if got := appendBool(nil, true); !bytes.Equal(got, []byte{0x01}) {
		t.Fatalf("true -> %x", got)
	}
	if got := appendBool(nil, false); !bytes.Equal(got, []byte{0x00}) {
		t.Fatalf("false -> %x", got)
	}
	for b := 2; b <= 0xff; b++ {
		r := newZapReader([]byte{byte(b)})
		if _, err := r.boolean(); err == nil {
			t.Fatalf("boolean accepted out-of-domain byte 0x%02x", b)
		}
	}
	// canonical values accepted
	for _, b := range []byte{0x00, 0x01} {
		r := newZapReader([]byte{b})
		if _, err := r.boolean(); err != nil {
			t.Fatalf("boolean rejected canonical byte 0x%02x: %v", b, err)
		}
	}
}

// TestZapVarFraming proves the u32-BE length frame round-trips and that a
// declared length exceeding the remaining bytes is rejected (rules 2, 4).
func TestZapVarFraming(t *testing.T) {
	for _, data := range [][]byte{nil, {}, {0x00}, []byte("hello"), bytes.Repeat([]byte{0xab}, 1000)} {
		wire := appendVar(nil, data)
		if len(wire) != 4+len(data) {
			t.Fatalf("var frame len %d want %d", len(wire), 4+len(data))
		}
		r := newZapReader(wire)
		got, err := r.varbytes()
		if err != nil {
			t.Fatalf("varbytes(%d): %v", len(data), err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("varbytes mismatch: %x vs %x", got, data)
		}
		if err := r.end(); err != nil {
			t.Fatalf("var end: %v", err)
		}
	}
	// absent optional lane is the u32(0) frame
	if got := appendVar(nil, nil); !bytes.Equal(got, []byte{0, 0, 0, 0}) {
		t.Fatalf("empty var frame = %x, want 00000000", got)
	}
	// length prefix that overruns the buffer is rejected, not allocated
	overrun := []byte{0xff, 0xff, 0xff, 0xff, 0x01, 0x02}
	r := newZapReader(overrun)
	if _, err := r.varbytes(); err == nil {
		t.Fatal("varbytes accepted length prefix exceeding remaining bytes")
	}
}

// TestZapFixed proves raw fixed-width reads and short-buffer rejection
// (rule 3).
func TestZapFixed(t *testing.T) {
	src := bytes.Repeat([]byte{0x5a}, 32)
	wire := appendFixed(nil, src)
	if !bytes.Equal(wire, src) {
		t.Fatalf("fixed encode altered bytes")
	}
	var got [32]byte
	r := newZapReader(wire)
	if err := r.fixedInto(got[:]); err != nil {
		t.Fatalf("fixedInto: %v", err)
	}
	if !bytes.Equal(got[:], src) {
		t.Fatalf("fixedInto mismatch")
	}
	// short buffer rejected
	short := newZapReader(src[:16])
	var dst [32]byte
	if err := short.fixedInto(dst[:]); err == nil {
		t.Fatal("fixedInto accepted short buffer")
	}
}

// TestZapMagic proves the 5-byte magic is accepted only when exact, and
// that legacy RLP / v2 leading bytes are rejected (rule 9).
func TestZapMagic(t *testing.T) {
	good := append(wireMagic[:], 0xde, 0xad)
	r := newZapReader(good)
	if err := r.expectMagic(); err != nil {
		t.Fatalf("expectMagic rejected valid magic: %v", err)
	}
	// legacy RLP list prefixes (0xc0..0xff) must be rejected
	for _, lead := range []byte{0xc0, 0xf8, 0xff, 0x02 /* legacy v2 byte */} {
		r := newZapReader([]byte{lead, 0x00, 0x00, 0x00, 0x00})
		if err := r.expectMagic(); err == nil {
			t.Fatalf("expectMagic accepted legacy lead byte 0x%02x", lead)
		}
	}
	// wrong version byte rejected
	wrongVer := []byte{'L', 'W', 'Z', 'P', 0x02}
	if err := newZapReader(wrongVer).expectMagic(); err == nil {
		t.Fatal("expectMagic accepted wrong version byte")
	}
	// truncated magic rejected
	if err := newZapReader([]byte{'L', 'W', 'Z'}).expectMagic(); err == nil {
		t.Fatal("expectMagic accepted truncated magic")
	}
}

// TestZapTrailingRejected proves the cursor enforces offset==len (rule 7).
func TestZapTrailingRejected(t *testing.T) {
	wire := appendU32(nil, 7)
	wire = append(wire, 0xff) // one extra byte
	r := newZapReader(wire)
	if _, err := r.u32(); err != nil {
		t.Fatalf("u32: %v", err)
	}
	if err := r.end(); err == nil {
		t.Fatal("end() accepted trailing byte")
	}
}

// TestZapCanonicalBits proves trim-on-encode and trailing-zero-reject on
// decode for the Signers bitset (rule 6).
func TestZapCanonicalBits(t *testing.T) {
	// A bitset grown past its highest set bit carries trailing zeros.
	b := NewBitSet()
	b.Add(1)
	for len(b) < 4 {
		b = append(b, 0) // simulate Add-grown trailing zero bytes
	}
	canon := canonicalBits(b)
	if len(canon) != 1 {
		t.Fatalf("canonicalBits did not trim: len=%d (%x)", len(canon), canon)
	}
	if err := checkCanonicalBits(canon); err != nil {
		t.Fatalf("checkCanonicalBits rejected trimmed bits: %v", err)
	}
	// Decode-side: a bitset with a trailing zero byte is non-canonical.
	if err := checkCanonicalBits([]byte{0x02, 0x00}); err == nil {
		t.Fatal("checkCanonicalBits accepted trailing zero byte")
	}
	// Empty bitset is canonical (no trailing zero to trim).
	if err := checkCanonicalBits([]byte{}); err != nil {
		t.Fatalf("checkCanonicalBits rejected empty bits: %v", err)
	}
	// Non-zero final byte is canonical.
	if err := checkCanonicalBits([]byte{0x00, 0x01}); err != nil {
		t.Fatalf("checkCanonicalBits rejected canonical bits with interior zero: %v", err)
	}
}

// TestZapShortReads proves every primitive returns an error (never
// panics) on a buffer that is too short.
func TestZapShortReads(t *testing.T) {
	empty := func() *zapReader { return newZapReader(nil) }
	if _, err := empty().u8(); err == nil {
		t.Fatal("u8 on empty did not error")
	}
	if _, err := empty().u16(); err == nil {
		t.Fatal("u16 on empty did not error")
	}
	if _, err := empty().u32(); err == nil {
		t.Fatal("u32 on empty did not error")
	}
	if _, err := empty().u64(); err == nil {
		t.Fatal("u64 on empty did not error")
	}
	if _, err := empty().boolean(); err == nil {
		t.Fatal("boolean on empty did not error")
	}
	if _, err := empty().varbytes(); err == nil {
		t.Fatal("varbytes on empty did not error")
	}
}

// FuzzZapReader drives a random read program over arbitrary bytes and
// asserts the reader never panics and never advances past the buffer.
func FuzzZapReader(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add(append(wireMagic[:], 0, 0, 0, 4, 1, 2, 3, 4))
	f.Add(bytes.Repeat([]byte{0xff}, 64))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// program byte selects which primitive to read next; the reader
		// must tolerate any sequence of reads against any buffer.
		r := newZapReader(raw)
		for i := 0; i < 32 && r.remaining() >= 0; i++ {
			sel := i % 7
			before := r.off
			var err error
			switch sel {
			case 0:
				_, err = r.u8()
			case 1:
				_, err = r.u16()
			case 2:
				_, err = r.u32()
			case 3:
				_, err = r.u64()
			case 4:
				_, err = r.boolean()
			case 5:
				_, err = r.varbytes()
			case 6:
				var d [20]byte
				err = r.fixedInto(d[:])
			}
			if r.off < before || r.off > len(r.buf) {
				t.Fatalf("cursor escaped buffer: off=%d before=%d len=%d", r.off, before, len(r.buf))
			}
			if err != nil {
				// On error the cursor must not have advanced into invalid
				// territory; stop the program (further reads are noise).
				break
			}
		}
		_ = r.end()
	})
}
