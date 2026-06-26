// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// zap.go — the canonical-profile TLV marshaler that is Warp's ONE wire
// and signing codec. There is no RLP, no version split, no alternative
// encoder. The format is total-order canonical: a given struct value has
// exactly one byte encoding, and decode rejects any byte stream that is
// not in canonical form. That property is what makes the encoding safe to
// use as a signing domain — every byte is committed and there is no
// malleability lane (no pointers, padding, flags, varints, or maps).
//
// Canonicality rules enforced here (the ZAP profile):
//
//  1. Integers are fixed-width big-endian (u8/u16/u32/u64). No varints.
//  2. Every variable-length field is framed with a u32 big-endian length
//     prefix followed by exactly that many bytes.
//  3. Fixed-width arrays ([20]/[32]/[96]) are written raw, with no length.
//  4. Every field is always present. An absent optional lane is the
//     u32(0) empty frame, never an omitted field.
//  5. Booleans are exactly 0x00 or 0x01; any other byte is rejected.
//  6. The Signers bitset is trim-canonical: no trailing zero byte. A
//     bitset whose final byte is zero is non-canonical (two encodings for
//     one set) — trimmed on encode, rejected on decode.
//  7. Decode rejects trailing bytes: the cursor MUST land exactly on the
//     end of the buffer (offset == len).
//  8. No pointers, padding, flags, or maps appear in the format.
//  9. The wire stream begins with the 5-byte magic "LWZP"||0x01. Legacy
//     RLP bytes (lead 0xc0..0xff) and the legacy 0x02 envelope byte are
//     rejected at the magic check; ZAP bytes are rejected by an RLP
//     decoder ('L' = 0x4c is below RLP's 0xc0 list floor).
//
// The big-endian length-prefix discipline is lifted from the proven
// HorizonCertificate codec (pulsar.go appendBELenPrefixed /
// readBELenPrefixed); here it is the single envelope codec.

// wireMagic is the 5-byte prefix on every WarpEnvelope wire stream:
// "LWZP" (Lux Warp Zap Protocol) followed by the format version 0x01.
var wireMagic = [5]byte{'L', 'W', 'Z', 'P', 0x01}

// Errors returned by the canonical decoder. Every path returns an error;
// none panic — the decoder runs on untrusted, attacker-controlled input.
var (
	errZapShort        = errors.New("warp zap: buffer too short")
	errZapBadMagic     = errors.New("warp zap: bad wire magic")
	errZapBadBool      = errors.New("warp zap: bool not in {0x00,0x01}")
	errZapTrailing     = errors.New("warp zap: trailing bytes after value")
	errZapLenOverflow  = errors.New("warp zap: length prefix exceeds remaining bytes")
	errZapBitsNonCanon = errors.New("warp zap: bitset has trailing zero byte (non-canonical)")
)

// ---------------------------------------------------------------------
// Encode primitives (append-style, total-order canonical).
// ---------------------------------------------------------------------

func appendU8(dst []byte, v uint8) []byte { return append(dst, v) }

func appendU16(dst []byte, v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return append(dst, b[:]...)
}

func appendU32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(dst, b[:]...)
}

func appendU64(dst []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(dst, b[:]...)
}

// appendBool writes exactly one byte: 0x01 for true, 0x00 for false.
func appendBool(dst []byte, v bool) []byte {
	if v {
		return append(dst, 0x01)
	}
	return append(dst, 0x00)
}

// appendFixed writes raw bytes with no length prefix. The caller
// guarantees a fixed width known to the decoder ([20]/[32]/[96]).
func appendFixed(dst, b []byte) []byte { return append(dst, b...) }

// appendVar writes a u32 big-endian length prefix followed by the bytes.
// This is the single framing for every variable-length field.
func appendVar(dst, b []byte) []byte {
	dst = appendU32(dst, uint32(len(b)))
	return append(dst, b...)
}

// ---------------------------------------------------------------------
// Decode cursor (strict, bounds-checked, trailing-byte aware).
// ---------------------------------------------------------------------

// zapReader is a forward-only cursor over a byte buffer. Each read is
// bounds-checked; a short read returns errZapShort rather than panicking.
type zapReader struct {
	buf []byte
	off int
}

func newZapReader(b []byte) *zapReader { return &zapReader{buf: b} }

func (r *zapReader) remaining() int { return len(r.buf) - r.off }

// expectMagic consumes and verifies the 5-byte wire magic.
func (r *zapReader) expectMagic() error {
	if r.remaining() < len(wireMagic) {
		return fmt.Errorf("%w: magic", errZapShort)
	}
	if !bytes.Equal(r.buf[r.off:r.off+len(wireMagic)], wireMagic[:]) {
		return errZapBadMagic
	}
	r.off += len(wireMagic)
	return nil
}

func (r *zapReader) u8() (uint8, error) {
	if r.remaining() < 1 {
		return 0, fmt.Errorf("%w: u8", errZapShort)
	}
	v := r.buf[r.off]
	r.off++
	return v, nil
}

func (r *zapReader) u16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, fmt.Errorf("%w: u16", errZapShort)
	}
	v := binary.BigEndian.Uint16(r.buf[r.off:])
	r.off += 2
	return v, nil
}

func (r *zapReader) u32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, fmt.Errorf("%w: u32", errZapShort)
	}
	v := binary.BigEndian.Uint32(r.buf[r.off:])
	r.off += 4
	return v, nil
}

func (r *zapReader) u64() (uint64, error) {
	if r.remaining() < 8 {
		return 0, fmt.Errorf("%w: u64", errZapShort)
	}
	v := binary.BigEndian.Uint64(r.buf[r.off:])
	r.off += 8
	return v, nil
}

// boolean reads one byte and rejects anything other than 0x00 / 0x01.
func (r *zapReader) boolean() (bool, error) {
	v, err := r.u8()
	if err != nil {
		return false, err
	}
	switch v {
	case 0x00:
		return false, nil
	case 0x01:
		return true, nil
	default:
		return false, fmt.Errorf("%w: 0x%02x", errZapBadBool, v)
	}
}

// fixedInto reads exactly len(dst) raw bytes into dst.
func (r *zapReader) fixedInto(dst []byte) error {
	n := len(dst)
	if r.remaining() < n {
		return fmt.Errorf("%w: fixed(%d)", errZapShort, n)
	}
	copy(dst, r.buf[r.off:r.off+n])
	r.off += n
	return nil
}

// varbytes reads a u32-BE length-prefixed frame, returning a fresh copy.
// The declared length must not exceed the bytes remaining after the
// prefix — this bounds allocation to the input size (no length bomb).
func (r *zapReader) varbytes() ([]byte, error) {
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(r.remaining()) {
		return nil, fmt.Errorf("%w: want %d have %d", errZapLenOverflow, n, r.remaining())
	}
	out := make([]byte, n)
	copy(out, r.buf[r.off:r.off+int(n)])
	r.off += int(n)
	return out, nil
}

// end asserts the cursor is exactly at the end of the buffer. Trailing
// bytes are a canonical-form violation and are rejected.
func (r *zapReader) end() error {
	if r.off != len(r.buf) {
		return fmt.Errorf("%w: %d byte(s) remain", errZapTrailing, len(r.buf)-r.off)
	}
	return nil
}

// ---------------------------------------------------------------------
// Canonical bitset helpers (rule 6).
// ---------------------------------------------------------------------

// canonicalBits returns the trim-canonical form of a bitset: trailing
// zero bytes removed so the encoding is unique. set operations (Add
// growing the backing slice) can leave trailing zero bytes; the wire
// form must not carry them.
func canonicalBits(b Bits) Bits { return b.trim() }

// checkCanonicalBits rejects a decoded bitset whose final byte is zero —
// a non-canonical encoding (two byte strings for the same logical set).
func checkCanonicalBits(b []byte) error {
	if len(b) > 0 && b[len(b)-1] == 0 {
		return errZapBitsNonCanon
	}
	return nil
}
