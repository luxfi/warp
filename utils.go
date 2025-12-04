// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"crypto/sha256"
	"errors"
	"math"
)

// Constants
const (
	// KiB is 1024 bytes
	KiB = 1024

	// SignatureLen is the length of a BLS signature
	SignatureLen = 96

	// PublicKeyLen is the length of a BLS public key
	PublicKeyLen = 48
)

// CheckMulDoesNotOverflow checks if a * b would overflow uint64
func CheckMulDoesNotOverflow(a, b uint64) error {
	if a == 0 || b == 0 {
		return nil
	}
	if a > math.MaxUint64/b {
		return errors.New("multiplication would overflow")
	}
	return nil
}

// AddUint64 adds two uint64 values and returns an error if overflow
func AddUint64(a, b uint64) (uint64, error) {
	if a > math.MaxUint64-b {
		return 0, errors.New("addition would overflow")
	}
	return a + b, nil
}

// ComputeHash256 computes SHA256 hash
func ComputeHash256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
