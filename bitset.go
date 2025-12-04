// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"fmt"
	"math/bits"
)

// Bits represents a bit set
type Bits []byte

// NewBits creates a new bit set
func NewBitSet() Bits {
	return make(Bits, 0)
}

// Add adds an index to the bit set
func (b *Bits) Add(i int) {
	if i < 0 {
		return
	}
	byteIndex := i / 8
	bitIndex := i % 8

	// Grow slice if needed
	for len(*b) <= byteIndex {
		*b = append(*b, 0)
	}

	(*b)[byteIndex] |= 1 << uint(bitIndex) //nolint:gosec // bitIndex is always 0-7
}

// Contains returns true if the bit set contains the index
func (b Bits) Contains(i int) bool {
	if i < 0 {
		return false
	}
	byteIndex := i / 8
	if byteIndex >= len(b) {
		return false
	}
	bitIndex := i % 8
	return (b[byteIndex] & (1 << uint(bitIndex))) != 0 //nolint:gosec // bitIndex is always 0-7
}

// BitLen returns the number of bits that can be represented (capacity)
func (b Bits) BitLen() int {
	return len(b) * 8
}

// HighestSetBit returns the highest bit index that is set + 1
// Returns 0 if no bits are set
func (b Bits) HighestSetBit() int {
	// Find the last non-zero byte
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != 0 {
			// Find the highest bit in this byte
			return i*8 + bits.Len8(b[i])
		}
	}
	return 0
}

// Len returns the number of set bits
func (b Bits) Len() int {
	count := 0
	for _, byte := range b {
		count += bits.OnesCount8(byte)
	}
	return count
}

// Equal returns true if two bit sets are equal
func (b Bits) Equal(other Bits) bool {
	if len(b) != len(other) {
		// Normalize lengths by trimming trailing zeros
		b = b.trim()
		other = other.trim()
		if len(b) != len(other) {
			return false
		}
	}

	for i := range b {
		if b[i] != other[i] {
			return false
		}
	}
	return true
}

// trim removes trailing zero bytes
func (b Bits) trim() Bits {
	i := len(b) - 1
	for i >= 0 && b[i] == 0 {
		i--
	}
	return b[:i+1]
}

// String returns a string representation of the bit set
func (b Bits) String() string {
	if len(b) == 0 {
		return "{}"
	}

	indices := make([]int, 0, b.Len())
	for i := 0; i < b.BitLen(); i++ {
		if b.Contains(i) {
			indices = append(indices, i)
		}
	}

	return fmt.Sprintf("%v", indices)
}

// Clear removes all bits from the set
func (b *Bits) Clear() {
	*b = (*b)[:0]
}

// Union returns the union of two bit sets
func (b Bits) Union(other Bits) Bits {
	maxLen := len(b)
	if len(other) > maxLen {
		maxLen = len(other)
	}

	result := make(Bits, maxLen)
	copy(result, b)
	for i := 0; i < len(other); i++ {
		result[i] |= other[i]
	}

	return result
}

// Intersection returns the intersection of two bit sets
func (b Bits) Intersection(other Bits) Bits {
	minLen := len(b)
	if len(other) < minLen {
		minLen = len(other)
	}

	result := make(Bits, minLen)
	for i := 0; i < minLen; i++ {
		result[i] = b[i] & other[i]
	}

	return result.trim()
}

// Difference returns the difference of two bit sets (elements in b but not in other)
func (b Bits) Difference(other Bits) Bits {
	result := make(Bits, len(b))
	copy(result, b)

	for i := 0; i < len(other) && i < len(result); i++ {
		result[i] &^= other[i]
	}

	return result.trim()
}
