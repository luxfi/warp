// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnsignedMessage(t *testing.T) {
	networkID := uint32(1)
	sourceChainID := make([]byte, 32)
	sourceChainID[31] = 1
	payload := []byte("test payload")

	// Create unsigned message
	msg, err := NewUnsignedMessage(networkID, sourceChainID, payload)
	require.NoError(t, err)
	require.NotNil(t, msg)

	// Verify fields
	require.Equal(t, networkID, msg.NetworkID)
	require.Equal(t, sourceChainID, msg.SourceChainID)
	require.Equal(t, payload, msg.Payload)

	// Test serialization
	bytes := msg.Bytes()
	require.NotEmpty(t, bytes)

	// Test ID
	id := msg.ID()
	require.Len(t, id, 32)

	// Test parsing
	parsed, err := ParseUnsignedMessage(bytes)
	require.NoError(t, err)
	require.Equal(t, msg.NetworkID, parsed.NetworkID)
	require.Equal(t, msg.SourceChainID, parsed.SourceChainID)
	require.Equal(t, msg.Payload, parsed.Payload)
}

func TestInvalidUnsignedMessage(t *testing.T) {
	networkID := uint32(1)
	payload := []byte("test payload")

	// Invalid source chain ID (not 32 bytes)
	_, err := NewUnsignedMessage(networkID, []byte("short"), payload)
	require.Error(t, err)

	// Valid message
	sourceChainID := make([]byte, 32)
	msg, err := NewUnsignedMessage(networkID, sourceChainID, payload)
	require.NoError(t, err)
	require.NotNil(t, msg)
}

func TestVerifyWeight(t *testing.T) {
	tests := []struct {
		name          string
		signedWeight  uint64
		totalWeight   uint64
		quorumNum     uint64
		quorumDen     uint64
		expectedError bool
	}{
		{
			name:          "valid 2/3 quorum",
			signedWeight:  67,
			totalWeight:   100,
			quorumNum:     2,
			quorumDen:     3,
			expectedError: false,
		},
		{
			name:          "exact quorum",
			signedWeight:  2,
			totalWeight:   3,
			quorumNum:     2,
			quorumDen:     3,
			expectedError: false,
		},
		{
			name:          "insufficient weight",
			signedWeight:  1,
			totalWeight:   3,
			quorumNum:     2,
			quorumDen:     3,
			expectedError: true,
		},
		{
			name:          "zero signed weight",
			signedWeight:  0,
			totalWeight:   100,
			quorumNum:     2,
			quorumDen:     3,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyWeight(tt.signedWeight, tt.totalWeight, tt.quorumNum, tt.quorumDen)
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
