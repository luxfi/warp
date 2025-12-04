// Copyright (C) 2025, Lux Industries, Inc.
// See the file LICENSE for licensing terms.

package main

import (
	"fmt"

	"github.com/luxfi/warp/types"
)

// SimpleMessage implements the types.Message interface
type SimpleMessage struct {
	id       types.ID
	sourceID types.ID
	destID   types.ID
	payload  []byte
}

func (m *SimpleMessage) ID() types.ID                 { return m.id }
func (m *SimpleMessage) SourceChainID() types.ID      { return m.sourceID }
func (m *SimpleMessage) DestinationChainID() types.ID { return m.destID }
func (m *SimpleMessage) Payload() []byte              { return m.payload }
func (m *SimpleMessage) Serialize() ([]byte, error) {
	// Simple concatenation for example
	result := make([]byte, 0, 32*3+len(m.payload))
	result = append(result, m.sourceID[:]...)
	result = append(result, m.destID[:]...)
	result = append(result, m.payload...)
	return result, nil
}

func main() {
	// Create a simple cross-chain message
	msg := &SimpleMessage{
		id:       types.ID{1, 2, 3},
		sourceID: types.ID{0xAA},
		destID:   types.ID{0xBB},
		payload:  []byte("Hello from chain A to chain B!"),
	}

	fmt.Printf("Message ID: %x\n", msg.ID())
	fmt.Printf("Source Chain: %x\n", msg.SourceChainID())
	fmt.Printf("Destination Chain: %x\n", msg.DestinationChainID())
	fmt.Printf("Payload: %s\n", msg.Payload())
}
