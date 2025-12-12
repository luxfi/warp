// Copyright (C) 2019-2025, Lux Industries Inc All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"context"

	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
)

// SendConfig configures message sending.
type SendConfig struct {
	NodeIDs       set.Set[ids.NodeID]
	Validators    int
	NonValidators int
	Peers         int
}

// Sender sends messages between nodes.
// This is the primary interface for cross-node communication used by VMs.
type Sender interface {
	SendRequest(ctx context.Context, nodeIDs set.Set[ids.NodeID], requestID uint32, request []byte) error
	SendResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error
	SendError(ctx context.Context, nodeID ids.NodeID, requestID uint32, errorCode int32, errorMessage string) error
	SendGossip(ctx context.Context, config SendConfig, msg []byte) error
}
