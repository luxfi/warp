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

// Sender sends warp messages
type Sender interface {
	SendRequest(ctx context.Context, nodeIDs set.Set[ids.NodeID], requestID uint32, requestBytes []byte) error
	SendResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, responseBytes []byte) error
	SendError(ctx context.Context, nodeID ids.NodeID, requestID uint32, errorCode int32, errorMessage string) error
	SendGossip(ctx context.Context, config SendConfig, gossipBytes []byte) error
}

// AppSender sends application-level messages between nodes.
// This is the interface used by VMs for cross-node communication.
type AppSender interface {
	SendAppRequest(ctx context.Context, nodeIDs set.Set[ids.NodeID], requestID uint32, appRequestBytes []byte) error
	SendAppResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, appResponseBytes []byte) error
	SendAppError(ctx context.Context, nodeID ids.NodeID, requestID uint32, errorCode int32, errorMessage string) error
	SendAppGossip(ctx context.Context, config SendConfig, appGossipBytes []byte) error
}
