// Copyright (C) 2019-2025, Lux Industries Inc All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"context"
	"time"

	"github.com/luxfi/ids"
)

// Handler handles warp messages between nodes.
// This is the primary interface for receiving cross-node messages used by VMs.
type Handler interface {
	// WarpRequest handles an incoming warp request and returns a response or error
	WarpRequest(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, msg []byte) ([]byte, *Error)
	// WarpResponse handles an incoming response to a previous warp request
	WarpResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, msg []byte) error
	// WarpGossip handles an incoming warp gossip message
	WarpGossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error
	// WarpRequestFailed is called when a warp request fails
	WarpRequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, err *Error) error
}
