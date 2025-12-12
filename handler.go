// Copyright (C) 2019-2025, Lux Industries Inc All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"context"
	"time"

	"github.com/luxfi/ids"
)

// Handler handles warp messages
type Handler interface {
	Request(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, msg []byte) error
	Response(ctx context.Context, nodeID ids.NodeID, requestID uint32, msg []byte) error
	Gossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error
	RequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, err *Error) error

	// App* methods are aliases for backward compatibility
	AppRequest(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, msg []byte) error
	AppResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, msg []byte) error
	AppGossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error
	AppRequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, err *Error) error
}
