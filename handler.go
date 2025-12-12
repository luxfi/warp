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
	// Request handles an incoming request and returns a response or error
	Request(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, msg []byte) ([]byte, *Error)
	// Response handles an incoming response to a previous request
	Response(ctx context.Context, nodeID ids.NodeID, requestID uint32, msg []byte) error
	// Gossip handles an incoming gossip message
	Gossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error
	// RequestFailed is called when a request fails
	RequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, err *Error) error
}
