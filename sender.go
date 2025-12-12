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
	// SendRequest sends a warp request to the given nodes.
	SendRequest(ctx context.Context, nodeIDs set.Set[ids.NodeID], requestID uint32, requestBytes []byte) error

	// SendResponse sends a warp response to a request.
	SendResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, responseBytes []byte) error

	// SendError sends a warp error response
	SendError(ctx context.Context, nodeID ids.NodeID, requestID uint32, errorCode int32, errorMessage string) error

	// SendGossip sends a warp gossip message.
	SendGossip(ctx context.Context, config SendConfig, gossipBytes []byte) error

	// SendAppRequest is an alias for SendRequest (for backward compatibility)
	SendAppRequest(ctx context.Context, nodeIDs set.Set[ids.NodeID], requestID uint32, requestBytes []byte) error

	// SendAppResponse is an alias for SendResponse (for backward compatibility)
	SendAppResponse(ctx context.Context, nodeID ids.NodeID, requestID uint32, responseBytes []byte) error

	// SendAppError is an alias for SendError (for backward compatibility)
	SendAppError(ctx context.Context, nodeID ids.NodeID, requestID uint32, errorCode int32, errorMessage string) error

	// SendAppGossip is an alias for SendGossip but takes nodeIDs directly
	SendAppGossip(ctx context.Context, nodeIDs set.Set[ids.NodeID], gossipBytes []byte) error
}
