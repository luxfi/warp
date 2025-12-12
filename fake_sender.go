// Copyright (C) 2019-2025, Lux Industries Inc All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"context"

	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
)

// FakeSender is a test implementation of Sender that does nothing.
type FakeSender struct{}

func (FakeSender) SendRequest(context.Context, set.Set[ids.NodeID], uint32, []byte) error {
	return nil
}

func (FakeSender) SendResponse(context.Context, ids.NodeID, uint32, []byte) error {
	return nil
}

func (FakeSender) SendError(context.Context, ids.NodeID, uint32, int32, string) error {
	return nil
}

func (FakeSender) SendGossip(context.Context, SendConfig, []byte) error {
	return nil
}
