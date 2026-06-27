// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"context"
)

// Verifier verifies warp messages before signing
type Verifier interface {
	// Verify verifies a Message with justification before this node
	// signs it. Returns nil on success, or an error if verification fails.
	Verify(ctx context.Context, message *Message, justification []byte) error
}
