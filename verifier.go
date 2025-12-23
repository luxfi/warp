// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"context"
)

// Verifier verifies warp messages before signing
type Verifier interface {
	// Verify verifies an unsigned warp message with justification.
	// Returns nil on success, or an error if verification fails.
	Verify(ctx context.Context, unsignedMessage *UnsignedMessage, justification []byte) error
}
