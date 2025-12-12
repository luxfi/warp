// Copyright (C) 2019-2025, Lux Industries Inc All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import "github.com/luxfi/p2p"

// Error is an alias for p2p.Error for backward compatibility
type Error = p2p.Error

// Standard errors re-exported from p2p
var (
	ErrUnexpected          = p2p.ErrUnexpected
	ErrUnregisteredHandler = p2p.ErrUnregisteredHandler
	ErrNotValidator        = p2p.ErrNotValidator
	ErrThrottled           = p2p.ErrThrottled
)
