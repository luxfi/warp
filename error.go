// Copyright (C) 2019-2025, Lux Industries Inc All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import "fmt"

// Error represents a warp error
type Error struct {
	Code    int32
	Message string
}

// Error implements the error interface
func (e *Error) Error() string {
	return fmt.Sprintf("warp error %d: %s", e.Code, e.Message)
}

// AppError is an alias for Error, used by VMs for application-level errors.
type AppError = Error
