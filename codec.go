// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"github.com/luxfi/geth/rlp"
)

// CodecImpl is used for serializing/deserializing warp messages
type CodecImpl struct{}

// Codec is the default codec instance
var Codec = &CodecImpl{}

// Marshal serializes the value
func (c *CodecImpl) Marshal(version uint16, v interface{}) ([]byte, error) {
	return rlp.EncodeToBytes(v)
}

// Unmarshal deserializes the bytes
func (c *CodecImpl) Unmarshal(b []byte, v interface{}) (uint16, error) {
	err := rlp.DecodeBytes(b, v)
	return CodecVersion, err
}

// RegisterType is a no-op for RLP codec
func (c *CodecImpl) RegisterType(v interface{}) error {
	return nil
}
