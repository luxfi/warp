// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"bytes"
	"errors"

	"github.com/luxfi/crypto/bls"
)

var (
	_ Signer = (*signer)(nil)

	ErrWrongSourceChainID = errors.New("wrong SourceChainID")
	ErrWrongNetworkID     = errors.New("wrong networkID")
)

// Signer signs warp messages
type Signer interface {
	// Sign signs an unsigned warp message and returns the signature bytes
	Sign(msg *UnsignedMessage) ([]byte, error)
}

// NewSigner creates a new warp message signer
func NewSigner(sk *bls.SecretKey, networkID uint32, chainID []byte) Signer {
	return &signer{
		sk:        sk,
		networkID: networkID,
		chainID:   chainID,
	}
}

type signer struct {
	sk        *bls.SecretKey
	networkID uint32
	chainID   []byte
}

func (s *signer) Sign(msg *UnsignedMessage) ([]byte, error) {
	// Compare source chain ID
	if !bytes.Equal(msg.SourceChainID, s.chainID) {
		return nil, ErrWrongSourceChainID
	}
	if msg.NetworkID != s.networkID {
		return nil, ErrWrongNetworkID
	}

	msgBytes := msg.Bytes()
	sig, err := s.sk.Sign(msgBytes)
	if err != nil {
		return nil, err
	}
	return bls.SignatureToBytes(sig), nil
}
