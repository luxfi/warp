// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"errors"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
)

var (
	_ Signer = (*signer)(nil)

	ErrWrongSourceChainID = errors.New("wrong SourceChainID")
	ErrWrongNetworkID     = errors.New("wrong networkID")
)

// Signer signs warp messages
type Signer interface {
	Sign(msg *UnsignedMessage) ([]byte, error)
}

// NewSigner creates a new warp message signer
func NewSigner(sk *bls.SecretKey, networkID uint32, chainID ids.ID) Signer {
	return &signer{
		sk:        sk,
		networkID: networkID,
		chainID:   chainID,
	}
}

type signer struct {
	sk        *bls.SecretKey
	networkID uint32
	chainID   ids.ID
}

func (s *signer) Sign(msg *UnsignedMessage) ([]byte, error) {
	if msg.SourceChainID != s.chainID {
		return nil, ErrWrongSourceChainID
	}
	if msg.NetworkID != s.networkID {
		return nil, ErrWrongNetworkID
	}

	sig, err := s.sk.Sign(msg.Bytes())
	if err != nil {
		return nil, err
	}
	return bls.SignatureToBytes(sig), nil
}
