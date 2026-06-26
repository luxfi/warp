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

// Signer signs warp messages. It signs the Beam domain
// (BeamSigningBytes(core.ID())), never the bare core bytes or an opaque
// caller-supplied digest.
type Signer interface {
	Sign(core *SignedCore) ([]byte, error)
}

// NewSigner creates a new warp message signer using a bls.Signer interface
func NewSigner(sk bls.Signer, networkID uint32, chainID ids.ID) Signer {
	return &signer{
		sk:        sk,
		networkID: networkID,
		chainID:   chainID,
	}
}

type signer struct {
	sk        bls.Signer
	networkID uint32
	chainID   ids.ID
}

func (s *signer) Sign(core *SignedCore) ([]byte, error) {
	if core.SourceChainID != s.chainID {
		return nil, ErrWrongSourceChainID
	}
	if core.NetworkID != s.networkID {
		return nil, ErrWrongNetworkID
	}

	sig, err := s.sk.Sign(BeamSigningBytes(core.ID()))
	if err != nil {
		return nil, err
	}
	return bls.SignatureToBytes(sig), nil
}
