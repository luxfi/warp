// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package signer

import (
	"context"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/warp"
)

// Signer is an interface for signing warp messages
type Signer interface {
	// Sign signs a message
	Sign(msg *warp.UnsignedMessage) (*bls.Signature, error)

	// GetPublicKey returns the public key
	GetPublicKey() *bls.PublicKey
}

// LocalSigner signs messages with a local secret key
type LocalSigner struct {
	sk *bls.SecretKey
	pk *bls.PublicKey
}

// NewLocalSigner creates a new local signer
func NewLocalSigner(sk *bls.SecretKey) *LocalSigner {
	return &LocalSigner{
		sk: sk,
		pk: sk.PublicKey(),
	}
}

// Sign signs a message
func (s *LocalSigner) Sign(msg *warp.UnsignedMessage) (*bls.Signature, error) {
	return warp.Sign(msg.Bytes(), s.sk)
}

// GetPublicKey returns the public key
func (s *LocalSigner) GetPublicKey() *bls.PublicKey {
	return s.pk
}

// Backend is an interface for signing backends
type Backend interface {
	// Sign signs a message with multiple signers
	Sign(ctx context.Context, msg *warp.UnsignedMessage, signerIndices []int) (*warp.Message, error)

	// GetValidators returns the current validator set
	GetValidators(ctx context.Context) ([]*warp.Validator, error)
}

// SignerBackend manages multiple signers
type SignerBackend struct {
	signers    map[int]Signer
	validators []*warp.Validator
}

// NewSignerBackend creates a new signer backend
func NewSignerBackend(validators []*warp.Validator) *SignerBackend {
	return &SignerBackend{
		signers:    make(map[int]Signer),
		validators: validators,
	}
}

// AddSigner adds a signer for a validator
func (b *SignerBackend) AddSigner(index int, signer Signer) error {
	if index < 0 || index >= len(b.validators) {
		return fmt.Errorf("invalid validator index %d", index)
	}

	// Verify public key matches
	expectedPK := b.validators[index].PublicKey
	if expectedPK != signer.GetPublicKey() {
		return errors.New("signer public key does not match validator")
	}

	b.signers[index] = signer
	return nil
}

// Sign signs a message with multiple signers
func (b *SignerBackend) Sign(
	ctx context.Context, msg *warp.UnsignedMessage, signerIndices []int,
) (*warp.Message, error) {
	if len(signerIndices) == 0 {
		return nil, errors.New("no signers specified")
	}

	// Get signers
	signers := make([]*bls.SecretKey, 0, len(signerIndices))
	for _, idx := range signerIndices {
		signer, ok := b.signers[idx]
		if !ok {
			return nil, fmt.Errorf("no signer for validator %d", idx)
		}

		// For local signers, we need the secret key
		localSigner, ok := signer.(*LocalSigner)
		if !ok {
			return nil, fmt.Errorf("signer %d is not a local signer", idx)
		}

		signers = append(signers, localSigner.sk)
	}

	// Sign message
	return warp.SignMessage(msg, signers, b.validators)
}

// GetValidators returns the current validator set
func (b *SignerBackend) GetValidators(ctx context.Context) ([]*warp.Validator, error) {
	return b.validators, nil
}

// RemoteSigner signs messages via RPC
type RemoteSigner struct {
	client SignerClient
	pk     *bls.PublicKey
}

// SignerClient is an interface for remote signing
type SignerClient interface {
	// Sign signs a message remotely
	Sign(ctx context.Context, msg []byte) ([]byte, error)

	// GetPublicKey gets the public key
	GetPublicKey(ctx context.Context) ([]byte, error)
}

// NewRemoteSigner creates a new remote signer
func NewRemoteSigner(client SignerClient) (*RemoteSigner, error) {
	// Get public key from remote
	pkBytes, err := client.GetPublicKey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	pk, err := bls.PublicKeyFromCompressedBytes(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &RemoteSigner{
		client: client,
		pk:     pk,
	}, nil
}

// Sign signs a message
func (s *RemoteSigner) Sign(msg *warp.UnsignedMessage) (*bls.Signature, error) {
	sigBytes, err := s.client.Sign(context.Background(), msg.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to sign remotely: %w", err)
	}

	return bls.SignatureFromBytes(sigBytes)
}

// GetPublicKey returns the public key
func (s *RemoteSigner) GetPublicKey() *bls.PublicKey {
	return s.pk
}
