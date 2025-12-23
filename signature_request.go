// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/p2p"
)

// SignatureHandlerID is the protocol ID for warp signature handling
const SignatureHandlerID = 0x12345678

// SignatureRequest represents a request for a warp signature
type SignatureRequest struct {
	Message       []byte
	Justification []byte
}

// SignatureResponse represents a warp signature response
type SignatureResponse struct {
	Signature []byte
}

// MarshalSignatureRequest marshals a signature request to bytes
func MarshalSignatureRequest(req *SignatureRequest) ([]byte, error) {
	// Format: msgLen(4) + msg + justLen(4) + just
	msgLen := len(req.Message)
	justLen := len(req.Justification)
	buf := make([]byte, 4+msgLen+4+justLen)
	binary.BigEndian.PutUint32(buf[0:4], uint32(msgLen))
	copy(buf[4:4+msgLen], req.Message)
	binary.BigEndian.PutUint32(buf[4+msgLen:8+msgLen], uint32(justLen))
	copy(buf[8+msgLen:], req.Justification)
	return buf, nil
}

// UnmarshalSignatureRequest unmarshals bytes to a signature request
func UnmarshalSignatureRequest(data []byte) (*SignatureRequest, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("data too short: %d", len(data))
	}
	msgLen := binary.BigEndian.Uint32(data[0:4])
	if len(data) < int(4+msgLen+4) {
		return nil, fmt.Errorf("data too short for message: %d", len(data))
	}
	justLen := binary.BigEndian.Uint32(data[4+msgLen : 8+msgLen])
	if len(data) < int(8+msgLen+justLen) {
		return nil, fmt.Errorf("data too short for justification: %d", len(data))
	}
	return &SignatureRequest{
		Message:       data[4 : 4+msgLen],
		Justification: data[8+msgLen : 8+msgLen+justLen],
	}, nil
}

// MarshalSignatureResponse marshals a signature response to bytes
func MarshalSignatureResponse(signature []byte) ([]byte, error) {
	// Format: sigLen(4) + sig
	buf := make([]byte, 4+len(signature))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(signature)))
	copy(buf[4:], signature)
	return buf, nil
}

// UnmarshalSignatureResponse unmarshals bytes to a signature response
func UnmarshalSignatureResponse(data []byte) (*SignatureResponse, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short: %d", len(data))
	}
	sigLen := binary.BigEndian.Uint32(data[0:4])
	if len(data) < int(4+sigLen) {
		return nil, fmt.Errorf("data too short for signature: %d", len(data))
	}
	return &SignatureResponse{
		Signature: data[4 : 4+sigLen],
	}, nil
}

// SignatureHandler handles warp signature requests
type SignatureHandler interface {
	// Request handles an incoming signature request
	Request(ctx context.Context, nodeID ids.NodeID, deadline time.Time, request []byte) ([]byte, error)
}

// NoOpSignatureHandler is a no-op implementation of SignatureHandler
type NoOpSignatureHandler struct{}

// Request returns an empty response
func (NoOpSignatureHandler) Request(context.Context, ids.NodeID, time.Time, []byte) ([]byte, error) {
	return nil, nil
}

// SignatureCacher provides caching for signature responses
type SignatureCacher[K comparable, V any] interface {
	Get(key K) (V, bool)
	Put(key K, value V)
}

// CachedSignatureHandler implements a cached handler for warp signatures
type CachedSignatureHandler struct {
	cache   SignatureCacher[ids.ID, []byte]
	backend interface{}
	signer  Signer
}

// NewCachedSignatureHandler creates a new cached signature handler
func NewCachedSignatureHandler(cache SignatureCacher[ids.ID, []byte], backend interface{}, signer Signer) SignatureHandler {
	return &CachedSignatureHandler{
		cache:   cache,
		backend: backend,
		signer:  signer,
	}
}

// Request handles an incoming signature request with caching
func (h *CachedSignatureHandler) Request(ctx context.Context, nodeID ids.NodeID, deadline time.Time, request []byte) ([]byte, error) {
	req, err := UnmarshalSignatureRequest(request)
	if err != nil {
		return nil, err
	}

	unsignedMessage, err := ParseUnsignedMessage(req.Message)
	if err != nil {
		return nil, err
	}

	// Check cache
	messageID := unsignedMessage.ID()
	if signatureBytes, ok := h.cache.Get(messageID); ok {
		return MarshalSignatureResponse(signatureBytes)
	}

	// Verify if backend is a Verifier
	if verifier, ok := h.backend.(Verifier); ok {
		if appErr := verifier.Verify(ctx, unsignedMessage, req.Justification); appErr != nil {
			return nil, appErr
		}
	}

	// Sign the message
	if h.signer == nil {
		return nil, fmt.Errorf("signer is nil")
	}
	signatureBytes, err := h.signer.Sign(unsignedMessage)
	if err != nil {
		return nil, err
	}

	h.cache.Put(messageID, signatureBytes)

	return MarshalSignatureResponse(signatureBytes)
}

// Ensure SignatureHandlerAdapter implements p2p.Handler
var _ p2p.Handler = (*SignatureHandlerAdapter)(nil)

// SignatureHandlerAdapter adapts a SignatureHandler to the p2p.Handler interface.
// This allows warp signature handlers to be registered with the p2p router.
type SignatureHandlerAdapter struct {
	handler SignatureHandler
}

// NewSignatureHandlerAdapter creates a new adapter that wraps a SignatureHandler
// and implements the p2p.Handler interface.
func NewSignatureHandlerAdapter(handler SignatureHandler) *SignatureHandlerAdapter {
	return &SignatureHandlerAdapter{handler: handler}
}

// Gossip implements p2p.Handler. Signature handlers do not use gossip.
func (a *SignatureHandlerAdapter) Gossip(ctx context.Context, nodeID ids.NodeID, gossipBytes []byte) {
	// Signature handlers do not use Gossip
}

// Request implements p2p.Handler by delegating to the wrapped SignatureHandler.
func (a *SignatureHandlerAdapter) Request(ctx context.Context, nodeID ids.NodeID, deadline time.Time, requestBytes []byte) ([]byte, *p2p.Error) {
	response, err := a.handler.Request(ctx, nodeID, deadline, requestBytes)
	if err != nil {
		return nil, &p2p.Error{
			Code:    500,
			Message: err.Error(),
		}
	}
	return response, nil
}
