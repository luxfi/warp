// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/log"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
	"github.com/luxfi/p2p"
)

var errFailedVerification = errors.New("failed verification")

type indexedValidator struct {
	*Validator
	Index int
}

type aggregatorResult struct {
	NodeID    ids.NodeID
	Validator indexedValidator
	Signature *bls.Signature
	Err       error
}

// NewSignatureAggregator returns an instance of SignatureAggregator
func NewSignatureAggregator(log log.Logger, client *p2p.Client) *SignatureAggregator {
	return &SignatureAggregator{
		log:    log,
		client: client,
	}
}

// SignatureAggregator aggregates validator signatures for warp messages
type SignatureAggregator struct {
	log    log.Logger
	client *p2p.Client
}

// AggregateSignatures blocks until quorumNum/quorumDen signatures from
// validators are requested to be aggregated into a warp message or the context
// is canceled. Returns the signed message and the amount of stake that signed
// the message. Caller is responsible for providing a well-formed canonical
// validator set corresponding to the signer bitset in the message.
func (s *SignatureAggregator) AggregateSignatures(
	ctx context.Context,
	message *Message,
	justification []byte,
	validators []*Validator,
	quorumNum uint64,
	quorumDen uint64,
) (
	_ *Message,
	aggregatedStake *big.Int,
	totalStake *big.Int,
	_ error,
) {
	request := &SignatureRequest{
		Message:       message.UnsignedMessage.Bytes(),
		Justification: justification,
	}

	requestBytes, err := MarshalSignatureRequest(request)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal signature request: %w", err)
	}

	nodeIDsToValidator := make(map[ids.NodeID]indexedValidator)
	// TODO expose concrete type to avoid type casting
	bitSetSignature, ok := message.Signature.(*BitSetSignature)
	if !ok {
		return nil, nil, nil, errors.New("invalid warp signature type")
	}

	signerBitSet := set.BitsFromBytes(bitSetSignature.Signers)

	nonSigners := make([]ids.NodeID, 0, len(validators))
	aggregatedStakeWeight := new(big.Int)
	totalStakeWeight := new(big.Int)
	for i, validator := range validators {
		totalStakeWeight.Add(totalStakeWeight, new(big.Int).SetUint64(validator.Weight))

		// Only try to aggregate signatures from validators that are not already in
		// the signer bit set
		if signerBitSet.Contains(i) {
			aggregatedStakeWeight.Add(aggregatedStakeWeight, new(big.Int).SetUint64(validator.Weight))
			continue
		}

		nodeID := validator.NodeID

		v := indexedValidator{
			Index:     i,
			Validator: validator,
		}

		nodeIDsToValidator[nodeID] = v
		nonSigners = append(nonSigners, nodeID)
	}

	// Account for requested signatures + the signature that was provided
	signatures := make([]*bls.Signature, 0, len(nonSigners)+1)
	if bitSetSignature.Signature != [bls.SignatureLen]byte{} {
		blsSignature, err := bls.SignatureFromBytes(bitSetSignature.Signature[:])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse bls signature: %w", err)
		}
		signatures = append(signatures, blsSignature)
	}

	results := make(chan aggregatorResult)
	handler := signatureResponseHandler{
		message:             message,
		nodeIDsToValidators: nodeIDsToValidator,
		results:             results,
	}

	if err := s.client.Request(ctx, set.Of(nonSigners...), requestBytes, handler.HandleResponse); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to send aggregation request: %w", err)
	}

	minThreshold := new(big.Int).Mul(totalStakeWeight, new(big.Int).SetUint64(quorumNum))
	minThreshold.Div(minThreshold, new(big.Int).SetUint64(quorumDen))

	// Block until:
	// 1. The context is cancelled
	// 2. We get responses from all validators
	// 3. The specified security threshold is reached
	for i := 0; i < len(nonSigners); i++ {
		select {
		case <-ctx.Done():
			// Try to return whatever progress we have if the context is cancelled
			msg, err := newAggregatedMessage(message, signerBitSet, signatures)
			if err != nil {
				return nil, nil, nil, err
			}

			return msg, aggregatedStakeWeight, totalStakeWeight, nil
		case result := <-results:
			if result.Err != nil {
				s.log.Debug(
					"dropping response",
					log.Stringer("nodeID", result.NodeID),
					log.Err(result.Err),
				)
				continue
			}

			// Validators may share public keys so drop any duplicate signatures
			if signerBitSet.Contains(result.Validator.Index) {
				s.log.Debug(
					"dropping duplicate signature",
					log.Stringer("nodeID", result.NodeID),
					log.Err(err),
				)
				continue
			}

			signatures = append(signatures, result.Signature)
			signerBitSet.Add(result.Validator.Index)
			aggregatedStakeWeight.Add(aggregatedStakeWeight, new(big.Int).SetUint64(result.Validator.Weight))

			if aggregatedStakeWeight.Cmp(minThreshold) != -1 {
				msg, err := newAggregatedMessage(message, signerBitSet, signatures)
				if err != nil {
					return nil, nil, nil, err
				}

				return msg, aggregatedStakeWeight, totalStakeWeight, nil
			}
		}
	}

	msg, err := newAggregatedMessage(message, signerBitSet, signatures)
	if err != nil {
		return nil, nil, nil, err
	}

	return msg, aggregatedStakeWeight, totalStakeWeight, nil
}

func newAggregatedMessage(
	message *Message,
	signerBitSet set.Bits,
	signatures []*bls.Signature,
) (*Message, error) {
	if len(signatures) == 0 {
		return message, nil
	}

	aggregateSignature, err := bls.AggregateSignatures(signatures)
	if err != nil {
		return nil, err
	}

	bitSetSignature := &BitSetSignature{
		Signers:   signerBitSet.Bytes(),
		Signature: [bls.SignatureLen]byte{},
	}
	copy(bitSetSignature.Signature[:], bls.SignatureToBytes(aggregateSignature))

	return NewMessage(message.UnsignedMessage, bitSetSignature)
}

type signatureResponseHandler struct {
	message             *Message
	nodeIDsToValidators map[ids.NodeID]indexedValidator
	results             chan aggregatorResult
}

func (r *signatureResponseHandler) HandleResponse(
	_ context.Context,
	nodeID ids.NodeID,
	responseBytes []byte,
	err error,
) {
	validator := r.nodeIDsToValidators[nodeID]
	if err != nil {
		r.results <- aggregatorResult{NodeID: nodeID, Validator: validator, Err: err}
		return
	}

	response, err := UnmarshalSignatureResponse(responseBytes)
	if err != nil {
		r.results <- aggregatorResult{NodeID: nodeID, Validator: validator, Err: err}
		return
	}

	signature, err := bls.SignatureFromBytes(response.Signature)
	if err != nil {
		r.results <- aggregatorResult{NodeID: nodeID, Validator: validator, Err: err}
		return
	}

	if !bls.Verify(validator.PublicKey, signature, r.message.UnsignedMessage.Bytes()) {
		r.results <- aggregatorResult{NodeID: nodeID, Validator: validator, Err: errFailedVerification}
		return
	}

	r.results <- aggregatorResult{NodeID: nodeID, Validator: validator, Signature: signature}
}
