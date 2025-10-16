// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package validators

//go:generate go run go.uber.org/mock/mockgen -source=$GOFILE -destination=./mocks/mock_canonical_validator_client.go -package=mocks

import (
	"context"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/utils/logging"
	"github.com/ava-labs/avalanchego/utils/rpc"
	"github.com/ava-labs/avalanchego/vms/platformvm"
	pchainapi "github.com/ava-labs/avalanchego/vms/platformvm/api"
	avalancheWarp "github.com/ava-labs/avalanchego/vms/platformvm/warp"
	"go.uber.org/zap"

	"github.com/ava-labs/icm-services/config"
	"github.com/ava-labs/icm-services/peers/utils"
	sharedUtils "github.com/ava-labs/icm-services/utils"
)

var _ CanonicalValidatorState = &CanonicalValidatorClient{}

// CanonicalValidatorState is an interface that wraps [avalancheWarp.ValidatorState] and adds additional
// convenience methods for fetching current and proposed validator sets.
type CanonicalValidatorState interface {
	avalancheWarp.ValidatorState

	GetSubnetID(ctx context.Context, blockchainID ids.ID) (ids.ID, error)
	GetCurrentValidatorSet(
		ctx context.Context,
		subnetID ids.ID,
	) (validators.WarpSet, error)
	GetAllValidatorSets(ctx context.Context, pchainHeight uint64) (map[ids.ID]validators.WarpSet, error)
	GetProposedValidators(ctx context.Context, subnetID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error)
}

// CanonicalValidatorClient wraps [platformvm.Client] and implements [CanonicalValidatorState]
type CanonicalValidatorClient struct {
	logger  logging.Logger
	client  *platformvm.Client
	options []rpc.Option
}

func NewCanonicalValidatorClient(logger logging.Logger, apiConfig *config.APIConfig) *CanonicalValidatorClient {
	client := platformvm.NewClient(apiConfig.BaseURL)
	options := utils.InitializeOptions(apiConfig)
	return &CanonicalValidatorClient{
		logger:  logger,
		client:  client,
		options: options,
	}
}

func (v *CanonicalValidatorClient) GetCurrentValidatorSet(
	ctx context.Context,
	subnetID ids.ID,
) (validators.WarpSet, error) {
	// Get the canonical validator set at the specified P-Chain height
	ctx, cancel := context.WithTimeout(ctx, sharedUtils.DefaultRPCTimeout)
	defer cancel()
	canonicalSubnetValidators, err := avalancheWarp.GetCanonicalValidatorSetFromSubnetID(
		ctx,
		v,
		pchainapi.ProposedHeight,
		subnetID,
	)
	if err != nil {
		v.logger.Error(
			"Failed to get the canonical subnet validator set",
			zap.String("subnetID", subnetID.String()),
			zap.Error(err),
		)
		return validators.WarpSet{}, err
	}

	return canonicalSubnetValidators, nil
}

func (v *CanonicalValidatorClient) GetSubnetID(ctx context.Context, blockchainID ids.ID) (ids.ID, error) {
	return v.client.ValidatedBy(ctx, blockchainID, v.options...)
}

func (v *CanonicalValidatorClient) GetProposedValidators(
	ctx context.Context,
	subnetID ids.ID,
) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	res, err := v.client.GetValidatorsAt(ctx, subnetID, pchainapi.ProposedHeight, v.options...)
	if err != nil {
		v.logger.Debug(
			"Error fetching proposed validators",
			zap.String("subnetID", subnetID.String()),
			zap.Error(err),
		)
		return nil, err
	}
	return res, nil
}

// Gets the validator set of the given subnet at the given P-chain block height.
// Uses [platform.getValidatorsAt] with supplied height
func (v *CanonicalValidatorClient) GetValidatorSet(
	ctx context.Context,
	height uint64,
	subnetID ids.ID,
) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	res, err := v.client.GetValidatorsAt(ctx, subnetID, pchainapi.Height(height), v.options...)
	if err != nil {
		v.logger.Debug(
			"Error fetching validators at height",
			zap.String("subnetID", subnetID.String()),
			zap.Uint64("pChainHeight", height),
			zap.Error(err),
		)
		return nil, err
	}
	return res, nil
}

// Gets all the validator sets at the given P-chain block height.
// Uses [platform.getAllValidatorsAt] with supplied height
func (v *CanonicalValidatorClient) GetAllValidatorSets(
	ctx context.Context,
	height uint64,
) (map[ids.ID]validators.WarpSet, error) {
	res, err := v.client.GetAllValidatorsAt(ctx, pchainapi.Height(height), v.options...)
	if err != nil {
		v.logger.Debug(
			"Error fetching validators at height",
			zap.Uint64("pChainHeight", height),
			zap.Error(err),
		)
		return nil, err
	}
	return res, nil
}
