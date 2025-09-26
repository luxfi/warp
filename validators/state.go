// (c) 2022-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package validators

import (
	"context"

	"github.com/luxfi/evm/iface"
	"github.com/luxfi/geth/common"
)

// State wraps the validator state to provide special handling for the Primary Network
type State struct {
	validatorState iface.ValidatorState
	subnetID       common.Hash
	chainID        common.Hash
	skipChainID    bool
}

// NewState creates a new State wrapper
func NewState(
	validatorState iface.ValidatorState,
	subnetID common.Hash,
	chainID common.Hash,
	skipChainID bool,
) *State {
	return &State{
		validatorState: validatorState,
		subnetID:       subnetID,
		chainID:        chainID,
		skipChainID:    skipChainID,
	}
}

// GetValidatorSet implements the ValidatorState interface
func (s *State) GetValidatorSet(ctx context.Context, height uint64, subnetID common.Hash) (map[common.Hash]*iface.ValidatorOutput, error) {
	return s.validatorState.GetValidatorSet(ctx, height, subnetID)
}

// GetCurrentHeight implements the ValidatorState interface
func (s *State) GetCurrentHeight(ctx context.Context) (uint64, error) {
	return s.validatorState.GetCurrentHeight(ctx)
}

// GetMinimumHeight implements the ValidatorState interface
func (s *State) GetMinimumHeight(ctx context.Context) (uint64, error) {
	return s.validatorState.GetMinimumHeight(ctx)
}

// GetSubnetID implements the ValidatorState interface
func (s *State) GetSubnetID(ctx context.Context, chainID common.Hash) (common.Hash, error) {
	if s.skipChainID && chainID == s.chainID {
		return s.subnetID, nil
	}
	return s.validatorState.GetSubnetID(ctx, chainID)
}
