// Copyright (C) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package relayer

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/logging"
	"github.com/ava-labs/icm-services/peers"
	"github.com/ava-labs/icm-services/relayer/config"
	"github.com/ava-labs/icm-services/utils"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

const retryPeriodSeconds = 5

// Convenience function to initialize connections and check stake for all source blockchains.
// This function blocks until it successfully connects to sufficient stake for all source blockchains
// or returns an error if unable to fetch warpConfigs or to connect to sufficient stake before timeout.
//
// Sufficient stake is determined by the Warp quora of the configured supported destinations,
// or if the subnet supports all destinations, by the quora of all configured destinations.
func InitializeConnectionsAndCheckStake(
	logger logging.Logger,
	network peers.AppRequestNetwork,
	cfg *config.Config,
) error {
	for _, sourceBlockchainConfig := range cfg.SourceBlockchains {
		network.TrackSubnet(sourceBlockchainConfig.GetSubnetID())
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(cfg.InitialConnectionTimeoutSeconds)*time.Second,
	)
	defer cancel()

	eg, ctx := errgroup.WithContext(ctx)
	for _, sourceBlockchain := range cfg.SourceBlockchains {
		eg.Go(func() error {
			if err := connectToPeers(ctx, logger, network, cfg, sourceBlockchain); err != nil {
				return fmt.Errorf(
					"failed to connect to non-primary network peers: %w",
					err,
				)
			}
			return nil
		})
	}
	return eg.Wait()
}

// Connect to the validators of the source blockchain. For each destination blockchain,
// verify that we have connected to a threshold of stake.
func connectToPeers(
	ctx context.Context,
	logger logging.Logger,
	network peers.AppRequestNetwork,
	cfg *config.Config,
	sourceBlockchain *config.SourceBlockchain,
) error {
	subnetID := sourceBlockchain.GetSubnetID()
	// Loop over destination blockchains here to confirm connections to a threshold of stake
	// which is determined by the Warp Quorum configs of the destination blockchains.
	for _, destination := range sourceBlockchain.SupportedDestinations {
		blockchainID := destination.GetBlockchainID()
		for {
			connectedValidators, err := network.GetConnectedCanonicalValidators(subnetID)
			if err != nil {
				logger.Error(
					"Failed to connect to canonical validators",
					zap.String("subnetID", subnetID.String()),
					zap.Error(err),
				)
				return err
			}
			ok, err := checkForSufficientConnectedStake(
				logger,
				cfg,
				connectedValidators,
				blockchainID)
			if err != nil {
				return err
			}
			if ok {
				break
			}
			logger.Warn(
				"Failed to connect to a threshold of stake, retrying...",
				zap.Stringer("subnetID", subnetID),
				zap.Stringer("destinationBlockchainID", blockchainID),
				zap.Uint64("connectedWeight", connectedValidators.ConnectedWeight),
				zap.Uint64("totalValidatorWeight", connectedValidators.ValidatorSet.TotalWeight),
			)
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				time.Sleep(retryPeriodSeconds * time.Second)
			}
		}
	}
	return nil
}

// Fetch the warp config from the destination chain config and check if the connected stake exceeds the threshold
func checkForSufficientConnectedStake(
	logger logging.Logger,
	cfg *config.Config,
	connectedValidators *peers.ConnectedCanonicalValidators,
	destinationBlockchainID ids.ID,
) (bool, error) {
	warpConfig, err := cfg.GetWarpConfig(destinationBlockchainID)
	if err != nil {
		logger.Error(
			"Failed to get warp config from chain config",
			zap.String("destinationBlockchainID", destinationBlockchainID.String()),
			zap.Error(err),
		)
		return false, err
	}
	return utils.CheckStakeWeightExceedsThreshold(
		big.NewInt(0).SetUint64(connectedValidators.ConnectedWeight),
		connectedValidators.ValidatorSet.TotalWeight,
		warpConfig.QuorumNumerator,
	), nil
}
