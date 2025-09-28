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
	for _, subnet := range cfg.GetTrackedSubnets().List() {
		network.TrackSubnet(subnet)
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(cfg.InitialConnectionTimeoutSeconds)*time.Second,
	)
	defer cancel()

	eg, ctx := errgroup.WithContext(ctx)
	for _, sourceBlockchain := range cfg.SourceBlockchains {
		eg.Go(func() error {
			logger.Info("Checking sufficient stake for source blockchain",
				zap.Stringer("subnetID", sourceBlockchain.GetSubnetID()),
				zap.String("blockchainID", sourceBlockchain.GetBlockchainID().String()),
			)
			return checkSufficientConnectedStake(ctx, logger, network, cfg, sourceBlockchain)
		})
	}
	return eg.Wait()
}

// Returns when connected to sufficient stake for all supported destinations of the source blockchain or
// in case of errors or timeouts.
func checkSufficientConnectedStake(
	ctx context.Context,
	logger logging.Logger,
	network peers.AppRequestNetwork,
	cfg *config.Config,
	sourceBlockchain *config.SourceBlockchain,
) error {
	subnetID := sourceBlockchain.GetSubnetID()

	checkConns := func() error {
		// ACP-181: Check connectivity for each destination's specific validator requirements
		// This ensures we have sufficient stake for both epoched and standard validator sets
		for _, destination := range sourceBlockchain.SupportedDestinations {
			destinationBlockchainID := destination.GetBlockchainID()
			// Ensure we have a valid blockchain ID (type ids.ID)
			if destinationBlockchainID == ids.Empty {
				logger.Debug("Skipping empty destination blockchain ID")
				continue
			}
			warpConfig, err := cfg.GetWarpConfig(destinationBlockchainID)
			logger.Debug("Checking connectivity for destination",
				zap.Stringer("destinationBlockchainID", destinationBlockchainID),
				zap.Any("warpConfig", warpConfig),
				zap.Error(err),
			)
			if err != nil {
				logger.Error(
					"Failed to get warp config from chain config",
					zap.Stringer("destinationBlockchainID", destinationBlockchainID),
					zap.Error(err),
				)
				return err
			}

			// Get validators for this specific destination (epoched if Granite activated, standard otherwise)
			vdrs, err := network.GetCanonicalValidators(ctx, subnetID, false, destinationBlockchainID)
			if err != nil {
				logger.Error(
					"Failed to retrieve validators for destination",
					zap.Stringer("subnetID", subnetID),
					zap.Stringer("destinationBlockchainID", destinationBlockchainID),
					zap.Error(err),
				)
				return err
			}

			// Log details of connected validators for this destination
			logger.Debug("Connected validators for destination",
				zap.Stringer("destinationBlockchainID", destinationBlockchainID),
				zap.Int("numConnectedPeers", vdrs.ConnectedNodes.Len()),
				zap.Uint64("connectedWeight", vdrs.ConnectedWeight),
				zap.Uint64("totalValidatorWeight", vdrs.ValidatorSet.TotalWeight),
			)

			// Check if we have sufficient stake for this destination's requirements
			if !utils.CheckStakeWeightExceedsThreshold(
				big.NewInt(0).SetUint64(vdrs.ConnectedWeight),
				vdrs.ValidatorSet.TotalWeight,
				warpConfig.QuorumNumerator,
			) {
				logger.Warn(
					"Failed to connect to sufficient stake for destination, retrying...",
					zap.Stringer("subnetID", subnetID),
					zap.Stringer("destinationBlockchainID", destinationBlockchainID),
					zap.Uint64("quorumNumerator", warpConfig.QuorumNumerator),
					zap.Uint64("connectedWeight", vdrs.ConnectedWeight),
					zap.Uint64("totalValidatorWeight", vdrs.ValidatorSet.TotalWeight),
					zap.Int("numConnectedPeers", vdrs.ConnectedNodes.Len()),
				)
				return fmt.Errorf("failed to connect to sufficient stake for destination %s", destinationBlockchainID)
			}

			logger.Info(
				"Connected to sufficient stake for destination",
				zap.Stringer("subnetID", subnetID),
				zap.Stringer("destinationBlockchainID", destinationBlockchainID),
				zap.Uint64("quorumNumerator", warpConfig.QuorumNumerator),
				zap.Uint64("connectedWeight", vdrs.ConnectedWeight),
				zap.Uint64("totalValidatorWeight", vdrs.ValidatorSet.TotalWeight),
				zap.Int("numConnectedPeers", vdrs.ConnectedNodes.Len()),
			)
		}

		logger.Info(
			"Connected to sufficient stake for all destinations",
			zap.Stringer("subnetID", subnetID),
		)
		return nil
	}

	ticker := time.Tick(retryPeriodSeconds * time.Second)
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("failed to connect to sufficient stake: %w", ctx.Err())
		case <-ticker:
			if err := checkConns(); err == nil {
				return nil
			}
		}
	}
}
