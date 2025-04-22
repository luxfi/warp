// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:generate mockgen -source=$GOFILE -destination=./mocks/mock_eth_client.go -package=mocks

package evm

import (
	"context"
	"errors"
	"math/big"
	"sync"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/logging"
	avalancheWarp "github.com/ava-labs/avalanchego/vms/platformvm/warp"
	"github.com/ava-labs/icm-services/relayer/config"
	"github.com/ava-labs/icm-services/utils"
	"github.com/ava-labs/icm-services/vms/evm/signer"
	"github.com/ava-labs/subnet-evm/core/types"
	"github.com/ava-labs/subnet-evm/ethclient"
	"github.com/ava-labs/subnet-evm/precompile/contracts/warp"
	predicateutils "github.com/ava-labs/subnet-evm/predicate"
	"github.com/ethereum/go-ethereum/common"
	"go.uber.org/zap"
)

const (
	// If the max base fee is not explicitly set, use 3x the current
	// base fee estimate
	defaultBaseFeeFactor        = 3
	defaultMaxPriorityFeePerGas = 2500000000 // 2.5 gwei
)

var (
	errInvalidMaxBaseFee           = errors.New("invalid max base fee")
	errInvalidMaxPriorityFeePerGas = errors.New("invalid max priority fee per gas")
)

// Client interface wraps the ethclient.Client interface for mocking purposes.
type Client interface {
	ethclient.Client
}

// Implements DestinationClient
type destinationClient struct {
	client                  ethclient.Client
	lock                    *sync.Mutex
	destinationBlockchainID ids.ID
	signer                  signer.Signer
	evmChainID              *big.Int
	currentNonce            uint64
	blockGasLimit           uint64
	maxBaseFee              *big.Int
	maxPriorityFeePerGas    *big.Int
	logger                  logging.Logger
}

func NewDestinationClient(
	logger logging.Logger,
	destinationBlockchain *config.DestinationBlockchain,
) (*destinationClient, error) {
	destinationID, err := ids.FromString(destinationBlockchain.BlockchainID)
	if err != nil {
		logger.Error(
			"Could not decode destination chain ID from string",
			zap.Error(err),
		)
		return nil, err
	}

	sgnr, err := signer.NewSigner(destinationBlockchain)
	if err != nil {
		logger.Error(
			"Failed to create signer",
			zap.Error(err),
		)
		return nil, err
	}

	// Dial the destination RPC endpoint
	client, err := utils.NewEthClientWithConfig(
		context.Background(),
		destinationBlockchain.RPCEndpoint.BaseURL,
		destinationBlockchain.RPCEndpoint.HTTPHeaders,
		destinationBlockchain.RPCEndpoint.QueryParams,
	)
	if err != nil {
		logger.Error(
			"Failed to dial rpc endpoint",
			zap.Error(err),
		)
		return nil, err
	}

	nonce, err := client.NonceAt(context.Background(), sgnr.Address(), nil)
	if err != nil {
		logger.Error(
			"Failed to get nonce",
			zap.Error(err),
		)
		return nil, err
	}

	evmChainID, err := client.ChainID(context.Background())
	if err != nil {
		logger.Error(
			"Failed to get chain ID from destination chain endpoint",
			zap.Error(err),
		)
		return nil, err
	}

	logger.Info(
		"Initialized destination client",
		zap.String("blockchainID", destinationID.String()),
		zap.String("evmChainID", evmChainID.String()),
		zap.Uint64("nonce", nonce),
	)

	var maxBaseFee *big.Int
	if len(destinationBlockchain.MaxBaseFee) > 0 {
		var ok bool
		maxBaseFee, ok = new(big.Int).SetString(destinationBlockchain.MaxBaseFee, 10)
		if !ok || maxBaseFee.Cmp(big.NewInt(0)) <= 0 {
			logger.Error(
				"Invalid max base fee",
				zap.String("maxBaseFee", destinationBlockchain.MaxBaseFee),
			)
			return nil, errInvalidMaxBaseFee
		}
	}

	var maxPriorityFeePerGas *big.Int
	if len(destinationBlockchain.MaxPriorityFeePerGas) > 0 {
		var ok bool
		maxPriorityFeePerGas, ok = new(big.Int).SetString(destinationBlockchain.MaxPriorityFeePerGas, 10)
		if !ok || maxPriorityFeePerGas.Cmp(big.NewInt(0)) <= 0 {
			logger.Error(
				"Invalid max priority fee per gas",
				zap.String("maxPriorityFeePerGas", destinationBlockchain.MaxPriorityFeePerGas),
			)
			return nil, errInvalidMaxPriorityFeePerGas
		}
	} else {
		maxPriorityFeePerGas = big.NewInt(defaultMaxPriorityFeePerGas)
	}

	return &destinationClient{
		client:                  client,
		lock:                    new(sync.Mutex),
		destinationBlockchainID: destinationID,
		signer:                  sgnr,
		evmChainID:              evmChainID,
		currentNonce:            nonce,
		logger:                  logger,
		blockGasLimit:           destinationBlockchain.BlockGasLimit,
		maxBaseFee:              maxBaseFee,
		maxPriorityFeePerGas:    maxPriorityFeePerGas,
	}, nil
}

func (c *destinationClient) SendTx(
	signedMessage *avalancheWarp.Message,
	toAddress string,
	gasLimit uint64,
	callData []byte,
) (common.Hash, error) {
	// If the max base fee isn't explicitly set, then default to fetching the
	// current base fee estimate and multiply it by `BaseFeeFactor` to allow for
	// an increase prior to the transaction being included in a block.
	var maxBaseFee *big.Int
	if c.maxBaseFee != nil {
		maxBaseFee = c.maxBaseFee
	} else {
		// Get the current base fee estimation, which is based on the previous blocks gas usage.
		baseFeeCtx, baseFeeCtxCancel := context.WithTimeout(context.Background(), utils.DefaultRPCTimeout)
		defer baseFeeCtxCancel()
		baseFee, err := c.client.EstimateBaseFee(baseFeeCtx)
		if err != nil {
			c.logger.Error(
				"Failed to get base fee",
				zap.Error(err),
			)
			return common.Hash{}, err
		}
		maxBaseFee = new(big.Int).Mul(baseFee, big.NewInt(defaultBaseFeeFactor))
	}

	// Get the suggested gas tip cap of the network
	gasTipCapCtx, gasTipCapCtxCancel := context.WithTimeout(context.Background(), utils.DefaultRPCTimeout)
	defer gasTipCapCtxCancel()
	gasTipCap, err := c.client.SuggestGasTipCap(gasTipCapCtx)
	if err != nil {
		c.logger.Error(
			"Failed to get gas tip cap",
			zap.Error(err),
		)
		return common.Hash{}, err
	}
	if gasTipCap.Cmp(c.maxPriorityFeePerGas) > 0 {
		gasTipCap = c.maxPriorityFeePerGas
	}

	to := common.HexToAddress(toAddress)
	gasFeeCap := new(big.Int).Add(maxBaseFee, gasTipCap)

	// Synchronize nonce access so that we send transactions in nonce order.
	// Hold the lock until the transaction is sent to minimize the chance of
	// an out-of-order transaction being dropped from the mempool.
	c.lock.Lock()
	defer c.lock.Unlock()

	// Construct the actual transaction to broadcast on the destination chain
	tx := predicateutils.NewPredicateTx(
		c.evmChainID,
		c.currentNonce,
		&to,
		gasLimit,
		gasFeeCap,
		gasTipCap,
		big.NewInt(0),
		callData,
		types.AccessList{},
		warp.ContractAddress,
		signedMessage.Bytes(),
	)

	// Sign and send the transaction on the destination chain
	signedTx, err := c.signer.SignTx(tx, c.evmChainID)
	if err != nil {
		c.logger.Error(
			"Failed to sign transaction",
			zap.Error(err),
		)
		return common.Hash{}, err
	}

	sendTxCtx, sendTxCtxCancel := context.WithTimeout(context.Background(), utils.DefaultRPCTimeout)
	defer sendTxCtxCancel()
	if err := c.client.SendTransaction(sendTxCtx, signedTx); err != nil {
		c.logger.Error(
			"Failed to send transaction",
			zap.Error(err),
		)
		return common.Hash{}, err
	}
	c.logger.Info(
		"Sent transaction",
		zap.String("txID", signedTx.Hash().String()),
		zap.Uint64("nonce", c.currentNonce),
	)
	c.currentNonce++

	return signedTx.Hash(), nil
}

func (c *destinationClient) Client() interface{} {
	return c.client
}

func (c *destinationClient) SenderAddress() common.Address {
	return c.signer.Address()
}

func (c *destinationClient) DestinationBlockchainID() ids.ID {
	return c.destinationBlockchainID
}

func (c *destinationClient) BlockGasLimit() uint64 {
	return c.blockGasLimit
}
