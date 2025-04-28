// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:generate mockgen -source=$GOFILE -destination=./mocks/mock_eth_client.go -package=mocks

package evm

import (
	"context"
	"math/big"
	"sync"
	"time"

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
	"github.com/ava-labs/subnet-evm/rpc"
	"github.com/ethereum/go-ethereum/common"
	"go.uber.org/zap"
)

const (
	// If the max base fee is not explicitly set, use 3x the current base fee estimate
	defaultBaseFeeFactor          = 3
	poolTxsPerAccount             = 16
	defaultBlockAcceptanceTimeout = 30 * time.Second
)

// Client interface wraps the ethclient.Client interface for mocking purposes.
type Client interface {
	ethclient.Client
}

// Implements DestinationClient
type destinationClient struct {
	client                  ethclient.Client
	nonceLock               *sync.Mutex
	destinationBlockchainID ids.ID
	signer                  signer.Signer
	evmChainID              *big.Int
	currentNonce            uint64
	blockGasLimit           uint64
	maxBaseFee              *big.Int
	maxPriorityFeePerGas    *big.Int
	logger                  logging.Logger
	poolTxsSemaphore        chan struct{}
	txInclusionTimeout      time.Duration
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

	logger = logger.With(zap.String("blockchainID", destinationBlockchain.BlockchainID))

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

	evmChainID, err := client.ChainID(context.Background())
	if err != nil {
		logger.Error(
			"Failed to get chain ID from destination chain endpoint",
			zap.Error(err),
		)
		return nil, err
	}

	// Create a semaphore to limit the number of transactions in the pool to poolTxsPerAccount.
	// Once in steady state, the number of pending txs should never exceed poolTxsPerAccount,
	// but on startup, we may have more pending txs than the pool size. Therefore, on startup,
	// we grab at most poolTxsPerAccount semaphores, and then release them once the pending txs are accepted.
	poolTxsSemaphore := make(chan struct{}, poolTxsPerAccount)

	// Construct txs using the pending nonce to account for restarts due to long-pending txs in the mempool
	pendingNonce, err := client.NonceAt(context.Background(), sgnr.Address(), big.NewInt(int64(rpc.PendingBlockNumber)))
	if err != nil {
		logger.Error(
			"Failed to get pending nonce",
			zap.Error(err),
		)
		return nil, err
	}

	// Calculate the number of pending transactions in the mempool using the current nonce.
	// This is used to acquire the correct number of semaphores on startup.
	currentNonce, err := client.NonceAt(context.Background(), sgnr.Address(), nil)
	if err != nil {
		logger.Error(
			"Failed to get current nonce",
			zap.Error(err),
		)
		return nil, err
	}

	numPendingTxs := max(currentNonce-pendingNonce, 0)
	if numPendingTxs > 0 {
		// Defensively account for the case where the number of pending txs is greater than poolTxsPerAccount
		overrunPendingTxs := uint64(max(int(numPendingTxs)-int(poolTxsPerAccount), 0))

		// Grab at most poolTxsPerAccount semaphores
		logger.Info(
			"Handling pending transactions on startup",
			zap.Uint64("numPendingTxs", numPendingTxs),
			zap.Uint64("overrunPendingTxs", overrunPendingTxs),
		)
		for i := uint64(0); i < numPendingTxs-overrunPendingTxs; i++ {
			poolTxsSemaphore <- struct{}{}
		}

		// Asynchronously release the numPendingTxs semaphores once the pending txs are accepted
		go func() {
			initialCurrentNonce := currentNonce
			for range time.Tick(2 * time.Second) {
				currentNonce, err := client.NonceAt(context.Background(), sgnr.Address(), nil)
				if err != nil {
					logger.Error(
						"Failed to get current nonce",
						zap.Error(err),
					)
					continue
				}
				processedPendingTxs := currentNonce - initialCurrentNonce
				logger.Info(
					"Processed pending transactions on startup",
					zap.Uint64("processedPendingTxs", processedPendingTxs),
				)
				for i := uint64(0); i < processedPendingTxs; i++ {
					// If there are more than poolTxsPerAccount pending txs, first decrement overrunPendingTxs
					// before releasing any semaphores to be acquired by message relayers
					if overrunPendingTxs > 0 {
						overrunPendingTxs--
						numPendingTxs--
						continue
					}
					<-poolTxsSemaphore
					numPendingTxs--
					if numPendingTxs == 0 {
						return
					}
				}
			}
		}()
	}

	logger.Info(
		"Initialized destination client",
		zap.String("evmChainID", evmChainID.String()),
		zap.Uint64("pendingNonce", pendingNonce),
		zap.Uint64("currentNonce", currentNonce),
	)

	return &destinationClient{
		client:                  client,
		nonceLock:               new(sync.Mutex),
		destinationBlockchainID: destinationID,
		signer:                  sgnr,
		evmChainID:              evmChainID,
		currentNonce:            pendingNonce,
		logger:                  logger,
		blockGasLimit:           destinationBlockchain.BlockGasLimit,
		maxBaseFee:              new(big.Int).SetUint64(destinationBlockchain.MaxBaseFee),
		maxPriorityFeePerGas:    new(big.Int).SetUint64(destinationBlockchain.MaxPriorityFeePerGas),
		poolTxsSemaphore:        poolTxsSemaphore,
		txInclusionTimeout:      time.Duration(destinationBlockchain.TxInclusionTimeoutSeconds) * time.Second,
	}, nil
}

// SendTx constructs, signs, and broadcast a transaction to deliver the given {signedMessage}
// to this chain with the provided {callData}. If the maximum base fee value is not configured, the
// maximum base is calculated as the current base fee multiplied by the default base fee factor.
// The maximum priority fee per gas is set the minimum of the suggested gas tip cap and the configured
// maximum priority fee per gas. The max fee per gas is set to the sum of the max base fee and the
// max priority fee per gas.
func (c *destinationClient) SendTx(
	signedMessage *avalancheWarp.Message,
	toAddress string,
	gasLimit uint64,
	callData []byte,
) (*types.Receipt, error) {
	// If the max base fee isn't explicitly set, then default to fetching the
	// current base fee estimate and multiply it by `BaseFeeFactor` to allow for
	// an increase prior to the transaction being included in a block.
	var maxBaseFee *big.Int
	if c.maxBaseFee.Cmp(big.NewInt(0)) > 0 {
		maxBaseFee = c.maxBaseFee
	} else {
		// Get the current base fee estimation for the chain.
		baseFeeCtx, baseFeeCtxCancel := context.WithTimeout(context.Background(), utils.DefaultRPCTimeout)
		defer baseFeeCtxCancel()
		baseFee, err := c.client.EstimateBaseFee(baseFeeCtx)
		if err != nil {
			c.logger.Error(
				"Failed to get base fee",
				zap.Error(err),
			)
			return nil, err
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
		return nil, err
	}
	if gasTipCap.Cmp(c.maxPriorityFeePerGas) > 0 {
		gasTipCap = c.maxPriorityFeePerGas
	}

	to := common.HexToAddress(toAddress)
	gasFeeCap := new(big.Int).Add(maxBaseFee, gasTipCap)

	// Synchronize nonce access so that we send transactions in nonce order.
	// Hold the lock until the transaction is sent, otherwise we may deadlock
	// on poolTxsSemaphore if there is a nonce gap in the mempool.
	c.nonceLock.Lock()

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
		return nil, err
	}

	sendTxCtx, sendTxCtxCancel := context.WithTimeout(context.Background(), utils.DefaultRPCTimeout)
	defer sendTxCtxCancel()

	c.logger.Info(
		"Sending transaction",
		zap.String("txID", signedTx.Hash().String()),
		zap.Uint64("nonce", c.currentNonce),
		zap.Int("poolTxSlotsAvailable", cap(c.poolTxsSemaphore)-len(c.poolTxsSemaphore)),
	)

	// Acquire a semaphore to limit the number of transactions in the mempool
	c.poolTxsSemaphore <- struct{}{}
	if err := c.client.SendTransaction(sendTxCtx, signedTx); err != nil {
		c.logger.Error(
			"Failed to send transaction",
			zap.Error(err),
		)
		return nil, err
	}
	c.logger.Info(
		"Sent transaction",
		zap.String("txID", signedTx.Hash().String()),
		zap.Uint64("nonce", c.currentNonce),
		zap.Int("poolTxSlotsAvailable", cap(c.poolTxsSemaphore)-len(c.poolTxsSemaphore)),
	)
	c.currentNonce++
	c.nonceLock.Unlock()

	receipt, err := c.waitForReceipt(signedTx.Hash())
	if err != nil {
		c.logger.Error(
			"Failed to get transaction receipt",
			zap.String("txID", signedTx.Hash().String()),
			zap.Error(err),
		)
		return nil, err
	}
	c.logger.Debug(
		"Sent transaction",
		zap.Int("poolTxSlotsAvailable", cap(c.poolTxsSemaphore)-len(c.poolTxsSemaphore)),
	)

	// Release the semaphore once the tx has been accepted
	<-c.poolTxsSemaphore

	return receipt, nil
}

func (c *destinationClient) waitForReceipt(
	txHash common.Hash,
) (*types.Receipt, error) {
	var receipt *types.Receipt
	operation := func() (err error) {
		callCtx, callCtxCancel := context.WithTimeout(context.Background(), utils.DefaultRPCTimeout)
		defer callCtxCancel()
		receipt, err = c.client.TransactionReceipt(callCtx, txHash)
		return err
	}
	err := utils.WithRetriesTimeout(c.logger, operation, c.txInclusionTimeout, "waitForReceipt")
	if err != nil {
		c.logger.Error(
			"Failed to get transaction receipt",
			zap.Error(err),
		)
		return nil, err
	}
	return receipt, nil
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
