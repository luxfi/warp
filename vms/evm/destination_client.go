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
	"github.com/ava-labs/avalanchego/utils/set"
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
	client ethclient.Client

	// Protects access to [keys], [keysInUse], and [nextKeyIndex]
	keySelectionCond *sync.Cond
	keys             []accountSigner
	// Provides non-blocking mutual exclusion for elements in [keys]
	keysInUse    map[int]bool
	nextKeyIndex int

	destinationBlockchainID ids.ID
	evmChainID              *big.Int
	blockGasLimit           uint64
	maxBaseFee              *big.Int
	maxPriorityFeePerGas    *big.Int
	logger                  logging.Logger
	txInclusionTimeout      time.Duration
}

type accountSigner struct {
	signer        signer.Signer
	currentNonce  uint64
	numPendingTxs int
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

	signers, err := signer.NewSigners(destinationBlockchain)
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

	var (
		pendingNonce, currentNonce uint64
		accountSigners             = make([]accountSigner, len(signers))
	)

	// Block until all pending txs are accepted
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for i, signer := range signers {
		for {
			// TODO: Iterate over all signers
			pendingNonce, err = client.NonceAt(context.Background(), signer.Address(), big.NewInt(int64(rpc.PendingBlockNumber)))
			if err != nil {
				logger.Error(
					"Failed to get pending nonce",
					zap.Error(err),
				)
				return nil, err
			}

			currentNonce, err = client.NonceAt(context.Background(), signer.Address(), nil)
			if err != nil {
				logger.Error(
					"Failed to get current nonce",
					zap.Error(err),
				)
				return nil, err
			}
			if pendingNonce == currentNonce {
				accountSigners[i] = accountSigner{
					signer:        signer,
					currentNonce:  currentNonce,
					numPendingTxs: 0,
				}
				break
			}
			logger.Info(
				"Waiting for pending txs to be accepted",
				zap.Uint64("pendingNonce", pendingNonce),
				zap.Uint64("currentNonce", currentNonce),
				zap.Stringer("address", signers[0].Address()),
			)
			<-ticker.C
		}
	}

	logger.Info(
		"Initialized destination client",
		zap.String("evmChainID", evmChainID.String()),
		zap.Uint64("nonce", pendingNonce),
	)

	return &destinationClient{
		client:                  client,
		keySelectionCond:        sync.NewCond(&sync.Mutex{}),
		keys:                    accountSigners,
		keysInUse:               make(map[int]bool),
		nextKeyIndex:            0,
		destinationBlockchainID: destinationID,
		evmChainID:              evmChainID,
		logger:                  logger,
		blockGasLimit:           destinationBlockchain.BlockGasLimit,
		maxBaseFee:              new(big.Int).SetUint64(destinationBlockchain.MaxBaseFee),
		maxPriorityFeePerGas:    new(big.Int).SetUint64(destinationBlockchain.MaxPriorityFeePerGas),
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
	deliverers set.Set[common.Address],
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

	signedTx, signerIdx, err := c.issueTransaction(
		deliverers,
		to,
		gasLimit,
		gasFeeCap,
		gasTipCap,
		callData,
		signedMessage,
	)
	if err != nil {
		c.logger.Error(
			"Failed to issue transaction",
			zap.Stringer("messageID", signedMessage.ID()),
			zap.Error(err),
		)
		return nil, err
	}

	receipt, err := c.waitForReceipt(signedTx.Hash(), signerIdx)
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
	)

	return receipt, nil
}

// Blocks until a key is available to use for signing.
func (c *destinationClient) acquireKey(deliverers set.Set[common.Address]) int {
	c.keySelectionCond.L.Lock()
	defer c.keySelectionCond.L.Unlock()

	// Round-robin through the keys until we find one that is
	// 1) not in use AND
	// 2) has less than poolTxsPerAccount pending txs AND
	// 3) is in the deliverers set (if deliverers is not empty)
	for {
		n := len(c.keys)
		for i := 0; i < n; i++ {
			idx := (c.nextKeyIndex + i) % n
			if (deliverers.Len() == 0 || deliverers.Contains(c.keys[idx].signer.Address())) &&
				!c.keysInUse[idx] &&
				c.keys[idx].numPendingTxs < poolTxsPerAccount {
				c.keysInUse[idx] = true
				c.nextKeyIndex = (idx + 1) % n
				return idx
			}
		}
		// No keys available, wait
		c.keySelectionCond.Wait()
	}
}

func (c *destinationClient) releaseKey(keyIndex int) {
	c.keySelectionCond.L.Lock()
	defer c.keySelectionCond.L.Unlock()

	c.keysInUse[keyIndex] = false
	c.keySelectionCond.Signal()
}

func (c *destinationClient) issueTransaction(
	deliverers set.Set[common.Address],
	to common.Address,
	gasLimit uint64,
	gasFeeCap *big.Int,
	gasTipCap *big.Int,
	callData []byte,
	signedMessage *avalancheWarp.Message,
) (*types.Transaction, int, error) {
	idx := c.acquireKey(deliverers)
	defer c.releaseKey(idx)

	// Construct the actual transaction to broadcast on the destination chain
	tx := predicateutils.NewPredicateTx(
		c.evmChainID,
		c.keys[idx].currentNonce,
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
	signedTx, err := c.keys[idx].signer.SignTx(tx, c.evmChainID)
	if err != nil {
		c.logger.Error(
			"Failed to sign transaction",
			zap.Error(err),
		)
		return nil, 0, err
	}

	sendTxCtx, sendTxCtxCancel := context.WithTimeout(context.Background(), utils.DefaultRPCTimeout)
	defer sendTxCtxCancel()

	c.logger.Info(
		"Sending transaction",
		zap.String("txID", signedTx.Hash().String()),
		zap.Uint64("nonce", c.keys[idx].currentNonce),
	)

	if err := c.client.SendTransaction(sendTxCtx, signedTx); err != nil {
		c.logger.Error(
			"Failed to send transaction",
			zap.Error(err),
		)
		return nil, 0, err
	}
	c.logger.Info(
		"Sent transaction",
		zap.String("txID", signedTx.Hash().String()),
		zap.Uint64("nonce", c.keys[idx].currentNonce),
	)

	c.keySelectionCond.L.Lock()
	defer c.keySelectionCond.L.Unlock()
	c.keys[idx].currentNonce++
	c.keys[idx].numPendingTxs++

	return signedTx, idx, nil
}

func (c *destinationClient) waitForReceipt(
	txHash common.Hash,
	signerIdx int,
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

	c.keySelectionCond.L.Lock()
	defer c.keySelectionCond.L.Unlock()
	c.keys[signerIdx].numPendingTxs--
	// Signal here, since a key may be waiting for a mempool slot to free up
	c.keySelectionCond.Signal()

	return receipt, nil
}

func (c *destinationClient) Client() interface{} {
	return c.client
}

func (c *destinationClient) SenderAddresses() []common.Address {
	c.keySelectionCond.L.Lock()
	defer c.keySelectionCond.L.Unlock()

	addresses := make([]common.Address, len(c.keys))
	for i, signer := range c.keys {
		addresses[i] = signer.signer.Address()
	}
	return addresses
}

func (c *destinationClient) DestinationBlockchainID() ids.ID {
	return c.destinationBlockchainID
}

func (c *destinationClient) BlockGasLimit() uint64 {
	return c.blockGasLimit
}
