// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:generate mockgen -source=$GOFILE -destination=./mocks/mock_eth_client.go -package=mocks

package evm

import (
	"context"
	"math/big"
	"reflect"
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
	pendingTxRefreshInterval      = 2 * time.Second
	defaultBlockAcceptanceTimeout = 30 * time.Second
)

// Client interface wraps the ethclient.Client interface for mocking purposes.
type Client interface {
	ethclient.Client
}

// Implements DestinationClient
type destinationClient struct {
	client ethclient.Client

	messageChans    []chan MessageData
	signerAddresses []common.Address

	destinationBlockchainID ids.ID
	evmChainID              *big.Int
	blockGasLimit           uint64
	maxBaseFee              *big.Int
	maxPriorityFeePerGas    *big.Int
	logger                  logging.Logger
	txInclusionTimeout      time.Duration
}

type accountSigner struct {
	logger            logging.Logger
	signer            signer.Signer
	currentNonce      uint64
	messageChan       chan MessageData
	txQueue           chan struct{}
	destinationClient *destinationClient
}

type MessageData struct {
	to            common.Address
	gasLimit      uint64
	gasFeeCap     *big.Int
	gasTipCap     *big.Int
	callData      []byte
	signedMessage *avalancheWarp.Message
	resultChan    chan messageResult
}

type messageResult struct {
	receipt *types.Receipt
	err     error
}

func NewDestinationClient(
	logger logging.Logger,
	destinationBlockchain *config.DestinationBlockchain,
) (*destinationClient, error) {
	var destClient destinationClient

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
		messageChans               = make([]chan MessageData, len(signers))
		signerAddresses            = make([]common.Address, len(signers))
	)

	// Block until all pending txs are accepted
	ticker := time.NewTicker(pendingTxRefreshInterval)
	defer ticker.Stop()
	for i, signer := range signers {
		for {
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
				// Limit the number of transactions in the mempool for each account,
				// otherwise they may be dropped.
				txQueue := make(chan struct{}, poolTxsPerAccount)
				messageChan := make(chan MessageData, 0)
				messageChans[i] = messageChan
				accountSigners[i] = accountSigner{
					logger:            logger.With(zap.Stringer("address", signer.Address())),
					signer:            signer,
					currentNonce:      currentNonce,
					messageChan:       messageChan,
					txQueue:           txQueue,
					destinationClient: &destClient,
				}
				signerAddresses[i] = signer.Address()
				go accountSigners[i].processIncomingTransactions()
				logger.Debug(
					"Pending txs accepted",
					zap.Stringer("address", signer.Address()),
				)
				break
			}
			logger.Info(
				"Waiting for pending txs to be accepted",
				zap.Uint64("pendingNonce", pendingNonce),
				zap.Uint64("currentNonce", currentNonce),
				zap.Stringer("address", signer.Address()),
			)
			<-ticker.C
		}
	}

	logger.Info(
		"Initialized destination client",
		zap.String("evmChainID", evmChainID.String()),
		zap.Uint64("nonce", pendingNonce),
	)

	destClient = destinationClient{
		client:                  client,
		messageChans:            messageChans,
		signerAddresses:         signerAddresses,
		destinationBlockchainID: destinationID,
		evmChainID:              evmChainID,
		logger:                  logger,
		blockGasLimit:           destinationBlockchain.BlockGasLimit,
		maxBaseFee:              new(big.Int).SetUint64(destinationBlockchain.MaxBaseFee),
		maxPriorityFeePerGas:    new(big.Int).SetUint64(destinationBlockchain.MaxPriorityFeePerGas),
		txInclusionTimeout:      time.Duration(destinationBlockchain.TxInclusionTimeoutSeconds) * time.Second,
	}

	return &destClient, nil
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

	resultChan := make(chan messageResult)
	defer close(resultChan)

	messageData := MessageData{
		to:            to,
		gasLimit:      gasLimit,
		gasFeeCap:     gasFeeCap,
		gasTipCap:     gasTipCap,
		callData:      callData,
		signedMessage: signedMessage,
		resultChan:    resultChan,
	}

	var cases []reflect.SelectCase
	for i, signerAddress := range c.signerAddresses {
		if deliverers.Len() != 0 {
			if !deliverers.Contains(signerAddress) {
				continue
			}
		}
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectSend,
			Chan: reflect.ValueOf(c.messageChans[i]),
			Send: reflect.ValueOf(messageData),
		})
	}

	// Select an available, eligible signer and acquire a txQueue slot
	reflect.Select(cases)

	// Wait for the receipt to be returned
	result := <-resultChan
	if result.err != nil {
		c.logger.Error(
			"Failed to get transaction receipt",
			zap.Error(err),
		)
		return nil, err
	}
	c.logger.Debug(
		"Sent transaction",
	)

	return result.receipt, nil
}

func (s *accountSigner) processIncomingTransactions() {
	for {
		// We can only only get to listen to readyChan if there is an open pending tx slot
		s.txQueue <- struct{}{}
		s.logger.Debug("Waiting for incoming transaction")
		// TODO handle error
		s.issueTransaction(<-s.messageChan)
	}
}

func (s *accountSigner) issueTransaction(
	data MessageData,
) error {
	s.logger.Debug(
		"Processing transaction",
		zap.String("to", data.to.String()),
	)

	// Construct the actual transaction to broadcast on the destination chain
	tx := predicateutils.NewPredicateTx(
		s.destinationClient.evmChainID,
		s.currentNonce,
		&data.to,
		data.gasLimit,
		data.gasFeeCap,
		data.gasTipCap,
		big.NewInt(0),
		data.callData,
		types.AccessList{},
		warp.ContractAddress,
		data.signedMessage.Bytes(),
	)

	// Sign and send the transaction on the destination chain
	signedTx, err := s.signer.SignTx(tx, s.destinationClient.evmChainID)
	if err != nil {
		s.logger.Error(
			"Failed to sign transaction",
			zap.Error(err),
		)
		return err
	}

	sendTxCtx, sendTxCtxCancel := context.WithTimeout(context.Background(), utils.DefaultRPCTimeout)
	defer sendTxCtxCancel()

	s.logger.Info(
		"Sending transaction",
		zap.String("txID", signedTx.Hash().String()),
		zap.Uint64("nonce", s.currentNonce),
	)

	if err := s.destinationClient.client.SendTransaction(sendTxCtx, signedTx); err != nil {
		s.logger.Error(
			"Failed to send transaction",
			zap.Error(err),
		)
		return err
	}
	s.logger.Info(
		"Sent transaction",
		zap.String("txID", signedTx.Hash().String()),
		zap.Uint64("nonce", s.currentNonce),
	)

	s.currentNonce++

	go s.waitForReceipt(signedTx.Hash(), data.resultChan)

	return nil
}

func (s *accountSigner) waitForReceipt(
	txHash common.Hash,
	resultChan chan messageResult,
) {
	// Release the txQueue slot once this function returns
	defer func() { <-s.txQueue }()

	var receipt *types.Receipt
	operation := func() (err error) {
		callCtx, callCtxCancel := context.WithTimeout(context.Background(), utils.DefaultRPCTimeout)
		defer callCtxCancel()
		receipt, err = s.destinationClient.client.TransactionReceipt(callCtx, txHash)
		return err
	}
	err := utils.WithRetriesTimeout(s.logger, operation, s.destinationClient.txInclusionTimeout, "waitForReceipt")
	if err != nil {
		s.logger.Error(
			"Failed to get transaction receipt",
			zap.Error(err),
		)
		resultChan <- messageResult{
			receipt: nil,
			err:     err,
		}
		return
	}

	resultChan <- messageResult{
		receipt: receipt,
		err:     nil,
	}
}

func (c *destinationClient) Client() interface{} {
	return c.client
}

func (c *destinationClient) SenderAddresses() []common.Address {
	return c.signerAddresses
}

func (c *destinationClient) DestinationBlockchainID() ids.ID {
	return c.destinationBlockchainID
}

func (c *destinationClient) BlockGasLimit() uint64 {
	return c.blockGasLimit
}
