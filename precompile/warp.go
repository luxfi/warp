// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package precompile

import (
	"errors"
	"fmt"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/vm"
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
)

// WarpPrecompile is the interface for the warp precompile contract
type WarpPrecompile interface {
	GetVerifiedWarpMessage(
		index uint32, evm *vm.EVM, caller common.Address, value *uint256.Int, readOnly bool,
	) ([]byte, error)
	SendWarpMessage(
		payload []byte, evm *vm.EVM, caller common.Address, value *uint256.Int, readOnly bool,
	) ([]byte, error)
	GetBlockchainID(
		evm *vm.EVM, caller common.Address, value *uint256.Int, readOnly bool,
	) ([]byte, error)
}

// WarpConfig is the configuration for the warp precompile
type WarpConfig struct {
	NetworkID         uint32
	SourceChainID     ids.ID
	BlockchainID      ids.ID
	QuorumNumerator   uint64
	QuorumDenominator uint64
}

// DefaultWarpConfig returns the default warp configuration
func DefaultWarpConfig(networkID uint32, chainID ids.ID) *WarpConfig {
	return &WarpConfig{
		NetworkID:         networkID,
		SourceChainID:     chainID,
		BlockchainID:      chainID,
		QuorumNumerator:   67,
		QuorumDenominator: 100,
	}
}

// WarpBackend is the backend interface for warp operations
type WarpBackend interface {
	GetMessage(index uint32) (*warp.Message, error)
	AddMessage(unsignedMessage *warp.UnsignedMessage) error
	GetValidatorState() warp.ValidatorState
}

// WarpModule implements the warp precompile functionality
type WarpModule struct {
	config  *WarpConfig
	backend WarpBackend
}

// NewWarpModule creates a new warp module
func NewWarpModule(config *WarpConfig, backend WarpBackend) *WarpModule {
	return &WarpModule{
		config:  config,
		backend: backend,
	}
}

// GetVerifiedWarpMessage retrieves a verified warp message
func (w *WarpModule) GetVerifiedWarpMessage(
	index uint32,
	evm *vm.EVM,
	caller common.Address,
	value *uint256.Int,
	readOnly bool,
) ([]byte, error) {
	msg, err := w.backend.GetMessage(index)
	if err != nil {
		return nil, fmt.Errorf("failed to get message: %w", err)
	}

	err = warp.VerifyMessage(
		msg,
		w.config.NetworkID,
		w.backend.GetValidatorState(),
		w.config.QuorumNumerator,
		w.config.QuorumDenominator,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to verify message: %w", err)
	}

	return msg.Bytes(), nil
}

// SendWarpMessage sends a warp message
func (w *WarpModule) SendWarpMessage(
	payload []byte,
	evm *vm.EVM,
	caller common.Address,
	value *uint256.Int,
	readOnly bool,
) ([]byte, error) {
	if readOnly {
		return nil, errors.New("cannot send warp message in read-only mode")
	}

	unsignedMsg, err := warp.NewUnsignedMessage(w.config.NetworkID, w.config.SourceChainID, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create unsigned message: %w", err)
	}

	if err := w.backend.AddMessage(unsignedMsg); err != nil {
		return nil, fmt.Errorf("failed to add message: %w", err)
	}

	msgID := unsignedMsg.ID()
	return msgID[:], nil
}

// GetBlockchainID retrieves the blockchain ID
func (w *WarpModule) GetBlockchainID(
	evm *vm.EVM,
	caller common.Address,
	value *uint256.Int,
	readOnly bool,
) ([]byte, error) {
	return w.config.BlockchainID[:], nil
}

// Gas costs for warp operations
const (
	GetVerifiedWarpMessageGas = 200_000
	SendWarpMessageGas        = 100_000
	GetBlockchainIDGas        = 10_000
)

// WarpPrecompileContract is the precompile contract address
var WarpPrecompileContract = common.HexToAddress("0x0200000000000000000000000000000000000005")

// WarpABI is the ABI for the warp precompile
const WarpABI = `[
	{
		"inputs": [{"internalType": "uint32", "name": "index", "type": "uint32"}],
		"name": "getVerifiedWarpMessage",
		"outputs": [
			{
				"components": [
					{"internalType": "bytes32", "name": "sourceChainID", "type": "bytes32"},
					{"internalType": "address", "name": "originSenderAddress", "type": "address"},
					{"internalType": "bytes", "name": "payload", "type": "bytes"}
				],
				"internalType": "struct WarpMessage", "name": "message", "type": "tuple"
			},
			{"internalType": "bool", "name": "valid", "type": "bool"}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [{"internalType": "bytes", "name": "payload", "type": "bytes"}],
		"name": "sendWarpMessage",
		"outputs": [{"internalType": "bytes32", "name": "messageID", "type": "bytes32"}],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getBlockchainID",
		"outputs": [{"internalType": "bytes32", "name": "blockchainID", "type": "bytes32"}],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "internalType": "address", "name": "sender", "type": "address"},
			{"indexed": true, "internalType": "bytes32", "name": "messageID", "type": "bytes32"},
			{"indexed": false, "internalType": "bytes", "name": "message", "type": "bytes"}
		],
		"name": "SendWarpMessage",
		"type": "event"
	}
]`
