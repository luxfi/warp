// Copyright (C) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package peers

import (
	"context"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/rpc"
	"github.com/ava-labs/avalanchego/vms/proposervm"
	"github.com/ava-labs/avalanchego/vms/proposervm/block"
	"github.com/ava-labs/icm-services/config"
	"github.com/ava-labs/icm-services/peers/utils"
)

//go:generate go run go.uber.org/mock/mockgen -source=$GOFILE -destination=./mocks/mock_p_chain_client.go -package=mocks

// PChainAPI is a wrapper around the info.Client,
// and provides additional options for the API
// passed in the config.
type ProposerVMAPI struct {
	client  *proposervm.JSONRPCClient
	options []rpc.Option
}

func NewProposerVMAPI(apiConfig *config.APIConfig, blockchainID ids.ID) *ProposerVMAPI {
	client := proposervm.NewJSONRPCClient(apiConfig.BaseURL, blockchainID.String())
	options := utils.InitializeOptions(apiConfig)
	return &ProposerVMAPI{
		client:  client,
		options: options,
	}
}

func (p *ProposerVMAPI) GetCurrentEpoch(ctx context.Context) (block.Epoch, error) {
	return p.client.GetCurrentEpoch(ctx, p.options...)
}