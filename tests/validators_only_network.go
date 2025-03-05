// Copyright (C) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package tests

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ava-labs/avalanchego/config"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/tests/fixture/tmpnet"
	"github.com/ava-labs/avalanchego/utils/logging"
	"github.com/ava-labs/avalanchego/utils/set"
	avalancheWarp "github.com/ava-labs/avalanchego/vms/platformvm/warp"
	"github.com/ava-labs/icm-contracts/tests/interfaces"
	"github.com/ava-labs/icm-contracts/tests/network"
	"github.com/ava-labs/icm-contracts/tests/utils"
	"github.com/ava-labs/icm-services/signature-aggregator/api"
	testUtils "github.com/ava-labs/icm-services/tests/utils"
	"github.com/ethereum/go-ethereum/log"
	. "github.com/onsi/gomega"
)

func ValidatorsOnlyNetwork(network *network.LocalNetwork, teleporter utils.TeleporterTestInfo) {
	// Begin Setup step
	ctx := context.Background()

	l1AInfo := network.GetPrimaryNetworkInfo()
	_, l1BInfo := network.GetTwoL1s()
	fundedAddress, fundedKey := network.GetFundedAccountInfo()

	relayerNodeID := ids.GenerateTestNodeID()
	relayerNodeIDSet := set.NewSet[ids.NodeID](1)
	relayerNodeIDSet.Add(relayerNodeID)

	// We have to send the message first since we won't be able to listen for receipts once the network is private.

	log.Info("Sending teleporter message from B -> A")
	receipt, _, _ := testUtils.SendBasicTeleporterMessage(
		ctx,
		teleporter,
		l1BInfo,
		l1AInfo,
		fundedKey,
		fundedAddress,
	)
	warpMessage := getWarpMessageFromLog(ctx, receipt, l1BInfo)

	// Restart l1B and make it private

	l1BNodes := set.NewSet[ids.NodeID](1)

	// Make l1BInfo a validator only network
	for _, subnet := range network.Subnets {
		if subnet.SubnetID == l1BInfo.SubnetID {
			subnet.Config = make(map[string]interface{})
			subnet.Config["validatorOnly"] = true
			subnet.Config["allowedNodes"] = relayerNodeIDSet
			err := subnet.Write(network.GetSubnetDir(), network.GetChainConfigDir())
			Expect(err).Should(BeNil())
			l1BNodes.Add(subnet.ValidatorIDs...)
		}
	}
	// Restart l1B nodes
	for _, tmpnetNode := range network.Nodes {
		if l1BNodes.Contains(tmpnetNode.NodeID) {
			port := getTmpnetNodePort(tmpnetNode)
			tmpnetNode.Flags[config.HTTPPortKey] = port
			// Restart the network to apply the new chain configs
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(120*time.Second))
			defer cancel()
			err := network.RestartNode(ctx, logging.NoLog{}, tmpnetNode)
			Expect(err).Should(BeNil())
		}
	}

	// Start the signature-aggregator
	signatureAggregatorConfig := testUtils.CreateDefaultSignatureAggregatorConfig(
		[]interfaces.L1TestInfo{l1AInfo, l1BInfo},
	)
	signatureAggregatorConfig.NodeID = relayerNodeID.String()

	signatureAggregatorConfigPath := testUtils.WriteSignatureAggregatorConfig(
		signatureAggregatorConfig,
		testUtils.DefaultSignatureAggregatorCfgFname,
	)
	log.Info("Starting the signature aggregator", "configPath", signatureAggregatorConfigPath)
	signatureAggregatorCancel, readyChan := testUtils.RunSignatureAggregatorExecutable(
		ctx,
		signatureAggregatorConfigPath,
		signatureAggregatorConfig,
	)
	defer signatureAggregatorCancel()

	// Wait for signature-aggregator to start up
	log.Info("Waiting for the signature-aggregator to start up")
	startupCtx, startupCancel := context.WithTimeout(ctx, 15*time.Second)
	defer startupCancel()
	testUtils.WaitForChannelClose(startupCtx, readyChan)

	// End setup step

	requestURL := fmt.Sprintf("http://localhost:%d%s", signatureAggregatorConfig.APIPort, api.APIPath)

	reqBody := api.AggregateSignatureRequest{
		Message: "0x" + hex.EncodeToString(warpMessage.Bytes()),
	}
	client := http.Client{
		Timeout: 20 * time.Second,
	}

	var sendRequestToAPI = func() {
		b, err := json.Marshal(reqBody)
		Expect(err).Should(BeNil())
		bodyReader := bytes.NewReader(b)

		req, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
		Expect(err).Should(BeNil())
		req.Header.Set("Content-Type", "application/json")

		res, err := client.Do(req)
		Expect(err).Should(BeNil())
		Expect(res.Status).Should(Equal("200 OK"))
		Expect(res.Header.Get("Content-Type")).Should(Equal("application/json"))

		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		Expect(err).Should(BeNil())

		var response api.AggregateSignatureResponse
		err = json.Unmarshal(body, &response)
		Expect(err).Should(BeNil())

		decodedMessage, err := hex.DecodeString(response.SignedMessage)
		Expect(err).Should(BeNil())

		signedMessage, err := avalancheWarp.ParseMessage(decodedMessage)
		Expect(err).Should(BeNil())
		Expect(signedMessage.ID()).Should(Equal(warpMessage.ID()))
	}

	sendRequestToAPI()
}

// TODO: once tmpnet supports static port option across restarts, remove this function
func getTmpnetNodePort(node *tmpnet.Node) string {
	hostPort := strings.TrimPrefix(node.URI, "http://")
	Expect(hostPort).ShouldNot(BeEmpty())
	_, port, err := net.SplitHostPort(hostPort)
	Expect(err).Should(BeNil())
	return port
}
