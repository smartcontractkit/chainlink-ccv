package changesets

import (
	"testing"

	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-protos/job-distributor/v1/shared/ptypes"
)

func addCCVTestEVMChainSupport(t *testing.T, env deployment.Environment, selector uint64) {
	t.Helper()
	chainID, err := chainsel.GetChainIDFromSelector(selector)
	require.NoError(t, err)
	client := env.Offchain.(*stubOffchainClient)
	for nodeID := range client.nodes {
		client.chainConfigs = append(client.chainConfigs, &nodev1.ChainConfig{
			NodeId: nodeID,
			Chain: &nodev1.Chain{
				Id:   chainID,
				Type: nodev1.ChainType_CHAIN_TYPE_EVM,
			},
			Ocr2Config: &nodev1.OCR2Config{Enabled: true},
		})
	}
}

func ccvTestNode(id, name, environment, target string) *nodev1.Node {
	product := "ccv"
	pluginType := "plugin"
	labels := []*ptypes.Label{
		{Key: "product", Value: &product},
		{Key: "environment", Value: &environment},
		{Key: "type", Value: &pluginType},
	}
	if target != "" {
		labels = append(labels, &ptypes.Label{Key: "target", Value: &target})
	}
	return &nodev1.Node{Id: id, Name: name, PublicKey: "csa-" + id, Labels: labels}
}
