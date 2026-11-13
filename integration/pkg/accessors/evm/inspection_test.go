package evm

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestInspectEVMConfigSanitizesEndpointsAndProjectsDefaults(t *testing.T) {
	inspection, err := inspectEVMConfig(protocol.ChainSelector(1), Info{
		ChainID: "1", FinalityDepth: 22, TXMBlockTime: 7 * time.Second,
		Nodes: []Node{{
			Name: "primary", HTTPUrl: "https://user:pass@rpc.example.com/path?api-key=secret",
			WSUrl: "wss://user:pass@ws.example.com/socket?token=secret", Order: 1,
		}},
	})
	require.NoError(t, err)
	require.Equal(t, "evm", inspection.Family)
	require.Equal(t, "1", inspection.ChainID)
	require.Len(t, inspection.Endpoints, 1)
	require.Equal(t, "https://rpc.example.com", inspection.Endpoints[0].HTTPURL)
	require.Equal(t, "wss://ws.example.com", inspection.Endpoints[0].WSURL)
	require.True(t, inspection.Endpoints[0].HasWebSocket)
	require.NotContains(t, fmt.Sprint(inspection), "secret")
	require.NotContains(t, fmt.Sprint(inspection), "user:pass")

	attributes := make(map[string]chainaccess.ChainAttribute)
	for _, attribute := range inspection.Attributes {
		attributes[attribute.Name] = attribute
	}
	require.Equal(t, "22", attributes["finality.depth"].Value)
	require.Equal(t, "false", attributes["head_tracker.persistence"].Value)
	require.Equal(t, "7s", attributes["txm.block_time"].Value)
	require.Equal(t, "operator", attributes["txm.block_time"].Source)
}

func TestSanitizeRPCURL(t *testing.T) {
	require.Equal(t, "", sanitizeRPCURL(""))
	require.Equal(t, "redacted", sanitizeRPCURL("not-a-url"))
	require.Equal(t, "https://rpc.example.com", sanitizeRPCURL("https://rpc.example.com/v2?token=secret"))
}

func TestAccessorInspectChainMergesRuntimeAndServiceDetails(t *testing.T) {
	base, err := inspectEVMConfig(protocol.ChainSelector(1), Info{
		ChainID: "1", Nodes: []Node{{Name: "primary", HTTPUrl: "http://localhost:8545"}},
	})
	require.NoError(t, err)
	runtime := &standaloneChain{inspection: base, sourceReaderHeaderFetchBatchSize: 25}
	acc := newAccessor(
		logger.Test(t), protocol.ChainSelector(1), runtime, common.HexToAddress("0x1234"), "custom-key",
		nil, nil, nil, nil, nil, nil,
	).(*accessor)
	acc.sourceParams = &SourceReaderParams{OnRampAddress: common.HexToAddress("0xabcd")}
	acc.logPollerEnabled = true

	inspection, err := acc.InspectChain(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"source", "destination"}, inspection.Roles)
	require.Equal(t, "1", inspection.ChainID)
	require.Len(t, inspection.Endpoints, 1)
	attributes := make(map[string]chainaccess.ChainAttribute)
	for _, attribute := range inspection.Attributes {
		attributes[attribute.Name] = attribute
	}
	require.Equal(t, common.HexToAddress("0xabcd").Hex(), attributes["contracts.on_ramp"].Value)
	require.Equal(t, common.HexToAddress("0x1234").Hex(), attributes["contracts.off_ramp"].Value)
	require.Equal(t, "true", attributes["source_reader.log_poller"].Value)
	require.Equal(t, "25", attributes["source_reader.header_batch_size"].Value)
	require.Equal(t, "custom-key", attributes["transmitter.key_name"].Value)
	require.Equal(t, "operator", attributes["transmitter.key_name"].Source)
}
