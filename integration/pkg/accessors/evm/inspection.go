package evm

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func inspectEVMConfig(selector protocol.ChainSelector, info Info) (chainaccess.ChainInspection, error) {
	effective, err := evmconfig.EffectiveChainFromInfo(info)
	if err != nil {
		return chainaccess.ChainInspection{}, fmt.Errorf("failed to project effective EVM config: %w", err)
	}
	inspection := chainaccess.ChainInspection{
		Selector: selector, Family: chainsel.FamilyEVM, ChainID: effective.ChainID,
		Endpoints: inspectEVMEndpoints(info.Nodes, effective.Nodes),
		Attributes: []chainaccess.ChainAttribute{
			{Name: "finality.depth", Value: strconv.FormatUint(uint64(effective.FinalityDepth), 10), Source: "effective"},
			{Name: "finality.tag_enabled", Value: strconv.FormatBool(effective.FinalityTagEnabled), Source: "effective"},
			{Name: "head_tracker.persistence", Value: strconv.FormatBool(effective.HeadTrackerPersistence), Source: "standalone_override"},
			{Name: "txm.block_time", Value: effective.TXMBlockTime, Source: effective.TXMBlockTimeSource},
		},
	}
	if effective.NewHeadsPollInterval != "" {
		inspection.Attributes = append(inspection.Attributes, chainaccess.ChainAttribute{
			Name: "node_pool.new_heads_poll_interval", Value: effective.NewHeadsPollInterval, Source: "effective",
		})
	}
	return inspection, nil
}

func inspectEVMEndpoints(infos []Node, effective []evmconfig.EffectiveNode) []chainaccess.ChainEndpoint {
	endpoints := make([]chainaccess.ChainEndpoint, 0, len(effective))
	for i, node := range effective {
		endpoint := chainaccess.ChainEndpoint{Name: node.Name, HasWebSocket: node.HasWebSocket, Order: node.Order}
		if i < len(infos) {
			endpoint.HTTPURL = sanitizeRPCURL(infos[i].HTTPUrl)
			endpoint.WSURL = sanitizeRPCURL(infos[i].WSUrl)
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

func sanitizeRPCURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "redacted"
	}
	return parsed.Scheme + "://" + parsed.Host
}

// InspectChain returns the runtime's sanitized effective EVM configuration snapshot.
func (c *standaloneChain) InspectChain(context.Context) (chainaccess.ChainInspection, error) {
	if c == nil {
		return chainaccess.ChainInspection{}, errors.New("EVM chain runtime is not available")
	}
	inspection := c.inspection
	inspection.Endpoints = append([]chainaccess.ChainEndpoint(nil), c.inspection.Endpoints...)
	inspection.Attributes = append([]chainaccess.ChainAttribute(nil), c.inspection.Attributes...)
	inspection.Diagnostics = append([]string(nil), c.inspection.Diagnostics...)
	return inspection, nil
}

// InspectChain merges the runtime's effective configuration with accessor roles and diagnostics.
func (a *accessor) InspectChain(ctx context.Context) (chainaccess.ChainInspection, error) {
	if a == nil || a.runtime == nil {
		return chainaccess.ChainInspection{}, errors.New("EVM chain runtime is not available")
	}
	inspection := chainaccess.ChainInspection{Selector: a.chainSelector, Family: chainsel.FamilyEVM}
	var err error
	if inspector, ok := a.runtime.(chainaccess.ChainInspector); ok {
		inspection, err = inspector.InspectChain(ctx)
		if err != nil {
			return inspection, err
		}
	} else {
		inspection.Diagnostics = append(inspection.Diagnostics, "effective EVM configuration is unavailable")
	}
	if a.sourceParams != nil {
		inspection.Roles = append(inspection.Roles, "source")
		inspection.Attributes = append(inspection.Attributes, chainaccess.ChainAttribute{
			Name: "contracts.on_ramp", Value: a.sourceParams.OnRampAddress.Hex(), Source: "operator",
		})
	}
	if a.offRampAddr != (common.Address{}) {
		inspection.Roles = append(inspection.Roles, "destination")
		inspection.Attributes = append(inspection.Attributes, chainaccess.ChainAttribute{
			Name: "contracts.off_ramp", Value: a.offRampAddr.Hex(), Source: "operator",
		})
	}
	if a.feeQuoterReader != nil || a.feeQuoterWriter != nil {
		inspection.Roles = append(inspection.Roles, "pricer")
	}
	keySource := "operator"
	if a.keyName == contracttransmitter.DefaultKeyName {
		keySource = "family_default"
	}
	inspection.Attributes = append(inspection.Attributes,
		chainaccess.ChainAttribute{Name: "source_reader.header_batch_size", Value: strconv.Itoa(a.runtime.SourceReaderHeaderFetchBatchSize()), Source: "effective"},
		chainaccess.ChainAttribute{Name: "source_reader.log_poller", Value: strconv.FormatBool(a.logPollerEnabled), Source: "operator"},
		chainaccess.ChainAttribute{Name: "transmitter.key_name", Value: a.keyName, Source: keySource},
		chainaccess.ChainAttribute{Name: "native_token.decimals", Value: strconv.Itoa(int(a.nativeDecimals)), Source: "effective"},
	)
	if degraded := a.Degraded(); degraded != nil {
		inspection.Diagnostics = append(inspection.Diagnostics, degraded.Error())
	}
	return inspection, nil
}
