package changesets

import (
	"strconv"

	execcontract "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
)

func convertTopologyMonitoring(m *deployments.MonitoringConfig) shared.MonitoringInput {
	if m == nil {
		return shared.MonitoringInput{}
	}
	return shared.MonitoringInput{
		Enabled: m.Enabled,
		Type:    m.Type,
		Beholder: shared.BeholderInput{
			InsecureConnection:       m.Beholder.InsecureConnection,
			CACertFile:               m.Beholder.CACertFile,
			OtelExporterGRPCEndpoint: m.Beholder.OtelExporterGRPCEndpoint,
			OtelExporterHTTPEndpoint: m.Beholder.OtelExporterHTTPEndpoint,
			LogStreamingEnabled:      m.Beholder.LogStreamingEnabled,
			MetricReaderInterval:     m.Beholder.MetricReaderInterval,
			TraceSampleRatio:         m.Beholder.TraceSampleRatio,
			TraceBatchTimeout:        m.Beholder.TraceBatchTimeout,
		},
	}
}

func buildNOPModes(nops []deployments.NOPConfig) map[shared.NOPAlias]shared.NOPMode {
	nopModes := make(map[shared.NOPAlias]shared.NOPMode)
	for _, nop := range nops {
		mode := nop.GetMode()
		nopModes[shared.NOPAlias(nop.Alias)] = mode
	}
	return nopModes
}

func getAllNOPAliases(nops []deployments.NOPConfig) []shared.NOPAlias {
	aliases := make([]shared.NOPAlias, len(nops))
	for i, nop := range nops {
		aliases[i] = shared.NOPAlias(nop.Alias)
	}
	return aliases
}

func getCommitteeChainSelectors(committee deployments.CommitteeConfig) []uint64 {
	selectors := make([]uint64, 0, len(committee.ChainConfigs))
	for chainStr := range committee.ChainConfigs {
		if sel, err := strconv.ParseUint(chainStr, 10, 64); err == nil {
			selectors = append(selectors, sel)
		}
	}
	return selectors
}

func filterChains(input, allowed []uint64) []uint64 {
	allowedSet := make(map[uint64]bool, len(allowed))
	for _, c := range allowed {
		allowedSet[c] = true
	}

	filtered := make([]uint64, 0, len(input))
	for _, sel := range input {
		if allowedSet[sel] {
			filtered = append(filtered, sel)
		}
	}
	return filtered
}

func getExecutorDeployedChains(ds datastore.DataStore, qualifier string) []uint64 {
	if ds == nil {
		return nil
	}
	refs := ds.Addresses().Filter(
		datastore.AddressRefByQualifier(qualifier),
		datastore.AddressRefByType(datastore.ContractType(execcontract.ProxyType)),
	)
	seen := make(map[uint64]bool, len(refs))
	chains := make([]uint64, 0, len(refs))
	for _, ref := range refs {
		if !seen[ref.ChainSelector] {
			seen[ref.ChainSelector] = true
			chains = append(chains, ref.ChainSelector)
		}
	}
	return chains
}
