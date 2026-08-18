package adapters

import (
	"fmt"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/rmn_proxy"
	execop "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/executor"
	offrampop "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
	dsutils "github.com/smartcontractkit/chainlink-ccip/deployment/utils/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	ccvdeploymentadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

type EVMCCVExecutorConfigAdapter struct{}

var _ ccvdeploymentadapters.ExecutorConfigAdapter = (*EVMCCVExecutorConfigAdapter)(nil)

func (a *EVMCCVExecutorConfigAdapter) GetDeployedChains(ds datastore.DataStore, qualifier string) []uint64 {
	if ds == nil {
		return nil
	}
	refs := ds.Addresses().Filter(
		datastore.AddressRefByQualifier(qualifier),
		datastore.AddressRefByType(datastore.ContractType(sequences.ExecutorProxyType)),
		datastore.AddressRefByVersion(execop.Version),
	)
	seen := make(map[uint64]struct{}, len(refs))
	chains := make([]uint64, 0, len(refs))
	for _, ref := range refs {
		if _, exists := seen[ref.ChainSelector]; exists {
			continue
		}
		family, err := chainsel.GetSelectorFamily(ref.ChainSelector)
		if err != nil || family != chainsel.FamilyEVM {
			continue
		}
		seen[ref.ChainSelector] = struct{}{}
		chains = append(chains, ref.ChainSelector)
	}
	return chains
}

// ResolveExecutorAddress resolves the EVM executor proxy address for the given chain and
// qualifier. On EVM the executor is fronted by a proxy contract (sequences.ExecutorProxyType);
// that datastore contract type is internal to this adapter and is not exposed by the ccv
// adapter API.
func (a *EVMCCVExecutorConfigAdapter) ResolveExecutorAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (string, error) {
	toAddress := func(ref datastore.AddressRef) (string, error) { return ref.Address, nil }
	executorAddr, err := dsutils.FindAndFormatRef(ds, datastore.AddressRef{
		Type:      datastore.ContractType(sequences.ExecutorProxyType),
		Qualifier: qualifier,
		Version:   execop.Version,
	}, chainSelector, toAddress)
	if err != nil {
		return "", fmt.Errorf("failed to get executor proxy address for chain %d: %w", chainSelector, err)
	}
	return executorAddr, nil
}

func (a *EVMCCVExecutorConfigAdapter) BuildChainConfig(ds datastore.DataStore, chainSelector uint64, qualifier string) (executor.ChainConfiguration, error) {
	toAddress := func(ref datastore.AddressRef) (string, error) { return ref.Address, nil }

	offRampAddr, err := dsutils.FindAndFormatRef(ds, datastore.AddressRef{
		Type:    datastore.ContractType(offrampop.ContractType),
		Version: offrampop.Version,
	}, chainSelector, toAddress)
	if err != nil {
		return executor.ChainConfiguration{}, fmt.Errorf("failed to get off ramp address for chain %d: %w", chainSelector, err)
	}

	executorAddr, err := a.ResolveExecutorAddress(ds, chainSelector, qualifier)
	if err != nil {
		return executor.ChainConfiguration{}, err
	}

	chainCfg := executor.ChainConfiguration{
		DestinationChainConfig: chainaccess.DestinationChainConfig{
			OffRampAddress: offRampAddr,
		},
		DefaultExecutorAddress: executorAddr,
	}

	// The RMN proxy is resolved best-effort: rmn_address is deprecated (nodes derive the RMN
	// Remote from the OffRamp's on-chain static config), so its absence from the datastore is
	// not an error. It is still emitted when present so generated specs keep working for node
	// binaries that predate the derivation cutover.
	rmnProxyRefs := ds.Addresses().Filter(
		datastore.AddressRefByChainSelector(chainSelector),
		datastore.AddressRefByType(datastore.ContractType(rmn_proxy.ContractType)),
		datastore.AddressRefByVersion(rmn_proxy.Version),
	)
	if len(rmnProxyRefs) > 1 {
		return executor.ChainConfiguration{}, fmt.Errorf("chain %d: expected at most 1 RMNProxy, found %d", chainSelector, len(rmnProxyRefs))
	}
	if len(rmnProxyRefs) == 1 {
		chainCfg.RmnAddress = rmnProxyRefs[0].Address
	}

	return chainCfg, nil
}
