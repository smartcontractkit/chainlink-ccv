package changesets_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	execcontract "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	offrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/offramp"
	onrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	"github.com/smartcontractkit/chainlink-ccv/deployments/testutils"
)

const (
	testCommittee         = "test-committee"
	testDefaultQualifier  = "default"
	testAggregatorName    = "instance-1"
	testAggregatorAddress = "aggregator-1:443"
	testIndexerAddress    = "http://indexer:8100"
)

var (
	defaultSelectors = []uint64{
		chainsel.TEST_90000001.Selector,
		chainsel.TEST_90000002.Selector,
	}

	testContractAddresses = struct {
		CommitteeVerifier1 common.Address
		CommitteeVerifier2 common.Address
		OnRamp1            common.Address
		OnRamp2            common.Address
		Executor1          common.Address
		Executor2          common.Address
		OffRamp1           common.Address
		OffRamp2           common.Address
		RMN1               common.Address
		RMN2               common.Address
	}{
		CommitteeVerifier1: common.HexToAddress("0x1111111111111111111111111111111111111111"),
		CommitteeVerifier2: common.HexToAddress("0x2222222222222222222222222222222222222222"),
		OnRamp1:            common.HexToAddress("0x3333333333333333333333333333333333333333"),
		OnRamp2:            common.HexToAddress("0x4444444444444444444444444444444444444444"),
		Executor1:          common.HexToAddress("0x5555555555555555555555555555555555555555"),
		Executor2:          common.HexToAddress("0x6666666666666666666666666666666666666666"),
		OffRamp1:           common.HexToAddress("0x7777777777777777777777777777777777777777"),
		OffRamp2:           common.HexToAddress("0x8888888888888888888888888888888888888888"),
		RMN1:               common.HexToAddress("0x9999999999999999999999999999999999999999"),
		RMN2:               common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	}
)

type TopologyOption func(*deployments.EnvironmentTopology)

func WithPyroscopeURL(url string) TopologyOption {
	return func(t *deployments.EnvironmentTopology) {
		t.PyroscopeURL = url
	}
}

func WithMonitoring(cfg deployments.MonitoringConfig) TopologyOption {
	return func(t *deployments.EnvironmentTopology) {
		t.Monitoring = cfg
	}
}

func WithNOPs(nops []deployments.NOPConfig) TopologyOption {
	return func(t *deployments.EnvironmentTopology) {
		t.NOPTopology.NOPs = nops
	}
}

func WithCommittee(name string, cfg deployments.CommitteeConfig) TopologyOption {
	return func(t *deployments.EnvironmentTopology) {
		if t.NOPTopology.Committees == nil {
			t.NOPTopology.Committees = make(map[string]deployments.CommitteeConfig)
		}
		t.NOPTopology.Committees[name] = cfg
	}
}

func WithExecutorPool(name string, cfg deployments.ExecutorPoolConfig) TopologyOption {
	return func(t *deployments.EnvironmentTopology) {
		if t.ExecutorPools == nil {
			t.ExecutorPools = make(map[string]deployments.ExecutorPoolConfig)
		}
		t.ExecutorPools[name] = cfg
	}
}

func WithIndexerAddress(address []string) TopologyOption {
	return func(t *deployments.EnvironmentTopology) {
		t.IndexerAddress = address
	}
}

func newTestTopology(opts ...TopologyOption) *deployments.EnvironmentTopology {
	sel1Str := strconv.FormatUint(chainsel.TEST_90000001.Selector, 10)
	sel2Str := strconv.FormatUint(chainsel.TEST_90000002.Selector, 10)

	topology := &deployments.EnvironmentTopology{
		IndexerAddress: []string{testIndexerAddress},
		PyroscopeURL:   "",
		NOPTopology: &deployments.NOPTopology{
			NOPs: []deployments.NOPConfig{
				{
					Alias:                 "nop-1",
					Name:                  "nop-1",
					SignerAddressByFamily: map[string]string{chainsel.FamilyEVM: "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"},
					Mode:                  shared.NOPModeStandalone,
				},
				{
					Alias:                 "nop-2",
					Name:                  "nop-2",
					SignerAddressByFamily: map[string]string{chainsel.FamilyEVM: "0x1234567890ABCDEF1234567890ABCDEF12345678"},
					Mode:                  shared.NOPModeStandalone,
				},
			},
			Committees: map[string]deployments.CommitteeConfig{
				testCommittee: {
					Qualifier:       testCommittee,
					VerifierVersion: semver.MustParse("1.7.0"),
					Aggregators: []deployments.AggregatorConfig{
						{Name: testAggregatorName, Address: testAggregatorAddress, InsecureAggregatorConnection: true},
					},
					ChainConfigs: map[string]deployments.ChainCommitteeConfig{
						sel1Str: {
							NOPAliases:    []string{"nop-1", "nop-2"},
							Threshold:     2,
							FeeAggregator: "0x0000000000000000000000000000000000000001",
						},
						sel2Str: {
							NOPAliases:    []string{"nop-1", "nop-2"},
							Threshold:     2,
							FeeAggregator: "0x0000000000000000000000000000000000000001",
						},
					},
				},
			},
		},
		ExecutorPools: map[string]deployments.ExecutorPoolConfig{
			testDefaultQualifier: {
				NOPAliases:        []string{"nop-1", "nop-2"},
				ExecutionInterval: 15 * time.Second,
			},
		},
	}

	for _, opt := range opts {
		opt(topology)
	}

	return topology
}

func newTestEnvironment(t *testing.T, selectors []uint64) deployment.Environment {
	t.Helper()
	env, _ := testutils.NewSimulatedEVMEnvironment(t, selectors)
	return env
}

func setupVerifierDatastore(t *testing.T, ds datastore.MutableDataStore, selectors []uint64, committeeQualifier, executorQualifier string) {
	t.Helper()
	addrs := testContractAddresses

	addContractToDatastore(t, ds, selectors[0], committeeQualifier, committee_verifier.ResolverType, addrs.CommitteeVerifier1)
	addContractToDatastore(t, ds, selectors[0], "", onrampoperations.ContractType, addrs.OnRamp1)
	addContractToDatastore(t, ds, selectors[0], executorQualifier, execcontract.ProxyType, addrs.Executor1)
	addContractToDatastore(t, ds, selectors[0], "", rmn_remote.ContractType, addrs.RMN1)

	if len(selectors) > 1 {
		addContractToDatastore(t, ds, selectors[1], committeeQualifier, committee_verifier.ResolverType, addrs.CommitteeVerifier2)
		addContractToDatastore(t, ds, selectors[1], "", onrampoperations.ContractType, addrs.OnRamp2)
		addContractToDatastore(t, ds, selectors[1], executorQualifier, execcontract.ProxyType, addrs.Executor2)
		addContractToDatastore(t, ds, selectors[1], "", rmn_remote.ContractType, addrs.RMN2)
	}
}

func setupExecutorDatastore(t *testing.T, ds datastore.MutableDataStore, selectors []uint64, executorQualifier string) {
	t.Helper()
	addrs := testContractAddresses

	addContractToDatastore(t, ds, selectors[0], executorQualifier, execcontract.ProxyType, addrs.Executor1)
	addContractToDatastore(t, ds, selectors[0], "", offrampoperations.ContractType, addrs.OffRamp1)
	addContractToDatastore(t, ds, selectors[0], "", rmn_remote.ContractType, addrs.RMN1)

	if len(selectors) > 1 {
		addContractToDatastore(t, ds, selectors[1], executorQualifier, execcontract.ProxyType, addrs.Executor2)
		addContractToDatastore(t, ds, selectors[1], "", offrampoperations.ContractType, addrs.OffRamp2)
		addContractToDatastore(t, ds, selectors[1], "", rmn_remote.ContractType, addrs.RMN2)
	}
}

func addContractToDatastore(t *testing.T, ds datastore.MutableDataStore, chainSelector uint64, qualifier string, contractType deployment.ContractType, addr common.Address) {
	t.Helper()
	err := ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: chainSelector,
		Qualifier:     qualifier,
		Type:          datastore.ContractType(contractType),
		Address:       addr.Hex(),
	})
	require.NoError(t, err)
}

func defaultMonitoringConfig() deployments.MonitoringConfig {
	return deployments.MonitoringConfig{
		Enabled: true,
		Type:    "beholder",
		Beholder: deployments.BeholderConfig{
			InsecureConnection:       true,
			OtelExporterHTTPEndpoint: "otel:4318",
			MetricReaderInterval:     5,
			TraceSampleRatio:         1.0,
			TraceBatchTimeout:        10,
		},
	}
}
