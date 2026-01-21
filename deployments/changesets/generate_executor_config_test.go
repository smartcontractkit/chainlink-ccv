package changesets_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	execcontract "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	offrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/changesets"
	executorconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/executor_config"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	"github.com/smartcontractkit/chainlink-ccv/deployments/testutils"
)

func TestGenerateExecutorConfig_ValidatesIndexerAddress(t *testing.T) {
	changeset := changesets.GenerateExecutorConfig()

	env := createExecutorTestEnvironment(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateExecutorConfigCfg{
		IndexerAddress: "",
		ExecutorPool:   testExecutorPool(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "indexer address is required")
}

func TestGenerateExecutorConfig_ValidatesExecutorPoolNOPs(t *testing.T) {
	changeset := changesets.GenerateExecutorConfig()

	env := createExecutorTestEnvironment(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateExecutorConfigCfg{
		IndexerAddress: "http://indexer:8100",
		ExecutorPool:   executorconfig.ExecutorPoolInput{NOPAliases: []string{}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "executor pool NOPs are required")
}

func TestGenerateExecutorConfig_ValidatesNOPAliases(t *testing.T) {
	changeset := changesets.GenerateExecutorConfig()

	env := createExecutorTestEnvironment(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateExecutorConfigCfg{
		IndexerAddress: "http://indexer:8100",
		ExecutorPool:   testExecutorPool(),
		TargetNOPs:          []string{"unknown-nop"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `not found in executor pool`)
}

func TestGenerateExecutorConfig_ValidatesChainSelectors(t *testing.T) {
	changeset := changesets.GenerateExecutorConfig()

	env := createExecutorTestEnvironment(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateExecutorConfigCfg{
		IndexerAddress: "http://indexer:8100",
		ExecutorPool:   testExecutorPool(),
		ChainSelectors: []uint64{1234},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "selector 1234 is not available in environment")
}

func TestGenerateExecutorConfig_GeneratesCorrectJobSpec(t *testing.T) {
	selectors := []uint64{
		chainsel.TEST_90000001.Selector,
		chainsel.TEST_90000002.Selector,
	}
	executorQualifier := testDefaultQualifier

	env, _ := testutils.NewSimulatedEVMEnvironment(t, selectors)
	sel1, sel2 := selectors[0], selectors[1]
	sel1Str := strconv.FormatUint(sel1, 10)
	sel2Str := strconv.FormatUint(sel2, 10)

	offRampAddr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	offRampAddr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	rmnAddr1 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	rmnAddr2 := common.HexToAddress("0x4444444444444444444444444444444444444444")
	executorAddr1 := common.HexToAddress("0x5555555555555555555555555555555555555555")
	executorAddr2 := common.HexToAddress("0x6666666666666666666666666666666666666666")

	ds := datastore.NewMemoryDataStore()

	addContractToDatastore(t, ds, sel1, "", offrampoperations.ContractType, offRampAddr1)
	addContractToDatastore(t, ds, sel2, "", offrampoperations.ContractType, offRampAddr2)
	addContractToDatastore(t, ds, sel1, "", rmn_remote.ContractType, rmnAddr1)
	addContractToDatastore(t, ds, sel2, "", rmn_remote.ContractType, rmnAddr2)
	addContractToDatastore(t, ds, sel1, executorQualifier, execcontract.ProxyType, executorAddr1)
	addContractToDatastore(t, ds, sel2, executorQualifier, execcontract.ProxyType, executorAddr2)

	env.DataStore = ds.Seal()

	cs := changesets.GenerateExecutorConfig()
	output, err := cs.Apply(env, changesets.GenerateExecutorConfigCfg{
		ExecutorQualifier: executorQualifier,
		ChainSelectors:    selectors,
		TargetNOPs:             []string{"nop-1"},
		ExecutorPool:      testExecutorPool(),
		IndexerAddress:    "http://indexer:8100",
		PyroscopeURL:      "http://pyroscope:4040",
		Monitoring:        testMonitoring(),
	})
	require.NoError(t, err)
	require.NotNil(t, output.DataStore)

	jobSpec, err := deployments.GetNOPJobSpec(output.DataStore.Seal(), "nop-1", "nop-1-default-executor")
	require.NoError(t, err)

	assert.Contains(t, jobSpec, `schemaVersion = 1`)
	assert.Contains(t, jobSpec, `type = "ccvexecutor"`)
	assert.Contains(t, jobSpec, `executorConfig = """`)
	assert.Contains(t, jobSpec, `indexer_address = "http://indexer:8100"`)
	assert.Contains(t, jobSpec, `executor_id = "nop-1"`)
	assert.Contains(t, jobSpec, `pyroscope_url = "http://pyroscope:4040"`)

	assert.Contains(t, jobSpec, `[chain_configuration]`)
	assert.Contains(t, jobSpec, sel1Str)
	assert.Contains(t, jobSpec, sel2Str)
	assert.True(t, strings.Contains(jobSpec, offRampAddr1.Hex()) || strings.Contains(jobSpec, strings.ToLower(offRampAddr1.Hex())))

	assert.Contains(t, jobSpec, `executor_pool = ["nop-1", "nop-2"]`)
	assert.Contains(t, jobSpec, `execution_interval`)

	assert.Contains(t, jobSpec, `[Monitoring]`)
	assert.Contains(t, jobSpec, `Enabled = true`)
	assert.Contains(t, jobSpec, `Type = "beholder"`)
}

func TestGenerateExecutorConfig_PreservesExistingConfigs(t *testing.T) {
	selectors := []uint64{
		chainsel.TEST_90000001.Selector,
		chainsel.TEST_90000002.Selector,
	}
	executorQualifier := testDefaultQualifier

	env, _ := testutils.NewSimulatedEVMEnvironment(t, selectors)
	sel1, sel2 := selectors[0], selectors[1]

	offRampAddr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	offRampAddr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	rmnAddr1 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	rmnAddr2 := common.HexToAddress("0x4444444444444444444444444444444444444444")
	executorAddr1 := common.HexToAddress("0x5555555555555555555555555555555555555555")
	executorAddr2 := common.HexToAddress("0x6666666666666666666666666666666666666666")

	ds := datastore.NewMemoryDataStore()

	addContractToDatastore(t, ds, sel1, "", offrampoperations.ContractType, offRampAddr1)
	addContractToDatastore(t, ds, sel2, "", offrampoperations.ContractType, offRampAddr2)
	addContractToDatastore(t, ds, sel1, "", rmn_remote.ContractType, rmnAddr1)
	addContractToDatastore(t, ds, sel2, "", rmn_remote.ContractType, rmnAddr2)
	addContractToDatastore(t, ds, sel1, executorQualifier, execcontract.ProxyType, executorAddr1)
	addContractToDatastore(t, ds, sel2, executorQualifier, execcontract.ProxyType, executorAddr2)

	existingVerifierJobSpec := "existing-verifier-job-spec-content"
	err := deployments.SaveNOPJobSpec(ds, "existing-nop", "existing-verifier", existingVerifierJobSpec)
	require.NoError(t, err)

	env.DataStore = ds.Seal()

	cs := changesets.GenerateExecutorConfig()
	output, err := cs.Apply(env, changesets.GenerateExecutorConfigCfg{
		ExecutorQualifier: executorQualifier,
		ChainSelectors:    selectors,
		TargetNOPs:             []string{"nop-1"},
		ExecutorPool:      testExecutorPool(),
		IndexerAddress:    "http://indexer:8100",
		PyroscopeURL:      "http://pyroscope:4040",
		Monitoring:        testMonitoring(),
	})
	require.NoError(t, err)
	require.NotNil(t, output.DataStore)

	outputSealed := output.DataStore.Seal()

	_, err = deployments.GetNOPJobSpec(outputSealed, "nop-1", "nop-1-default-executor")
	require.NoError(t, err, "new executor job spec should be present")

	retrievedVerifierJobSpec, err := deployments.GetNOPJobSpec(outputSealed, "existing-nop", "existing-verifier")
	require.NoError(t, err, "existing verifier job spec should be preserved")
	assert.Equal(t, existingVerifierJobSpec, retrievedVerifierJobSpec, "verifier job spec should be unchanged")
}

func TestGenerateExecutorConfig_RemovesOrphanedJobSpecs(t *testing.T) {
	selectors := []uint64{
		chainsel.TEST_90000001.Selector,
		chainsel.TEST_90000002.Selector,
	}
	executorQualifier := testDefaultQualifier

	env, _ := testutils.NewSimulatedEVMEnvironment(t, selectors)
	sel1, sel2 := selectors[0], selectors[1]

	offRampAddr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	offRampAddr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	rmnAddr1 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	rmnAddr2 := common.HexToAddress("0x4444444444444444444444444444444444444444")
	executorAddr1 := common.HexToAddress("0x5555555555555555555555555555555555555555")
	executorAddr2 := common.HexToAddress("0x6666666666666666666666666666666666666666")

	ds := datastore.NewMemoryDataStore()

	addContractToDatastore(t, ds, sel1, "", offrampoperations.ContractType, offRampAddr1)
	addContractToDatastore(t, ds, sel2, "", offrampoperations.ContractType, offRampAddr2)
	addContractToDatastore(t, ds, sel1, "", rmn_remote.ContractType, rmnAddr1)
	addContractToDatastore(t, ds, sel2, "", rmn_remote.ContractType, rmnAddr2)
	addContractToDatastore(t, ds, sel1, executorQualifier, execcontract.ProxyType, executorAddr1)
	addContractToDatastore(t, ds, sel2, executorQualifier, execcontract.ProxyType, executorAddr2)

	err := deployments.SaveNOPJobSpec(ds, "nop-removed", "nop-removed-default-executor", "old-job-spec")
	require.NoError(t, err)

	env.DataStore = ds.Seal()

	cs := changesets.GenerateExecutorConfig()
	output, err := cs.Apply(env, changesets.GenerateExecutorConfigCfg{
		ExecutorQualifier: executorQualifier,
		ChainSelectors:    selectors,
		ExecutorPool:      testExecutorPool(),
		IndexerAddress:    "http://indexer:8100",
		PyroscopeURL:      "http://pyroscope:4040",
		Monitoring:        testMonitoring(),
	})
	require.NoError(t, err)
	require.NotNil(t, output.DataStore)

	outputSealed := output.DataStore.Seal()

	_, err = deployments.GetNOPJobSpec(outputSealed, "nop-removed", "nop-removed-default-executor")
	require.Error(t, err, "orphaned executor job spec should be deleted")

	_, err = deployments.GetNOPJobSpec(outputSealed, "nop-1", "nop-1-default-executor")
	require.NoError(t, err, "nop-1 executor job spec should exist")

	_, err = deployments.GetNOPJobSpec(outputSealed, "nop-2", "nop-2-default-executor")
	require.NoError(t, err, "nop-2 executor job spec should exist")
}

func TestGenerateExecutorConfig_PreservesOtherQualifierJobSpecs(t *testing.T) {
	selectors := []uint64{
		chainsel.TEST_90000001.Selector,
		chainsel.TEST_90000002.Selector,
	}
	executorQualifier := testDefaultQualifier

	env, _ := testutils.NewSimulatedEVMEnvironment(t, selectors)
	sel1, sel2 := selectors[0], selectors[1]

	offRampAddr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	offRampAddr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	rmnAddr1 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	rmnAddr2 := common.HexToAddress("0x4444444444444444444444444444444444444444")
	executorAddr1 := common.HexToAddress("0x5555555555555555555555555555555555555555")
	executorAddr2 := common.HexToAddress("0x6666666666666666666666666666666666666666")

	ds := datastore.NewMemoryDataStore()

	addContractToDatastore(t, ds, sel1, "", offrampoperations.ContractType, offRampAddr1)
	addContractToDatastore(t, ds, sel2, "", offrampoperations.ContractType, offRampAddr2)
	addContractToDatastore(t, ds, sel1, "", rmn_remote.ContractType, rmnAddr1)
	addContractToDatastore(t, ds, sel2, "", rmn_remote.ContractType, rmnAddr2)
	addContractToDatastore(t, ds, sel1, executorQualifier, execcontract.ProxyType, executorAddr1)
	addContractToDatastore(t, ds, sel2, executorQualifier, execcontract.ProxyType, executorAddr2)

	err := deployments.SaveNOPJobSpec(ds, "nop-1", "nop-1-other-pool-executor", "other-pool-job-spec")
	require.NoError(t, err)

	env.DataStore = ds.Seal()

	cs := changesets.GenerateExecutorConfig()
	output, err := cs.Apply(env, changesets.GenerateExecutorConfigCfg{
		ExecutorQualifier: executorQualifier,
		ChainSelectors:    selectors,
		TargetNOPs:             []string{"nop-1"},
		ExecutorPool:      testExecutorPool(),
		IndexerAddress:    "http://indexer:8100",
		PyroscopeURL:      "http://pyroscope:4040",
		Monitoring:        testMonitoring(),
	})
	require.NoError(t, err)
	require.NotNil(t, output.DataStore)

	outputSealed := output.DataStore.Seal()

	otherPoolJobSpec, err := deployments.GetNOPJobSpec(outputSealed, "nop-1", "nop-1-other-pool-executor")
	require.NoError(t, err, "job spec for other pool should be preserved")
	assert.Equal(t, "other-pool-job-spec", otherPoolJobSpec)

	_, err = deployments.GetNOPJobSpec(outputSealed, "nop-1", "nop-1-default-executor")
	require.NoError(t, err, "nop-1 default executor job spec should exist")
}

func TestGenerateExecutorConfig_ScopedNOPAliasesPreservesOtherNOPs(t *testing.T) {
	selectors := []uint64{
		chainsel.TEST_90000001.Selector,
		chainsel.TEST_90000002.Selector,
	}
	executorQualifier := testDefaultQualifier

	env, _ := testutils.NewSimulatedEVMEnvironment(t, selectors)
	sel1, sel2 := selectors[0], selectors[1]

	offRampAddr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	offRampAddr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	rmnAddr1 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	rmnAddr2 := common.HexToAddress("0x4444444444444444444444444444444444444444")
	executorAddr1 := common.HexToAddress("0x5555555555555555555555555555555555555555")
	executorAddr2 := common.HexToAddress("0x6666666666666666666666666666666666666666")

	ds := datastore.NewMemoryDataStore()

	addContractToDatastore(t, ds, sel1, "", offrampoperations.ContractType, offRampAddr1)
	addContractToDatastore(t, ds, sel2, "", offrampoperations.ContractType, offRampAddr2)
	addContractToDatastore(t, ds, sel1, "", rmn_remote.ContractType, rmnAddr1)
	addContractToDatastore(t, ds, sel2, "", rmn_remote.ContractType, rmnAddr2)
	addContractToDatastore(t, ds, sel1, executorQualifier, execcontract.ProxyType, executorAddr1)
	addContractToDatastore(t, ds, sel2, executorQualifier, execcontract.ProxyType, executorAddr2)

	err := deployments.SaveNOPJobSpec(ds, "nop-1", "nop-1-default-executor", "nop-1-job-spec")
	require.NoError(t, err)
	err = deployments.SaveNOPJobSpec(ds, "nop-2", "nop-2-default-executor", "nop-2-job-spec")
	require.NoError(t, err)

	env.DataStore = ds.Seal()

	cs := changesets.GenerateExecutorConfig()
	output, err := cs.Apply(env, changesets.GenerateExecutorConfigCfg{
		ExecutorQualifier: executorQualifier,
		ChainSelectors:    selectors,
		TargetNOPs:             []string{"nop-1"},
		ExecutorPool:      testExecutorPool(),
		IndexerAddress:    "http://indexer:8100",
		PyroscopeURL:      "http://pyroscope:4040",
		Monitoring:        testMonitoring(),
	})
	require.NoError(t, err)
	require.NotNil(t, output.DataStore)

	outputSealed := output.DataStore.Seal()

	_, err = deployments.GetNOPJobSpec(outputSealed, "nop-1", "nop-1-default-executor")
	require.NoError(t, err, "nop-1 executor job spec should exist")

	nop2JobSpec, err := deployments.GetNOPJobSpec(outputSealed, "nop-2", "nop-2-default-executor")
	require.NoError(t, err, "nop-2 executor job spec should be preserved when not in scope")
	assert.Equal(t, "nop-2-job-spec", nop2JobSpec, "nop-2 job spec should be unchanged")
}

func testExecutorPool() executorconfig.ExecutorPoolInput {
	return executorconfig.ExecutorPoolInput{
		NOPAliases:        []string{"nop-1", "nop-2"},
		ExecutionInterval: 15 * time.Second,
	}
}

func testMonitoring() shared.MonitoringInput {
	return shared.MonitoringInput{
		Enabled: true,
		Type:    "beholder",
		Beholder: shared.BeholderInput{
			InsecureConnection:       true,
			OtelExporterHTTPEndpoint: "otel:4318",
			MetricReaderInterval:     5,
			TraceSampleRatio:         1.0,
			TraceBatchTimeout:        10,
		},
	}
}

func createExecutorTestEnvironment(t *testing.T) deployment.Environment {
	t.Helper()

	selectors := []uint64{
		chainsel.TEST_90000001.Selector,
		chainsel.TEST_90000002.Selector,
	}
	env, _ := testutils.NewSimulatedEVMEnvironment(t, selectors)
	return env
}
