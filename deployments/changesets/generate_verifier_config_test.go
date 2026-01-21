package changesets_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	execcontract "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	onrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/changesets"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	verifierconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/verifier_config"
	"github.com/smartcontractkit/chainlink-ccv/deployments/testutils"
)

const testDefaultQualifier = "default"

func TestGenerateVerifierConfig_ValidatesDefaultExecutorQualifier(t *testing.T) {
	changeset := changesets.GenerateVerifierConfig()

	env := createVerifierTestEnvironment(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateVerifierConfigCfg{
		DefaultExecutorQualifier: "",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "default executor qualifier is required")
}

func TestGenerateVerifierConfig_ValidatesCommitteeQualifier(t *testing.T) {
	changeset := changesets.GenerateVerifierConfig()

	env := createVerifierTestEnvironment(t)

	committee := testCommitteeInput()
	committee.Qualifier = ""
	err := changeset.VerifyPreconditions(env, changesets.GenerateVerifierConfigCfg{
		DefaultExecutorQualifier: testDefaultQualifier,
		EnvironmentNOPs:          testVerifierNOPs(),
		Committee:                committee,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "committee qualifier is required")
}

func TestGenerateVerifierConfig_ValidatesAggregators(t *testing.T) {
	changeset := changesets.GenerateVerifierConfig()

	env := createVerifierTestEnvironment(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateVerifierConfigCfg{
		DefaultExecutorQualifier: testDefaultQualifier,
		EnvironmentNOPs:          testVerifierNOPs(),
		Committee: verifierconfig.CommitteeInput{
			Qualifier:   testCommittee,
			Aggregators: []verifierconfig.AggregatorInput{},
			NOPAliases:  []shared.NOPAlias{"nop-1", "nop-2"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one aggregator is required")
}

func TestGenerateVerifierConfig_ValidatesNOPSignerAddress(t *testing.T) {
	changeset := changesets.GenerateVerifierConfig()

	env := createVerifierTestEnvironment(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateVerifierConfigCfg{
		DefaultExecutorQualifier: testDefaultQualifier,
		EnvironmentNOPs: []verifierconfig.NOPInput{
			{Alias: "nop-1", SignerAddress: ""},
			{Alias: "nop-2", SignerAddress: "0x1234567890ABCDEF1234567890ABCDEF12345678"},
		},
		Committee: testCommitteeInput(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `NOP "nop-1" missing signer_address`)
}

func TestGenerateVerifierConfig_ValidatesNOPAliasesExist(t *testing.T) {
	changeset := changesets.GenerateVerifierConfig()

	env := createVerifierTestEnvironment(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateVerifierConfigCfg{
		DefaultExecutorQualifier: testDefaultQualifier,
		EnvironmentNOPs:          testVerifierNOPs(),
		Committee:                testCommitteeInput(),
		TargetNOPs:               []shared.NOPAlias{"unknown-nop"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `NOP alias "unknown-nop" not found in NOPs input`)
}

func TestGenerateVerifierConfig_ValidatesChainSelectors(t *testing.T) {
	changeset := changesets.GenerateVerifierConfig()

	env := createVerifierTestEnvironment(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateVerifierConfigCfg{
		DefaultExecutorQualifier: testDefaultQualifier,
		EnvironmentNOPs:          testVerifierNOPs(),
		Committee:                testCommitteeInput(),
		ChainSelectors:           []uint64{1234},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "selector 1234 is not available in environment")
}

func TestGenerateVerifierConfig_GeneratesCorrectJobSpec(t *testing.T) {
	selectors := []uint64{
		chainsel.TEST_90000001.Selector,
		chainsel.TEST_90000002.Selector,
	}
	committee := testCommittee
	executorQualifier := testDefaultQualifier

	env, _ := testutils.NewSimulatedEVMEnvironment(t, selectors)
	sel1, sel2 := selectors[0], selectors[1]
	sel1Str := strconv.FormatUint(sel1, 10)
	sel2Str := strconv.FormatUint(sel2, 10)

	committeeVerifierAddr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	committeeVerifierAddr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	onRampAddr1 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	onRampAddr2 := common.HexToAddress("0x4444444444444444444444444444444444444444")
	executorAddr1 := common.HexToAddress("0x5555555555555555555555555555555555555555")
	executorAddr2 := common.HexToAddress("0x6666666666666666666666666666666666666666")
	rmnAddr1 := common.HexToAddress("0x7777777777777777777777777777777777777777")
	rmnAddr2 := common.HexToAddress("0x8888888888888888888888888888888888888888")

	ds := datastore.NewMemoryDataStore()

	addContractToDatastore(t, ds, sel1, committee, committee_verifier.ResolverType, committeeVerifierAddr1)
	addContractToDatastore(t, ds, sel2, committee, committee_verifier.ResolverType, committeeVerifierAddr2)
	addContractToDatastore(t, ds, sel1, "", onrampoperations.ContractType, onRampAddr1)
	addContractToDatastore(t, ds, sel2, "", onrampoperations.ContractType, onRampAddr2)
	addContractToDatastore(t, ds, sel1, executorQualifier, execcontract.ProxyType, executorAddr1)
	addContractToDatastore(t, ds, sel2, executorQualifier, execcontract.ProxyType, executorAddr2)
	addContractToDatastore(t, ds, sel1, "", rmn_remote.ContractType, rmnAddr1)
	addContractToDatastore(t, ds, sel2, "", rmn_remote.ContractType, rmnAddr2)

	env.DataStore = ds.Seal()

	cs := changesets.GenerateVerifierConfig()
	output, err := cs.Apply(env, changesets.GenerateVerifierConfigCfg{
		DefaultExecutorQualifier: executorQualifier,
		ChainSelectors:           selectors,
		TargetNOPs:               []shared.NOPAlias{"nop-1"},
		EnvironmentNOPs:          testVerifierNOPs(),
		Committee:                testCommitteeInput(),
		PyroscopeURL:             "http://pyroscope:4040",
		Monitoring:               testVerifierMonitoring(),
	})
	require.NoError(t, err)
	require.NotNil(t, output.DataStore)

	jobSpec, err := deployments.GetNOPJobSpec(output.DataStore.Seal(), "nop-1", "instance-1-test-committee-verifier")
	require.NoError(t, err)

	assert.Contains(t, jobSpec, `schemaVersion = 1`)
	assert.Contains(t, jobSpec, `type = "ccvcommitteeverifier"`)
	assert.Contains(t, jobSpec, `committeeVerifierConfig = """`)
	assert.Contains(t, jobSpec, `verifier_id = "instance-1-test-committee-verifier"`)
	assert.Contains(t, jobSpec, `aggregator_address = "aggregator-1:443"`)
	assert.Contains(t, jobSpec, `signer_address = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"`)
	assert.Contains(t, jobSpec, `pyroscope_url = "http://pyroscope:4040"`)

	assert.Contains(t, jobSpec, `[committee_verifier_addresses]`)
	assert.Contains(t, jobSpec, sel1Str)
	assert.Contains(t, jobSpec, sel2Str)
	assert.True(t, strings.Contains(jobSpec, committeeVerifierAddr1.Hex()) || strings.Contains(jobSpec, strings.ToLower(committeeVerifierAddr1.Hex())))

	assert.Contains(t, jobSpec, `[on_ramp_addresses]`)
	assert.Contains(t, jobSpec, `[default_executor_on_ramp_addresses]`)
	assert.Contains(t, jobSpec, `[rmn_remote_addresses]`)

	assert.Contains(t, jobSpec, `[monitoring]`)
	assert.Contains(t, jobSpec, `Enabled = true`)
	assert.Contains(t, jobSpec, `Type = "beholder"`)
}

func addContractToDatastore(t *testing.T, ds *datastore.MemoryDataStore, selector uint64, qualifier string, contractType deployment.ContractType, addr common.Address) {
	t.Helper()
	err := ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: selector,
		Qualifier:     qualifier,
		Type:          datastore.ContractType(contractType),
		Address:       addr.Hex(),
	})
	require.NoError(t, err)
}

func TestGenerateVerifierConfig_PreservesExistingConfigs(t *testing.T) {
	selectors := []uint64{
		chainsel.TEST_90000001.Selector,
		chainsel.TEST_90000002.Selector,
	}
	committee := testCommittee
	executorQualifier := testDefaultQualifier

	env, _ := testutils.NewSimulatedEVMEnvironment(t, selectors)
	sel1, sel2 := selectors[0], selectors[1]

	committeeVerifierAddr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	committeeVerifierAddr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	onRampAddr1 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	onRampAddr2 := common.HexToAddress("0x4444444444444444444444444444444444444444")
	executorAddr1 := common.HexToAddress("0x5555555555555555555555555555555555555555")
	executorAddr2 := common.HexToAddress("0x6666666666666666666666666666666666666666")
	rmnAddr1 := common.HexToAddress("0x7777777777777777777777777777777777777777")
	rmnAddr2 := common.HexToAddress("0x8888888888888888888888888888888888888888")

	ds := datastore.NewMemoryDataStore()

	addContractToDatastore(t, ds, sel1, committee, committee_verifier.ResolverType, committeeVerifierAddr1)
	addContractToDatastore(t, ds, sel2, committee, committee_verifier.ResolverType, committeeVerifierAddr2)
	addContractToDatastore(t, ds, sel1, "", onrampoperations.ContractType, onRampAddr1)
	addContractToDatastore(t, ds, sel2, "", onrampoperations.ContractType, onRampAddr2)
	addContractToDatastore(t, ds, sel1, executorQualifier, execcontract.ProxyType, executorAddr1)
	addContractToDatastore(t, ds, sel2, executorQualifier, execcontract.ProxyType, executorAddr2)
	addContractToDatastore(t, ds, sel1, "", rmn_remote.ContractType, rmnAddr1)
	addContractToDatastore(t, ds, sel2, "", rmn_remote.ContractType, rmnAddr2)

	existingExecutorJobSpec := "existing-executor-job-spec-content"
	err := deployments.SaveNOPJobSpec(ds, "existing-nop", "existing-executor", existingExecutorJobSpec)
	require.NoError(t, err)

	env.DataStore = ds.Seal()

	cs := changesets.GenerateVerifierConfig()
	output, err := cs.Apply(env, changesets.GenerateVerifierConfigCfg{
		DefaultExecutorQualifier: executorQualifier,
		ChainSelectors:           selectors,
		TargetNOPs:               []shared.NOPAlias{"nop-1"},
		EnvironmentNOPs:          testVerifierNOPs(),
		Committee:                testCommitteeInput(),
		PyroscopeURL:             "http://pyroscope:4040",
		Monitoring:               testVerifierMonitoring(),
	})
	require.NoError(t, err)
	require.NotNil(t, output.DataStore)

	outputSealed := output.DataStore.Seal()

	_, err = deployments.GetNOPJobSpec(outputSealed, "nop-1", "instance-1-test-committee-verifier")
	require.NoError(t, err, "new verifier job spec should be present")

	retrievedExecutorJobSpec, err := deployments.GetNOPJobSpec(outputSealed, "existing-nop", "existing-executor")
	require.NoError(t, err, "existing executor job spec should be preserved")
	assert.Equal(t, existingExecutorJobSpec, retrievedExecutorJobSpec, "executor job spec should be unchanged")
}

func TestGenerateVerifierConfig_MultipleAggregatorsPerCommittee(t *testing.T) {
	selectors := []uint64{
		chainsel.TEST_90000001.Selector,
		chainsel.TEST_90000002.Selector,
	}
	committee := testCommittee
	executorQualifier := testDefaultQualifier

	env, _ := testutils.NewSimulatedEVMEnvironment(t, selectors)
	sel1, sel2 := selectors[0], selectors[1]

	committeeVerifierAddr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	committeeVerifierAddr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	onRampAddr1 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	onRampAddr2 := common.HexToAddress("0x4444444444444444444444444444444444444444")
	executorAddr1 := common.HexToAddress("0x5555555555555555555555555555555555555555")
	executorAddr2 := common.HexToAddress("0x6666666666666666666666666666666666666666")
	rmnAddr1 := common.HexToAddress("0x7777777777777777777777777777777777777777")
	rmnAddr2 := common.HexToAddress("0x8888888888888888888888888888888888888888")

	ds := datastore.NewMemoryDataStore()

	addContractToDatastore(t, ds, sel1, committee, committee_verifier.ResolverType, committeeVerifierAddr1)
	addContractToDatastore(t, ds, sel2, committee, committee_verifier.ResolverType, committeeVerifierAddr2)
	addContractToDatastore(t, ds, sel1, "", onrampoperations.ContractType, onRampAddr1)
	addContractToDatastore(t, ds, sel2, "", onrampoperations.ContractType, onRampAddr2)
	addContractToDatastore(t, ds, sel1, executorQualifier, execcontract.ProxyType, executorAddr1)
	addContractToDatastore(t, ds, sel2, executorQualifier, execcontract.ProxyType, executorAddr2)
	addContractToDatastore(t, ds, sel1, "", rmn_remote.ContractType, rmnAddr1)
	addContractToDatastore(t, ds, sel2, "", rmn_remote.ContractType, rmnAddr2)

	env.DataStore = ds.Seal()

	multiAggCommittee := verifierconfig.CommitteeInput{
		Qualifier: testCommittee,
		Aggregators: []verifierconfig.AggregatorInput{
			{Name: "agg-primary", Address: "aggregator-primary:443"},
			{Name: "agg-secondary", Address: "aggregator-secondary:443"},
			{Name: "agg-tertiary", Address: "aggregator-tertiary:443"},
		},
		NOPAliases: []shared.NOPAlias{"nop-1", "nop-2"},
	}

	cs := changesets.GenerateVerifierConfig()
	output, err := cs.Apply(env, changesets.GenerateVerifierConfigCfg{
		DefaultExecutorQualifier: executorQualifier,
		ChainSelectors:           selectors,
		TargetNOPs:               []shared.NOPAlias{"nop-1"},
		EnvironmentNOPs:          testVerifierNOPs(),
		Committee:                multiAggCommittee,
		PyroscopeURL:             "http://pyroscope:4040",
		Monitoring:               testVerifierMonitoring(),
	})
	require.NoError(t, err)
	require.NotNil(t, output.DataStore)

	outputSealed := output.DataStore.Seal()

	jobSpec1, err := deployments.GetNOPJobSpec(outputSealed, "nop-1", "agg-primary-test-committee-verifier")
	require.NoError(t, err, "job spec for primary aggregator should exist")
	assert.Contains(t, jobSpec1, `aggregator_address = "aggregator-primary:443"`)

	jobSpec2, err := deployments.GetNOPJobSpec(outputSealed, "nop-1", "agg-secondary-test-committee-verifier")
	require.NoError(t, err, "job spec for secondary aggregator should exist")
	assert.Contains(t, jobSpec2, `aggregator_address = "aggregator-secondary:443"`)

	jobSpec3, err := deployments.GetNOPJobSpec(outputSealed, "nop-1", "agg-tertiary-test-committee-verifier")
	require.NoError(t, err, "job spec for tertiary aggregator should exist")
	assert.Contains(t, jobSpec3, `aggregator_address = "aggregator-tertiary:443"`)

	assert.Contains(t, jobSpec1, `signer_address = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"`)
	assert.Contains(t, jobSpec2, `signer_address = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"`)
	assert.Contains(t, jobSpec3, `signer_address = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"`)
}

func TestGenerateVerifierConfig_RemovesOrphanedJobSpecs(t *testing.T) {
	selectors := []uint64{
		chainsel.TEST_90000001.Selector,
		chainsel.TEST_90000002.Selector,
	}
	committee := testCommittee
	executorQualifier := testDefaultQualifier

	env, _ := testutils.NewSimulatedEVMEnvironment(t, selectors)
	sel1, sel2 := selectors[0], selectors[1]

	committeeVerifierAddr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	committeeVerifierAddr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	onRampAddr1 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	onRampAddr2 := common.HexToAddress("0x4444444444444444444444444444444444444444")
	executorAddr1 := common.HexToAddress("0x5555555555555555555555555555555555555555")
	executorAddr2 := common.HexToAddress("0x6666666666666666666666666666666666666666")
	rmnAddr1 := common.HexToAddress("0x7777777777777777777777777777777777777777")
	rmnAddr2 := common.HexToAddress("0x8888888888888888888888888888888888888888")

	ds := datastore.NewMemoryDataStore()

	addContractToDatastore(t, ds, sel1, committee, committee_verifier.ResolverType, committeeVerifierAddr1)
	addContractToDatastore(t, ds, sel2, committee, committee_verifier.ResolverType, committeeVerifierAddr2)
	addContractToDatastore(t, ds, sel1, "", onrampoperations.ContractType, onRampAddr1)
	addContractToDatastore(t, ds, sel2, "", onrampoperations.ContractType, onRampAddr2)
	addContractToDatastore(t, ds, sel1, executorQualifier, execcontract.ProxyType, executorAddr1)
	addContractToDatastore(t, ds, sel2, executorQualifier, execcontract.ProxyType, executorAddr2)
	addContractToDatastore(t, ds, sel1, "", rmn_remote.ContractType, rmnAddr1)
	addContractToDatastore(t, ds, sel2, "", rmn_remote.ContractType, rmnAddr2)

	err := deployments.SaveNOPJobSpec(ds, "nop-removed", "instance-1-test-committee-verifier", "old-job-spec")
	require.NoError(t, err)

	env.DataStore = ds.Seal()

	cs := changesets.GenerateVerifierConfig()
	output, err := cs.Apply(env, changesets.GenerateVerifierConfigCfg{
		DefaultExecutorQualifier: executorQualifier,
		ChainSelectors:           selectors,
		EnvironmentNOPs:          testVerifierNOPs(),
		Committee:                testCommitteeInput(),
		PyroscopeURL:             "http://pyroscope:4040",
		Monitoring:               testVerifierMonitoring(),
	})
	require.NoError(t, err)
	require.NotNil(t, output.DataStore)

	outputSealed := output.DataStore.Seal()

	_, err = deployments.GetNOPJobSpec(outputSealed, "nop-removed", "instance-1-test-committee-verifier")
	require.Error(t, err, "orphaned verifier job spec should be deleted")

	_, err = deployments.GetNOPJobSpec(outputSealed, "nop-1", "instance-1-test-committee-verifier")
	require.NoError(t, err, "nop-1 verifier job spec should exist")

	_, err = deployments.GetNOPJobSpec(outputSealed, "nop-2", "instance-1-test-committee-verifier")
	require.NoError(t, err, "nop-2 verifier job spec should exist")
}

func TestGenerateVerifierConfig_PreservesOtherCommitteeJobSpecs(t *testing.T) {
	selectors := []uint64{
		chainsel.TEST_90000001.Selector,
		chainsel.TEST_90000002.Selector,
	}
	committee := testCommittee
	executorQualifier := testDefaultQualifier

	env, _ := testutils.NewSimulatedEVMEnvironment(t, selectors)
	sel1, sel2 := selectors[0], selectors[1]

	committeeVerifierAddr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	committeeVerifierAddr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	onRampAddr1 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	onRampAddr2 := common.HexToAddress("0x4444444444444444444444444444444444444444")
	executorAddr1 := common.HexToAddress("0x5555555555555555555555555555555555555555")
	executorAddr2 := common.HexToAddress("0x6666666666666666666666666666666666666666")
	rmnAddr1 := common.HexToAddress("0x7777777777777777777777777777777777777777")
	rmnAddr2 := common.HexToAddress("0x8888888888888888888888888888888888888888")

	ds := datastore.NewMemoryDataStore()

	addContractToDatastore(t, ds, sel1, committee, committee_verifier.ResolverType, committeeVerifierAddr1)
	addContractToDatastore(t, ds, sel2, committee, committee_verifier.ResolverType, committeeVerifierAddr2)
	addContractToDatastore(t, ds, sel1, "", onrampoperations.ContractType, onRampAddr1)
	addContractToDatastore(t, ds, sel2, "", onrampoperations.ContractType, onRampAddr2)
	addContractToDatastore(t, ds, sel1, executorQualifier, execcontract.ProxyType, executorAddr1)
	addContractToDatastore(t, ds, sel2, executorQualifier, execcontract.ProxyType, executorAddr2)
	addContractToDatastore(t, ds, sel1, "", rmn_remote.ContractType, rmnAddr1)
	addContractToDatastore(t, ds, sel2, "", rmn_remote.ContractType, rmnAddr2)

	err := deployments.SaveNOPJobSpec(ds, "nop-1", "instance-1-other-committee-verifier", "other-committee-job-spec")
	require.NoError(t, err)

	env.DataStore = ds.Seal()

	cs := changesets.GenerateVerifierConfig()
	output, err := cs.Apply(env, changesets.GenerateVerifierConfigCfg{
		DefaultExecutorQualifier: executorQualifier,
		ChainSelectors:           selectors,
		TargetNOPs:               []shared.NOPAlias{"nop-1"},
		EnvironmentNOPs:          testVerifierNOPs(),
		Committee:                testCommitteeInput(),
		PyroscopeURL:             "http://pyroscope:4040",
		Monitoring:               testVerifierMonitoring(),
	})
	require.NoError(t, err)
	require.NotNil(t, output.DataStore)

	outputSealed := output.DataStore.Seal()

	otherCommitteeJobSpec, err := deployments.GetNOPJobSpec(outputSealed, "nop-1", "instance-1-other-committee-verifier")
	require.NoError(t, err, "job spec for other committee should be preserved")
	assert.Equal(t, "other-committee-job-spec", otherCommitteeJobSpec)

	_, err = deployments.GetNOPJobSpec(outputSealed, "nop-1", "instance-1-test-committee-verifier")
	require.NoError(t, err, "nop-1 test-committee verifier job spec should exist")
}

func TestGenerateVerifierConfig_ScopedNOPAliasesPreservesOtherNOPs(t *testing.T) {
	selectors := []uint64{
		chainsel.TEST_90000001.Selector,
		chainsel.TEST_90000002.Selector,
	}
	committee := testCommittee
	executorQualifier := testDefaultQualifier

	env, _ := testutils.NewSimulatedEVMEnvironment(t, selectors)
	sel1, sel2 := selectors[0], selectors[1]

	committeeVerifierAddr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	committeeVerifierAddr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	onRampAddr1 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	onRampAddr2 := common.HexToAddress("0x4444444444444444444444444444444444444444")
	executorAddr1 := common.HexToAddress("0x5555555555555555555555555555555555555555")
	executorAddr2 := common.HexToAddress("0x6666666666666666666666666666666666666666")
	rmnAddr1 := common.HexToAddress("0x7777777777777777777777777777777777777777")
	rmnAddr2 := common.HexToAddress("0x8888888888888888888888888888888888888888")

	ds := datastore.NewMemoryDataStore()

	addContractToDatastore(t, ds, sel1, committee, committee_verifier.ResolverType, committeeVerifierAddr1)
	addContractToDatastore(t, ds, sel2, committee, committee_verifier.ResolverType, committeeVerifierAddr2)
	addContractToDatastore(t, ds, sel1, "", onrampoperations.ContractType, onRampAddr1)
	addContractToDatastore(t, ds, sel2, "", onrampoperations.ContractType, onRampAddr2)
	addContractToDatastore(t, ds, sel1, executorQualifier, execcontract.ProxyType, executorAddr1)
	addContractToDatastore(t, ds, sel2, executorQualifier, execcontract.ProxyType, executorAddr2)
	addContractToDatastore(t, ds, sel1, "", rmn_remote.ContractType, rmnAddr1)
	addContractToDatastore(t, ds, sel2, "", rmn_remote.ContractType, rmnAddr2)

	err := deployments.SaveNOPJobSpec(ds, "nop-1", "instance-1-test-committee-verifier", "nop-1-job-spec")
	require.NoError(t, err)
	err = deployments.SaveNOPJobSpec(ds, "nop-2", "instance-1-test-committee-verifier", "nop-2-job-spec")
	require.NoError(t, err)

	env.DataStore = ds.Seal()

	cs := changesets.GenerateVerifierConfig()
	output, err := cs.Apply(env, changesets.GenerateVerifierConfigCfg{
		DefaultExecutorQualifier: executorQualifier,
		ChainSelectors:           selectors,
		TargetNOPs:               []shared.NOPAlias{"nop-1"},
		EnvironmentNOPs:          testVerifierNOPs(),
		Committee:                testCommitteeInput(),
		PyroscopeURL:             "http://pyroscope:4040",
		Monitoring:               testVerifierMonitoring(),
	})
	require.NoError(t, err)
	require.NotNil(t, output.DataStore)

	outputSealed := output.DataStore.Seal()

	_, err = deployments.GetNOPJobSpec(outputSealed, "nop-1", "instance-1-test-committee-verifier")
	require.NoError(t, err, "nop-1 verifier job spec should exist")

	nop2JobSpec, err := deployments.GetNOPJobSpec(outputSealed, "nop-2", "instance-1-test-committee-verifier")
	require.NoError(t, err, "nop-2 verifier job spec should be preserved when not in scope")
	assert.Equal(t, "nop-2-job-spec", nop2JobSpec, "nop-2 job spec should be unchanged")
}

func testVerifierNOPs() []verifierconfig.NOPInput {
	return []verifierconfig.NOPInput{
		{Alias: "nop-1", SignerAddress: "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"},
		{Alias: "nop-2", SignerAddress: "0x1234567890ABCDEF1234567890ABCDEF12345678"},
	}
}

func testCommitteeInput() verifierconfig.CommitteeInput {
	return verifierconfig.CommitteeInput{
		Qualifier: testCommittee,
		Aggregators: []verifierconfig.AggregatorInput{
			{Name: "instance-1", Address: "aggregator-1:443"},
		},
		NOPAliases: []shared.NOPAlias{"nop-1", "nop-2"},
	}
}

func testVerifierMonitoring() shared.MonitoringInput {
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

func createVerifierTestEnvironment(t *testing.T) deployment.Environment {
	t.Helper()

	selectors := []uint64{
		chainsel.TEST_90000001.Selector,
		chainsel.TEST_90000002.Selector,
	}
	env, _ := testutils.NewSimulatedEVMEnvironment(t, selectors)
	return env
}
