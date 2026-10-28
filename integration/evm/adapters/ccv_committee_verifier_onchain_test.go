package adapters_test

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"

	mcmstypes "github.com/smartcontractkit/mcms/types"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldfevm "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/operations/contract"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/test/environment"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/test/onchain"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/create2_factory"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/committee_verifier"
	cv "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v2_0_0/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/deployment/finality"

	ccvdeploymentadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	adapters "github.com/smartcontractkit/chainlink-ccv/integration/evm/adapters"
)

const cvQualifier = "alpha"

// newCommitteeVerifierEnv deploys a CommitteeVerifier owned by the deployer key on a simulated
// chain with one extra funded account, and returns the env with the verifier in its datastore.
func newCommitteeVerifierEnv(t *testing.T, deployerIsAllowlistAdmin bool) (deployment.Environment, cldfevm.Chain, *cv.CommitteeVerifier) {
	t.Helper()
	e, err := environment.New(t.Context(),
		environment.WithEVMSimulatedWithConfig(t, []uint64{testChainSelector}, onchain.EVMSimLoaderConfig{NumAdditionalAccounts: 1}),
	)
	require.NoError(t, err)
	e.DataStore = datastore.NewMemoryDataStore().Seal()
	chain := e.BlockChains.EVMChains()[testChainSelector]
	require.NotEmpty(t, chain.Users, "simulated chain must expose an extra account to act as the new owner")
	allowlistAdmin := ""
	if deployerIsAllowlistAdmin {
		allowlistAdmin = chain.DeployerKey.From.Hex()
	}

	factoryRef, err := contract.MaybeDeployContract(
		e.OperationsBundle, create2_factory.Deploy, chain,
		contract.DeployInput[create2_factory.ConstructorArgs]{
			TypeAndVersion: deployment.NewTypeAndVersion(create2_factory.ContractType, *create2_factory.Version),
			ChainSelector:  testChainSelector,
			Args:           create2_factory.ConstructorArgs{AllowList: []common.Address{chain.DeployerKey.From}},
		}, nil,
	)
	require.NoError(t, err)

	report, err := cldf_ops.ExecuteSequence(
		e.OperationsBundle, (&adapters.EVMCommitteeVerifierDeployAdapter{}).DeployCommitteeVerifier(), e.BlockChains,
		ccvdeploymentadapters.CommitteeVerifierDeployInput{
			ChainSelector:     testChainSelector,
			DeployerContract:  factoryRef.Address,
			ExistingAddresses: []datastore.AddressRef{rmnProxyRef(testChainSelector)},
			Params: ccvdeploymentadapters.CommitteeVerifierDeployParams{
				Version:          committee_verifier.Version,
				FeeAggregator:    testFeeAggregator,
				AllowlistAdmin:   allowlistAdmin,
				StorageLocations: []string{"https://test.chain.link.fake"},
				Qualifier:        cvQualifier,
			},
		},
	)
	require.NoError(t, err)

	ds := datastore.NewMemoryDataStore()
	var cvAddr common.Address
	for _, ref := range report.Output.Addresses {
		require.NoError(t, ds.Addresses().Add(ref))
		if ref.Type == datastore.ContractType(committee_verifier.ContractType) {
			cvAddr = common.HexToAddress(ref.Address)
		}
	}
	require.NotEqual(t, common.Address{}, cvAddr, "deploy must return the CommitteeVerifier address")
	e.DataStore = ds.Seal()

	verifier, err := cv.NewCommitteeVerifier(cvAddr, chain.Client)
	require.NoError(t, err)
	return *e, chain, verifier
}

// handOwnershipToUser moves CommitteeVerifier ownership to chain.Users[0], standing in for a timelock.
func handOwnershipToUser(t *testing.T, chain cldfevm.Chain, verifier *cv.CommitteeVerifier) *bind.TransactOpts {
	t.Helper()
	newOwner := chain.Users[0]
	tx, err := verifier.TransferOwnership(chain.DeployerKey, newOwner.From)
	confirmTx(t, chain, tx, err)
	tx, err = verifier.AcceptOwnership(newOwner)
	confirmTx(t, chain, tx, err)
	owner, err := verifier.Owner(&bind.CallOpts{})
	require.NoError(t, err)
	require.Equal(t, newOwner.From, owner)
	return newOwner
}

// executeBatchOp sends each proposed transaction from the owner, as the timelock would.
func executeBatchOp(t *testing.T, chain cldfevm.Chain, owner *bind.TransactOpts, op mcmstypes.BatchOperation) {
	t.Helper()
	for _, mtx := range op.Transactions {
		to := common.HexToAddress(mtx.To)
		nonce, err := chain.Client.PendingNonceAt(t.Context(), owner.From)
		require.NoError(t, err)
		gasPrice, err := chain.Client.SuggestGasPrice(t.Context())
		require.NoError(t, err)
		unsigned := types.NewTransaction(nonce, to, big.NewInt(0), 1_000_000, gasPrice, mtx.Data)
		signed, err := owner.Signer(owner.From, unsigned)
		require.NoError(t, err)
		require.NoError(t, chain.Client.SendTransaction(t.Context(), signed))
		_, err = chain.Confirm(signed)
		require.NoError(t, err)
	}
}

func requireSingleBatchOp(t *testing.T, ops []mcmstypes.BatchOperation, verifier common.Address) mcmstypes.BatchOperation {
	t.Helper()
	require.Len(t, ops, 1)
	require.Equal(t, mcmstypes.ChainSelector(testChainSelector), ops[0].ChainSelector)
	require.Len(t, ops[0].Transactions, 1)
	require.Equal(t, verifier, common.HexToAddress(ops[0].Transactions[0].To))
	return ops[0]
}

func TestEVMCCVCommitteeVerifierOnchainAdapter_SetAllowedFinalityConfig(t *testing.T) {
	e, chain, verifier := newCommitteeVerifierEnv(t, false)
	adapter := &adapters.EVMCCVCommitteeVerifierOnchainAdapter{}
	safe := finality.Config{WaitForSafe: true}.Raw()
	depth := finality.Config{BlockDepth: 7}.Raw()

	ops, err := adapter.SetAllowedFinalityConfig(t.Context(), e, testChainSelector, cvQualifier, false, true, 0)
	require.NoError(t, err)
	require.Empty(t, ops, "deployer-key mode must execute directly and return no batch ops")
	got, err := verifier.GetAllowedFinalityConfig(&bind.CallOpts{})
	require.NoError(t, err)
	require.Equal(t, safe, got)

	owner := handOwnershipToUser(t, chain, verifier)
	ops, err = adapter.SetAllowedFinalityConfig(t.Context(), e, testChainSelector, cvQualifier, false, false, 7)
	require.NoError(t, err)
	op := requireSingleBatchOp(t, ops, verifier.Address())
	got, err = verifier.GetAllowedFinalityConfig(&bind.CallOpts{})
	require.NoError(t, err)
	require.Equal(t, safe, got, "MCMS mode must not change state before the proposal executes")

	executeBatchOp(t, chain, owner, op)
	got, err = verifier.GetAllowedFinalityConfig(&bind.CallOpts{})
	require.NoError(t, err)
	require.Equal(t, depth, got, "executing the batch op as owner must apply the change")
}

func TestEVMCCVCommitteeVerifierOnchainAdapter_ApplySignatureConfigs(t *testing.T) {
	e, chain, verifier := newCommitteeVerifierEnv(t, false)
	adapter := &adapters.EVMCCVCommitteeVerifierOnchainAdapter{}
	source := chainsel.TEST_90000002.Selector
	signers := []string{
		"0x00000000000000000000000000000000000000A1",
		"0x00000000000000000000000000000000000000A2",
	}
	change := func(threshold uint8) ccvdeploymentadapters.SignatureConfigChange {
		return ccvdeploymentadapters.SignatureConfigChange{NewConfigs: []ccvdeploymentadapters.SignatureConfig{{
			SourceChainSelector: source, Signers: signers, Threshold: threshold,
		}}}
	}
	threshold := func() uint8 {
		cfg, err := verifier.GetSignatureConfig(&bind.CallOpts{}, source)
		require.NoError(t, err)
		return cfg.Threshold
	}

	ops, err := adapter.ApplySignatureConfigs(t.Context(), e, testChainSelector, cvQualifier, change(1))
	require.NoError(t, err)
	require.Empty(t, ops, "deployer-key mode must execute directly and return no batch ops")
	require.Equal(t, uint8(1), threshold())

	owner := handOwnershipToUser(t, chain, verifier)
	ops, err = adapter.ApplySignatureConfigs(t.Context(), e, testChainSelector, cvQualifier, change(2))
	require.NoError(t, err)
	op := requireSingleBatchOp(t, ops, verifier.Address())
	require.Equal(t, uint8(1), threshold(), "MCMS mode must not change state before the proposal executes")

	executeBatchOp(t, chain, owner, op)
	require.Equal(t, uint8(2), threshold(), "executing the batch op as owner must apply the change")
}

func TestEVMCCVCommitteeVerifierOnchainAdapter_ApplyAllowlistUpdates(t *testing.T) {
	e, chain, verifier := newCommitteeVerifierEnv(t, false)
	adapter := &adapters.EVMCCVCommitteeVerifierOnchainAdapter{}
	dest := chainsel.TEST_90000002.Selector
	first := "0x00000000000000000000000000000000000000B1"
	second := "0x00000000000000000000000000000000000000B2"
	allowed := func() []common.Address {
		cfg, err := verifier.GetRemoteChainConfig(&bind.CallOpts{}, dest)
		require.NoError(t, err)
		return cfg.AllowedSendersList
	}

	ops, err := adapter.ApplyAllowlistUpdates(t.Context(), e, testChainSelector, cvQualifier, dest, true, []string{first}, nil)
	require.NoError(t, err)
	require.Empty(t, ops, "deployer-key mode must execute directly and return no batch ops")
	require.ElementsMatch(t, []common.Address{common.HexToAddress(first)}, allowed())

	owner := handOwnershipToUser(t, chain, verifier)
	ops, err = adapter.ApplyAllowlistUpdates(t.Context(), e, testChainSelector, cvQualifier, dest, true, []string{second}, nil)
	require.NoError(t, err)
	op := requireSingleBatchOp(t, ops, verifier.Address())
	require.ElementsMatch(t, []common.Address{common.HexToAddress(first)}, allowed(), "MCMS mode must not change state before the proposal executes")

	executeBatchOp(t, chain, owner, op)
	require.ElementsMatch(t, []common.Address{common.HexToAddress(first), common.HexToAddress(second)}, allowed(),
		"executing the batch op as owner must apply the change")
}

func TestEVMCCVCommitteeVerifierOnchainAdapter_ApplyAllowlistUpdates_AllowlistAdminExecutesDirectly(t *testing.T) {
	env, chain, verifier := newCommitteeVerifierEnv(t, true)
	adapter := &adapters.EVMCCVCommitteeVerifierOnchainAdapter{}
	dest := chainsel.TEST_90000002.Selector
	sender := "0x00000000000000000000000000000000000000B1"

	handOwnershipToUser(t, chain, verifier)
	ops, err := adapter.ApplyAllowlistUpdates(t.Context(), env, testChainSelector, cvQualifier, dest, true, []string{sender}, nil)
	require.NoError(t, err)
	require.Empty(t, ops, "the allowlist admin may call applyAllowlistUpdates directly, so nothing is proposed")
	cfg, err := verifier.GetRemoteChainConfig(&bind.CallOpts{}, dest)
	require.NoError(t, err)
	require.ElementsMatch(t, []common.Address{common.HexToAddress(sender)}, cfg.AllowedSendersList)
}
