package evm

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestCreateEVMAccessorFactoryUsesLocalConfigInsteadOfBlockchainInfos(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evm.toml")
	require.NoError(t, os.WriteFile(path, []byte("[chains]\n"), 0o600))
	t.Setenv(EVMConfigPathEnv, path)

	genericConfig := chainaccess.GenericConfig{}
	factory, err := CreateEVMAccessorFactory(logger.Test(t), genericConfig)
	require.NoError(t, err)
	require.NotNil(t, factory)
}

// writeEVMFiles mounts an EVM config and secrets file with the given contents.
func writeEVMFiles(t *testing.T, config, secrets string) {
	t.Helper()
	dir := t.TempDir()
	configPath, secretsPath := filepath.Join(dir, "evm.toml"), filepath.Join(dir, "secrets.toml")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))
	require.NoError(t, os.WriteFile(secretsPath, []byte(secrets), 0o600))
	t.Setenv(EVMConfigPathEnv, configPath)
	t.Setenv(evmconfig.EVMSecretsPathEnv, secretsPath)
}

func TestCreateEVMAccessorFactoryLogPollerNeedsTheEVMDatabase(t *testing.T) {
	writeEVMFiles(t, "log_poller_enabled = true\n[chains]\n", "")
	_, err := CreateEVMAccessorFactory(logger.Test(t), chainaccess.GenericConfig{})
	require.ErrorContains(t, err, "requires [db]")
}

func TestCreateEVMAccessorFactoryPassesLogPollerAndVerifierID(t *testing.T) {
	writeEVMFiles(t,
		"log_poller_enabled = true\n[chains.16015286601757825753]\n[[chains.16015286601757825753.nodes]]\nname = \"primary\"\nhttp_url = \"http://localhost:8545\"\n",
		"[db]\nurl = \"postgres://localhost:5432/evm\"\n")
	got, err := CreateEVMAccessorFactory(logger.Test(t), chainaccess.GenericConfig{VerifierID: "verifier-1"})
	require.NoError(t, err)
	f := got.(*factory)
	require.True(t, f.logPollerEnabled)
	require.Equal(t, "verifier-1", f.verifierID)
	require.NotNil(t, f.db, "the database is configured but not connected")
	require.Equal(t, []*big.Int{big.NewInt(11155111)}, f.chainIDs, "Sepolia's chain ID, from the EVM config")
}

func TestCreateAccessorFactoryDoesNotDialRPCDuringConstruction(t *testing.T) {
	t.Parallel()

	infos := chainaccess.Infos[Info]{
		"5009297550715157269": {
			ChainID: "1",
			Family:  chainsel.FamilyEVM,
			Nodes: []Node{{
				HTTPUrl: "http://127.0.0.1:1",
			}},
		},
	}

	factory, err := CreateAccessorFactory(logger.Test(t), chainaccess.GenericConfig{}, infos)
	require.NoError(t, err)
	require.NotNil(t, factory)
}

func TestCreateAccessorFactoryPassesFeeQuoterAddressesToTheFactory(t *testing.T) {
	t.Parallel()

	const selector = "5009297550715157269"
	newFactory := func(t *testing.T, address string) chainaccess.AccessorFactory {
		t.Helper()
		generic := chainaccess.GenericConfig{
			PricerConfig: chainaccess.PricerConfig{FeeQuoterAddresses: map[string]string{selector: address}},
		}
		factory, err := CreateAccessorFactory(logger.Test(t), generic, chainaccess.Infos[Info]{})
		require.NoError(t, err)
		return factory
	}

	t.Run("invalid address fails", func(t *testing.T) {
		t.Parallel()
		_, err := newFactory(t, "not-an-address").GetAccessor(t.Context(), 5009297550715157269)
		require.ErrorContains(t, err, "invalid fee quoter address")
	})

	t.Run("valid address is enough to start the runtime", func(t *testing.T) {
		t.Parallel()
		// No chain info exists, so the runtime builder fails. It is called only if the fee quoter address passes.
		_, err := newFactory(t, validTestFeeQuoterAddress).GetAccessor(t.Context(), 5009297550715157269)
		require.ErrorContains(t, err, "failed to get EVM config for chain")
	})
}

func TestCreateAccessorFactoryPassesNativeTokenDecimalsToTheFactory(t *testing.T) {
	t.Parallel()

	generic := chainaccess.GenericConfig{
		PricerConfig: chainaccess.PricerConfig{
			FeeQuoterAddresses:  map[string]string{"5009297550715157269": validTestFeeQuoterAddress},
			NativeTokenDecimals: map[string]uint8{"5009297550715157269": 37},
		},
	}
	factory, err := CreateAccessorFactory(logger.Test(t), generic, chainaccess.Infos[Info]{})
	require.NoError(t, err)

	_, err = factory.GetAccessor(t.Context(), 5009297550715157269)
	require.ErrorContains(t, err, "invalid native token decimals 37")
}
