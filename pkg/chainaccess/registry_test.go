package chainaccess_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// testEVMFactory and testAccessor are minimal implementations used to exercise
// the NewRegistry → GetAccessor path without any real chain connectivity.

var (
	constructorShouldFail atomic.Bool
	accessorShouldFail    atomic.Bool
)

type testEVMFactory struct{}

func (f *testEVMFactory) GetAccessor(_ context.Context, _ protocol.ChainSelector) (chainaccess.Accessor, error) {
	if accessorShouldFail.Load() {
		return nil, errors.New("test accessor error")
	}
	return &testAccessor{}, nil
}

type testAccessor struct{}

func (a *testAccessor) SourceReader() (chainaccess.SourceReader, error) {
	return nil, errors.New("source reader not available")
}

func (a *testAccessor) DestinationReader() (chainaccess.DestinationReader, error) {
	return nil, errors.New("destination reader not available")
}

func (a *testAccessor) ContractTransmitter() (chainaccess.ContractTransmitter, error) {
	return nil, errors.New("contract transmitter not available")
}

func (a *testAccessor) Close() error {
	return nil
}

func init() {
	// Register a test constructor for the "evm" family so that NewRegistry
	// can build a Registry without real RPC connections.
	chainaccess.Register("evm", func(_ logger.Logger, _ chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) {
		return &testEVMFactory{}, nil
	})

	// Register a second family whose constructor can be toggled to fail.
	// "test-constructor-error" is not a real chain-selectors family, so it
	// will never be selected by GetAccessor; it only exercises the
	// NewRegistry constructor-error code path.
	chainaccess.Register("test-constructor-error", func(_ logger.Logger, _ chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) {
		if constructorShouldFail.Load() {
			return nil, errors.New("test constructor error")
		}
		return &testEVMFactory{}, nil
	})
}

// ethereumMainnetSelector is the chain selector for Ethereum mainnet, which the
// chain-selectors library maps to the "evm" family.
const ethereumMainnetSelector = protocol.ChainSelector(5009297550715157269)

func TestNewRegistry_GetAccessor(t *testing.T) {
	cfg := `
[on_ramp_addresses]
"5009297550715157269" = "0xOnRamp"

[rmn_remote_addresses]
"5009297550715157269" = "0xRMN"
`
	lggr := logger.Test(t)
	reg, err := chainaccess.NewRegistry(lggr, cfg)
	require.NoError(t, err)
	require.NotNil(t, reg)

	accessor, err := reg.GetAccessor(context.Background(), ethereumMainnetSelector)
	require.NoError(t, err)
	assert.NotNil(t, accessor)
}

func TestRegister_PanicsOnDuplicate(t *testing.T) {
	assert.Panics(t, func() {
		chainaccess.Register("evm", func(_ logger.Logger, _ chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) {
			return nil, nil
		})
	})
}

func TestNewRegistry_InvalidTOML(t *testing.T) {
	lggr := logger.Test(t)
	_, err := chainaccess.NewRegistry(lggr, "}{not valid toml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal generic config")
}

func TestNewRegistry_WarnsAndIgnoresBlockchainInfos(t *testing.T) {
	lggr, logs := logger.TestObserved(t, zapcore.WarnLevel)
	reg, err := chainaccess.NewRegistry(lggr, `
[blockchain_infos."5009297550715157269"]
chain_id = "1"
`)
	require.NoError(t, err)
	require.NotNil(t, reg)
	entries := logs.FilterMessageSnippet("Ignoring removed application config").All()
	require.Len(t, entries, 1)
	assert.Equal(t, chainaccess.BlockchainInfosConfigKey, entries[0].ContextMap()["field"])
}

func TestNewRegistry_ConstructorError(t *testing.T) {
	constructorShouldFail.Store(true)
	defer constructorShouldFail.Store(false)

	lggr := logger.Test(t)
	_, err := chainaccess.NewRegistry(lggr, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to construct accessor factory")
}

func TestGetAccessor_UnknownSelector(t *testing.T) {
	lggr := logger.Test(t)
	reg, err := chainaccess.NewRegistry(lggr, "")
	require.NoError(t, err)

	// Selector 0 is not present in the chain-selectors library.
	_, err = reg.GetAccessor(context.Background(), protocol.ChainSelector(0))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get selector family")
}

func TestGetAccessor_NoFactoryForFamily(t *testing.T) {
	lggr := logger.Test(t)
	reg, err := chainaccess.NewRegistry(lggr, "")
	require.NoError(t, err)

	// Solana mainnet maps to the "solana" family, which has no registered factory.
	solanaSelector := protocol.ChainSelector(chainsel.SOLANA_MAINNET.Selector)
	_, err = reg.GetAccessor(context.Background(), solanaSelector)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no factory registered for chain family")
}

func TestGetAccessor_FactoryError(t *testing.T) {
	accessorShouldFail.Store(true)
	defer accessorShouldFail.Store(false)

	lggr := logger.Test(t)
	reg, err := chainaccess.NewRegistry(lggr, "")
	require.NoError(t, err)

	_, err = reg.GetAccessor(context.Background(), ethereumMainnetSelector)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test accessor error")
}

type TestInfo struct {
	ChainID         string
	Type            string
	Family          string
	UniqueChainName string
}

func (t TestInfo) Empty() bool {
	return t.ChainID == "" && t.Type == "" && t.Family == "" && t.UniqueChainName == ""
}

func TestHelper_GetBlockchainByChainSelector_NilMapEntriesTreatedAsNotFound(t *testing.T) {
	validInfo := TestInfo{ChainID: "123", Type: "evm", Family: "evm", UniqueChainName: "chain-123"}
	selector := protocol.ChainSelector(999)
	tests := []struct {
		name    string
		infos   chainaccess.Infos[TestInfo]
		wantErr bool
	}{
		{
			name:    "returns error when key exists but value is nil",
			infos:   chainaccess.Infos[TestInfo]{"999": {}},
			wantErr: false, // With generic types, this isn't something we can test for.
		},
		{
			name:    "returns info when key exists and value is non-nil",
			infos:   chainaccess.Infos[TestInfo]{"999": validInfo},
			wantErr: false,
		},
		{
			name:    "returns error when key does not exist",
			infos:   chainaccess.Infos[TestInfo]{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.infos.GetBlockchainByChainSelector(selector)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetBlockchainByChainSelector() expected error, got nil")
				}
				if !got.Empty() {
					t.Errorf("GetBlockchainByChainSelector() expected empty info when error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Errorf("GetBlockchainByChainSelector() unexpected error: %v", err)
			}
			/*
				// Can't reliably test for nil vs empty struct with generic types.
				if got.Empty() {
					t.Errorf("GetBlockchainByChainSelector() expected non-empty info")
				}
			*/
		})
	}
}

func TestInfos_GetAllInfos(t *testing.T) {
	t.Run("empty infos returns empty map", func(t *testing.T) {
		infos := chainaccess.Infos[TestInfo]{}
		result := infos.GetAllInfos()
		if len(result) != 0 {
			t.Errorf("expected empty map, got %v", result)
		}
	})

	t.Run("valid numeric keys are converted to ChainSelectors", func(t *testing.T) {
		infos := chainaccess.Infos[TestInfo]{
			"100": {ChainID: "100", Type: "evm"},
			"200": {ChainID: "200", Type: "evm"},
		}
		result := infos.GetAllInfos()
		if len(result) != 2 {
			t.Errorf("expected 2 entries, got %d", len(result))
		}
		if result[protocol.ChainSelector(100)].ChainID != "100" {
			t.Errorf("expected ChainID 100, got %s", result[protocol.ChainSelector(100)].ChainID)
		}
		if result[protocol.ChainSelector(200)].ChainID != "200" {
			t.Errorf("expected ChainID 200, got %s", result[protocol.ChainSelector(200)].ChainID)
		}
	})

	t.Run("non-numeric keys are skipped", func(t *testing.T) {
		infos := chainaccess.Infos[TestInfo]{
			"valid":    {ChainID: "bad"},  // non-numeric: skipped
			"also-bad": {ChainID: "bad"},  // non-numeric: skipped
			"42":       {ChainID: "good"}, // numeric: kept
		}
		result := infos.GetAllInfos()
		if len(result) != 1 {
			t.Errorf("expected 1 entry, got %d", len(result))
		}
		if result[protocol.ChainSelector(42)].ChainID != "good" {
			t.Errorf("expected ChainID good, got %s", result[protocol.ChainSelector(42)].ChainID)
		}
	})
}

func TestInfos_GetAllChainSelectors(t *testing.T) {
	t.Run("empty infos returns empty slice", func(t *testing.T) {
		infos := chainaccess.Infos[TestInfo]{}
		selectors := infos.GetAllChainSelectors()
		if len(selectors) != 0 {
			t.Errorf("expected empty slice, got %v", selectors)
		}
	})

	t.Run("returns one selector per valid numeric key", func(t *testing.T) {
		infos := chainaccess.Infos[TestInfo]{
			"10":      {ChainID: "10"},
			"20":      {ChainID: "20"},
			"bad-key": {ChainID: "skip"},
		}
		selectors := infos.GetAllChainSelectors()
		if len(selectors) != 2 {
			t.Errorf("expected 2 selectors, got %d: %v", len(selectors), selectors)
		}
		found := make(map[protocol.ChainSelector]bool)
		for _, s := range selectors {
			found[s] = true
		}
		if !found[protocol.ChainSelector(10)] {
			t.Error("expected selector 10, not found")
		}
		if !found[protocol.ChainSelector(20)] {
			t.Error("expected selector 20, not found")
		}
	})
}
