package pricer

import (
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/assets"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	evmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
	"github.com/smartcontractkit/chainlink-evm/pkg/gas"
	"github.com/smartcontractkit/chainlink-evm/pkg/keys"
	evmkeys "github.com/smartcontractkit/chainlink-evm/pkg/keys/v2"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/clientwrappers"
	"github.com/smartcontractkit/chainlink-evm/pkg/txm/storage"
)

// TODO: Move this to chainlink-evm/pkg/client.
func NewEvmClientFromConfig(lggr logger.Logger, cfg evmtoml.EVMConfig) (client.Client, error) {
	chainScopedCfg := evmconfig.NewTOMLChainScopedConfig(&cfg)
	nodePoolCfg := &evmconfig.NodePoolConfig{C: cfg.Chain.NodePool}

	return client.NewEvmClient(
		nodePoolCfg,
		chainScopedCfg.EVM(),
		nodePoolCfg.Errors(),
		lggr,
		chainScopedCfg.EVM().ChainID(),
		chainScopedCfg.Nodes(),
		chainScopedCfg.EVM().ChainType(),
	)
}

// NewStatelessTxmV2FromConfig creates a stateless (in-memory) TxmV2.
// TODO: Move this to chainlink-evm/pkg/txm.
func NewStatelessTxmV2FromConfig(
	lggr logger.Logger,
	cfg evmtoml.EVMConfig,
	evmClient client.Client,
	keyStore keystore.Keystore,
	estimator gas.EvmFeeEstimator,
) *txm.Txm {
	chainScopedCfg := evmconfig.NewTOMLChainScopedConfig(&cfg)
	evmCfg := chainScopedCfg.EVM()
	chainID := evmCfg.ChainID()

	inMemoryStoreManager := storage.NewInMemoryStoreManager(lggr, chainID)
	txmClient := clientwrappers.NewChainClient(evmClient)
	priceMaxKey := func(addr common.Address) *assets.Wei {
		return evmCfg.GasEstimator().PriceMax()
	}

	txKeyCoreKeystore := evmkeys.NewTxKeyCoreKeystore(keyStore)
	txmKeyStore := keys.NewStore(txKeyCoreKeystore)
	chainStore := keys.NewChainStore(txKeyCoreKeystore, chainID)
	attemptBuilder := txm.NewAttemptBuilder(priceMaxKey, estimator, chainStore, 0)

	return txm.NewTxm(
		lggr,
		chainID,
		txmClient,
		attemptBuilder,
		inMemoryStoreManager,
		nil, // stuckTxDetector
		txm.Config{
			EIP1559:   evmCfg.GasEstimator().EIP1559DynamicFees(),
			BlockTime: *evmCfg.Transactions().TransactionManagerV2().BlockTime(),
		},
		txmKeyStore,
		nil, // errorHandler
	)
}
