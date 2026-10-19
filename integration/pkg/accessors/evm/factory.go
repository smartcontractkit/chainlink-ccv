package evm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/destinationreader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
)

// defaultExecutionVisibilityWindow mirrors executor.maxRetryDurationDefault.
const defaultExecutionVisibilityWindow = 8 * time.Hour

type runtimeBuilder func(
	ctx context.Context,
	chainSelector protocol.ChainSelector,
	lggr logger.Logger,
) (chainRuntime, error)

type factory struct {
	lggr logger.Logger

	// rmnRemoteAddresses carries the deprecated configured RMN Remote addresses, passed to the
	// readers only so they can warn when a configured value disagrees with the address derived
	// from the ramp's on-chain static config. It is not required.
	onRampAddresses    map[protocol.ChainSelector]string
	rmnRemoteAddresses map[protocol.ChainSelector]string
	destChainConfigs   map[protocol.ChainSelector]chainaccess.DestinationChainConfig

	executionVisibilityWindow time.Duration
	newRuntime                runtimeBuilder
}

func newFactory(
	lggr logger.Logger,
	onRampAddresses, rmnRemoteAddresses map[protocol.ChainSelector]string,
	destChainConfigs map[protocol.ChainSelector]chainaccess.DestinationChainConfig,
	executionVisibilityWindow time.Duration,
	newRuntime runtimeBuilder,
) chainaccess.AccessorFactory {
	if executionVisibilityWindow == 0 {
		executionVisibilityWindow = defaultExecutionVisibilityWindow
	}
	return &factory{
		lggr:                      lggr,
		onRampAddresses:           onRampAddresses,
		rmnRemoteAddresses:        rmnRemoteAddresses,
		destChainConfigs:          destChainConfigs,
		executionVisibilityWindow: executionVisibilityWindow,
		newRuntime:                newRuntime,
	}
}

// isValidAddress reports whether s is a non-empty hex address that is not the zero address.
func isValidAddress(s string) bool {
	return common.IsHexAddress(s) && common.HexToAddress(s) != (common.Address{})
}

func (f *factory) GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (chainaccess.Accessor, error) {
	if f == nil {
		return nil, fmt.Errorf("cannot get accessor for chain %d: EVM accessor factory is nil", chainSelector)
	}
	if f.newRuntime == nil {
		return nil, fmt.Errorf("cannot get accessor for chain %d: EVM runtime builder is nil", chainSelector)
	}

	family, err := chainsel.GetSelectorFamily(uint64(chainSelector))
	if err != nil {
		return nil, fmt.Errorf("failed to get selector family for %d - update chain-selectors library?: %w", chainSelector, err)
	}
	if family != chainsel.FamilyEVM {
		return nil, fmt.Errorf("skipping chain, only evm is supported for chain %d, family %s", chainSelector, family)
	}

	onRampAddress := f.onRampAddresses[chainSelector]
	rmnRemoteAddress := f.rmnRemoteAddresses[chainSelector]
	destCfg := f.destChainConfigs[chainSelector]
	hasSourceReaderConfig := isValidAddress(onRampAddress)
	// A configured rmn_address without an off-ramp address signals destination intent too: it
	// fails the gate below rather than being silently ignored, since rmn_address on its own
	// cannot construct destination services.
	hasAnyDestinationConfig := destCfg.OffRampAddress != "" || destCfg.RmnAddress != ""
	hasDestinationConfig := isValidAddress(destCfg.OffRampAddress)
	if hasAnyDestinationConfig && !hasDestinationConfig {
		return nil, fmt.Errorf(
			"cannot get accessor for chain %d: destination services require a valid non-zero off-ramp address",
			chainSelector,
		)
	}
	if !hasSourceReaderConfig && !hasDestinationConfig {
		return nil, fmt.Errorf(
			"cannot get accessor for chain %d: neither source nor destination services are configured",
			chainSelector,
		)
	}

	chainLggr := logger.With(f.lggr, "chainSelector", chainSelector)
	runtime, err := f.newRuntime(ctx, chainSelector, chainLggr)
	if err != nil {
		return nil, fmt.Errorf("failed to start EVM services for chain %d: %w", chainSelector, err)
	}
	if runtime == nil {
		return nil, fmt.Errorf("failed to start EVM services for chain %d: runtime is nil", chainSelector)
	}
	chainClient, err := runtime.ChainClient()
	if err != nil {
		closeErr := runtime.Close()
		return nil, errors.Join(fmt.Errorf("failed to get EVM chain client for chain %d: %w", chainSelector, err), closeErr)
	}
	if chainClient == nil {
		closeErr := runtime.Close()
		return nil, errors.Join(fmt.Errorf("failed to get EVM chain client for chain %d: client is nil", chainSelector), closeErr)
	}

	// SourceReader is optional: if the on-ramp address is absent (for example,
	// executor-only config), the runtime can still provide the destination
	// reader and transmitter. The reader itself is built on the first SourceReader call, so
	// a caller that selects the LogPoller reader never builds the RPC one.
	var sourceParams *SourceReaderParams
	if hasSourceReaderConfig {
		headTracker, err := runtime.HeadTracker()
		if err != nil {
			closeErr := runtime.Close()
			return nil, errors.Join(fmt.Errorf("failed to get EVM head tracker for chain %d: %w", chainSelector, err), closeErr)
		}
		if headTracker == nil {
			closeErr := runtime.Close()
			return nil, errors.Join(fmt.Errorf("failed to get EVM head tracker for chain %d: tracker is nil", chainSelector), closeErr)
		}
		sourceParams = &SourceReaderParams{
			ChainClient:                chainClient,
			HeadTracker:                headTracker,
			OnRampAddress:              common.HexToAddress(onRampAddress),
			ConfiguredRMNRemoteAddress: common.HexToAddress(rmnRemoteAddress),
			CCIPMessageSentTopic:       onramp.OnRampCCIPMessageSent{}.Topic().Hex(),
			ChainSelector:              chainSelector,
			Logger:                     chainLggr,
			HeaderFetchBatchSize:       runtime.SourceReaderHeaderFetchBatchSize(),
		}
	}

	var evmDestReader chainaccess.DestinationReader
	var offRampAddr common.Address
	if hasDestinationConfig {
		offRampAddr = common.HexToAddress(destCfg.OffRampAddress)
		dr, err := destinationreader.NewEvmDestinationReader(ctx, destinationreader.Params{
			Lggr:                      chainLggr,
			ChainSelector:             chainSelector,
			ChainClient:               chainClient,
			OfframpAddress:            destCfg.OffRampAddress,
			RmnRemoteAddress:          destCfg.RmnAddress,
			ExecutionVisabilityWindow: f.executionVisibilityWindow,
			Monitoring:                monitoring.NewNoopExecutorMonitoring(),
		})
		if err != nil {
			if sourceParams == nil {
				closeErr := runtime.Close()
				return nil, errors.Join(fmt.Errorf("failed to create EVM destination reader: %w", err), closeErr)
			}
			chainLggr.Warnw("Failed to create EVM destination reader, DestinationReader will be unavailable", "error", err)
		} else {
			evmDestReader = dr
		}
	}

	keyName := contracttransmitter.DefaultKeyName
	if destCfg.TransmitterKeyName != "" {
		keyName = destCfg.TransmitterKeyName
	}

	acc := buildAccessor(chainLggr, chainSelector, runtime, offRampAddr, keyName, nil, evmDestReader, nil)
	acc.sourceParams = sourceParams
	return acc, nil
}

type accessor struct {
	destinationReader   chainaccess.DestinationReader
	contractTransmitter chainaccess.ContractTransmitter

	// sourceMu guards the lazily built source reader and the dependencies that select it.
	// sourceParams is nil for an accessor with no source config, such as the executor's.
	sourceMu     sync.Mutex
	sourceParams *SourceReaderParams
	sourceReader chainaccess.SourceReader
	sourceErr    error
	sourceBuilt  bool
	// logPoller is set only by a successful SetSourceReaderDeps and selects the LogPoller reader.
	logPoller      logpoller.LogPoller
	lpDB           *sql.DB
	lpVerifierID   string
	cancelLifetime context.CancelFunc

	lggr          logger.Logger
	chainSelector protocol.ChainSelector
	runtime       chainRuntime
	offRampAddr   common.Address
	keyName       string
}

func newAccessor(
	lggr logger.Logger,
	chainSelector protocol.ChainSelector,
	runtime chainRuntime,
	offRampAddr common.Address,
	keyName string,
	sourceReader chainaccess.SourceReader,
	destinationReader chainaccess.DestinationReader,
	contractTransmitter chainaccess.ContractTransmitter,
) chainaccess.Accessor {
	return buildAccessor(lggr, chainSelector, runtime, offRampAddr, keyName, sourceReader, destinationReader, contractTransmitter)
}

func buildAccessor(
	lggr logger.Logger,
	chainSelector protocol.ChainSelector,
	runtime chainRuntime,
	offRampAddr common.Address,
	keyName string,
	sourceReader chainaccess.SourceReader,
	destinationReader chainaccess.DestinationReader,
	contractTransmitter chainaccess.ContractTransmitter,
) *accessor {
	return &accessor{
		lggr:                lggr,
		chainSelector:       chainSelector,
		runtime:             runtime,
		offRampAddr:         offRampAddr,
		keyName:             keyName,
		sourceReader:        sourceReader,
		sourceBuilt:         sourceReader != nil,
		destinationReader:   destinationReader,
		contractTransmitter: contractTransmitter,
	}
}

// SetKeystore builds and starts chainlink-evm's transaction manager for a
// destination accessor. Source-only accessors do not need signing services.
func (a *accessor) SetKeystore(ctx context.Context, ks keystore.Keystore) error {
	if a == nil {
		return errors.New("EVM accessor is nil")
	}
	if a.offRampAddr == (common.Address{}) {
		return nil
	}
	if a.runtime == nil {
		return errors.New("EVM chain runtime is not available")
	}
	ct, err := a.runtime.NewContractTransmitter(ctx, a.chainSelector, ks, a.keyName, a.offRampAddr)
	if err != nil {
		return fmt.Errorf("failed to start EVM contract transmitter for chain %d: %w", a.chainSelector, err)
	}
	if ct == nil {
		return fmt.Errorf("failed to start EVM contract transmitter for chain %d: transmitter is nil", a.chainSelector)
	}
	a.contractTransmitter = ct
	return nil
}

// SourceReader builds the reader on the first call and returns the same result afterwards: the
// LogPoller reader if SetSourceReaderDeps succeeded, the RPC reader otherwise.
func (a *accessor) SourceReader() (chainaccess.SourceReader, error) {
	if a == nil {
		return nil, errors.New("source reader not available")
	}
	a.sourceMu.Lock()
	defer a.sourceMu.Unlock()

	if a.sourceBuilt {
		return a.sourceReader, a.sourceErr
	}
	if a.sourceParams == nil {
		return nil, errors.New("source reader not available")
	}
	a.sourceBuilt = true
	// The constructors take a ctx but do no I/O with it.
	ctx := context.Background()
	if a.logPoller != nil {
		// logPoller is only set by SetSourceReaderDeps, which required a logPollerRuntime.
		if lpRuntime, ok := a.runtime.(logPollerRuntime); ok {
			cfg := NewLogPollerConfig(a.logPoller, a.newORM(lpRuntime, a.lpDB), a.lpVerifierID)
			a.sourceReader, a.sourceErr = NewLogPollerSourceReader(ctx, *a.sourceParams, cfg)
		} else {
			a.sourceErr = errors.New("EVM chain runtime cannot host a LogPoller")
		}
	} else {
		a.sourceReader, a.sourceErr = NewEVMSourceReader(ctx, *a.sourceParams)
	}
	if a.sourceErr != nil {
		a.sourceReader = nil
		a.sourceErr = fmt.Errorf("failed to create EVM source reader: %w", a.sourceErr)
	}
	return a.sourceReader, a.sourceErr
}

func (a *accessor) DestinationReader() (chainaccess.DestinationReader, error) {
	if a == nil || a.destinationReader == nil {
		return nil, errors.New("destination reader not available")
	}
	return a.destinationReader, nil
}

func (a *accessor) ContractTransmitter() (chainaccess.ContractTransmitter, error) {
	if a == nil || a.contractTransmitter == nil {
		return nil, errors.New("contract transmitter not available")
	}
	return a.contractTransmitter, nil
}

func (a *accessor) FeeQuoter() (chainaccess.FeeQuoter, error) {
	return nil, errors.New("fee quoter not available")
}

func (a *accessor) GasPriceReader() (chainaccess.GasPriceReader, error) {
	return nil, errors.New("gas price reader not available")
}

// Close releases the production services owned by this accessor.
func (a *accessor) Close() error {
	if a == nil || a.runtime == nil {
		return nil
	}
	a.sourceMu.Lock()
	cancel := a.cancelLifetime
	a.sourceMu.Unlock()
	if cancel != nil {
		cancel()
	}
	return a.runtime.Close()
}
