package evm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/destinationreader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// defaultExecutionVisibilityWindow mirrors executor.maxRetryDurationDefault.
const defaultExecutionVisibilityWindow = 8 * time.Hour

type runtimeBuilder func(
	ctx context.Context,
	chainSelector protocol.ChainSelector,
	lggr logger.Logger,
) (chainRuntime, error)

// runtimeEntry is a shared chainRuntime and its live reference count. Runtimes are shared
// because a chain must have exactly one LogPoller per process: two would both poll the chain
// and write evm.log_poller_blocks for it.
type runtimeEntry struct {
	rt   chainRuntime
	refs int
}

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

	// mu guards runtimes
	mu       sync.Mutex
	runtimes map[protocol.ChainSelector]*runtimeEntry
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

// acquireRuntime returns the chain's runtime, building it on first use, and takes a reference.
// Every successful call must be paired with exactly one releaseRuntime. newRuntime runs with mu
// held, so chain startup is serialized, which matches the sequential accessor loops today.
func (f *factory) acquireRuntime(ctx context.Context, chainSelector protocol.ChainSelector, lggr logger.Logger) (chainRuntime, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if entry, ok := f.runtimes[chainSelector]; ok {
		entry.refs++
		return entry.rt, nil
	}

	runtime, err := f.newRuntime(ctx, chainSelector, lggr)
	if err != nil {
		return nil, fmt.Errorf("failed to start EVM services for chain %d: %w", chainSelector, err)
	}

	if runtime == nil {
		return nil, fmt.Errorf("failed to start EVM services for chain %d: runtime is nil", chainSelector)
	}

	if f.runtimes == nil {
		f.runtimes = make(map[protocol.ChainSelector]*runtimeEntry)
	}

	f.runtimes[chainSelector] = &runtimeEntry{rt: runtime, refs: 1}
	return runtime, nil
}

// releaseRuntime drops a reference and closes the runtime once the last one goes. Eviction and
// the decision to close happen under mu so a concurrent acquire cannot revive a dying entry;
// Close itself runs outside it, because it waits on orphan recovery and tears down RPCs.
func (f *factory) releaseRuntime(chainSelector protocol.ChainSelector) error {
	f.mu.Lock()

	entry, ok := f.runtimes[chainSelector]
	if !ok {
		f.mu.Unlock()
		f.lggr.Warnw("Released an EVM chain runtime that was not held; this is a refcount bug",
			"chainSelector", chainSelector)
		return nil
	}

	entry.refs--
	if entry.refs > 0 {
		f.mu.Unlock()
		return nil
	}

	delete(f.runtimes, chainSelector)
	f.mu.Unlock()

	return entry.rt.Close()
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
	runtime, err := f.acquireRuntime(ctx, chainSelector, chainLggr)
	if err != nil {
		return nil, err
	}
	chainClient, err := runtime.ChainClient()
	if err != nil {
		closeErr := f.releaseRuntime(chainSelector)
		return nil, errors.Join(fmt.Errorf("failed to get EVM chain client for chain %d: %w", chainSelector, err), closeErr)
	}
	if chainClient == nil {
		closeErr := f.releaseRuntime(chainSelector)
		return nil, errors.Join(fmt.Errorf("failed to get EVM chain client for chain %d: client is nil", chainSelector), closeErr)
	}

	// SourceReader is optional: if the on-ramp address is absent (for example,
	// executor-only config), the runtime can still provide the destination
	// reader and transmitter.
	var evmSourceReader chainaccess.SourceReader
	if hasSourceReaderConfig {
		headTracker, err := runtime.HeadTracker()
		if err != nil {
			closeErr := f.releaseRuntime(chainSelector)
			return nil, errors.Join(fmt.Errorf("failed to get EVM head tracker for chain %d: %w", chainSelector, err), closeErr)
		}
		if headTracker == nil {
			closeErr := f.releaseRuntime(chainSelector)
			return nil, errors.Join(fmt.Errorf("failed to get EVM head tracker for chain %d: tracker is nil", chainSelector), closeErr)
		}
		sr, err := NewEVMSourceReader(
			ctx,
			chainClient,
			headTracker,
			common.HexToAddress(onRampAddress),
			common.HexToAddress(rmnRemoteAddress),
			onramp.OnRampCCIPMessageSent{}.Topic().Hex(),
			chainSelector,
			chainLggr,
			runtime.SourceReaderHeaderFetchBatchSize(),
			nil,
		)
		if err != nil {
			closeErr := f.releaseRuntime(chainSelector)
			return nil, errors.Join(fmt.Errorf("failed to create EVM source reader: %w", err), closeErr)
		}
		evmSourceReader = sr
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
			if evmSourceReader == nil {
				closeErr := f.releaseRuntime(chainSelector)
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

	return newAccessor(
		chainLggr,
		chainSelector,
		runtime,
		func() error { return f.releaseRuntime(chainSelector) },
		offRampAddr,
		keyName,
		evmSourceReader,
		evmDestReader,
		nil,
	), nil
}

type accessor struct {
	sourceReader        chainaccess.SourceReader
	destinationReader   chainaccess.DestinationReader
	contractTransmitter chainaccess.ContractTransmitter

	lggr          logger.Logger
	chainSelector protocol.ChainSelector
	runtime       chainRuntime
	offRampAddr   common.Address
	keyName       string

	// closeOnce keeps Close idempotent: a second call must not drop a second reference.
	closeOnce sync.Once
	release   func() error
}

func newAccessor(
	lggr logger.Logger,
	chainSelector protocol.ChainSelector,
	runtime chainRuntime,
	release func() error,
	offRampAddr common.Address,
	keyName string,
	sourceReader chainaccess.SourceReader,
	destinationReader chainaccess.DestinationReader,
	contractTransmitter chainaccess.ContractTransmitter,
) chainaccess.Accessor {
	return &accessor{
		lggr:                lggr,
		chainSelector:       chainSelector,
		runtime:             runtime,
		release:             release,
		offRampAddr:         offRampAddr,
		keyName:             keyName,
		sourceReader:        sourceReader,
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

// SetDataSource gives the chain's LogPoller the database it needs, starts it, and hands it to
// the source reader. A chain with log_poller_mode off needs no poller and no database.
func (a *accessor) SetDataSource(ctx context.Context, ds sqlutil.DataSource) error {
	if a == nil {
		return errors.New("EVM accessor is nil")
	}
	if a.runtime == nil {
		return errors.New("EVM chain runtime is not available")
	}

	mode := a.runtime.LogPollerMode()
	if mode == evmconfig.LogPollerModeOff {
		return nil
	}
	if ds == nil {
		return fmt.Errorf("log_poller_mode %q requires a database for chain %d", mode, a.chainSelector)
	}

	lp, err := a.runtime.LogPoller(ctx, ds)
	if err != nil {
		return fmt.Errorf("failed to start EVM log poller for chain %d: %w", a.chainSelector, err)
	}

	// Destination-only accessors have no source reader, and a nil one fails the assertion too.
	attacher, ok := a.sourceReader.(logPollerAttacher)
	if !ok {
		return nil
	}
	if err := attacher.AttachLogPoller(ctx, lp, mode); err != nil {
		return fmt.Errorf("failed to attach the log poller for chain %d: %w", a.chainSelector, err)
	}
	return nil
}

func (a *accessor) SourceReader() (chainaccess.SourceReader, error) {
	if a == nil || a.sourceReader == nil {
		return nil, errors.New("source reader not available")
	}
	return a.sourceReader, nil
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

// Close drops this accessor's reference to the shared chain runtime. The runtime is torn down
// once the last accessor holding it closes.
func (a *accessor) Close() error {
	if a == nil || a.release == nil {
		return nil
	}

	var err error
	a.closeOnce.Do(func() { err = a.release() })
	return err
}
