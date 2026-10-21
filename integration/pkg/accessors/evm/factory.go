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
	"github.com/smartcontractkit/chainlink-ccv/common/lazy"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/destinationreader"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/pricereader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
)

// defaultExecutionVisibilityWindow mirrors executor.maxRetryDurationDefault.
const defaultExecutionVisibilityWindow = 8 * time.Hour

// defaultNativeDecimals is the number of decimals of the native token, unless a chain sets another number.
const defaultNativeDecimals = 18

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
	feeQuoterAddresses map[protocol.ChainSelector]string
	// nativeDecimals overrides the native token decimals of a chain. The default is 18.
	nativeDecimals map[protocol.ChainSelector]uint8

	executionVisibilityWindow time.Duration
	// readerStalenessThreshold overrides the destination reader's staleness default
	// (50 poll intervals) when set; zero keeps the default.
	readerStalenessThreshold time.Duration
	newRuntime               runtimeBuilder
	// db is the EVM database shared by every accessor; nil when none is configured.
	db *lazy.Lazy[*sql.DB]
}

func newFactory(
	lggr logger.Logger,
	onRampAddresses, rmnRemoteAddresses map[protocol.ChainSelector]string,
	destChainConfigs map[protocol.ChainSelector]chainaccess.DestinationChainConfig,
	feeQuoterAddresses map[protocol.ChainSelector]string,
	nativeDecimals map[protocol.ChainSelector]uint8,
	executionVisibilityWindow time.Duration,
	readerStalenessThreshold time.Duration,
	newRuntime runtimeBuilder,
) *factory {
	if executionVisibilityWindow == 0 {
		executionVisibilityWindow = defaultExecutionVisibilityWindow
	}
	return &factory{
		lggr:                      lggr,
		onRampAddresses:           onRampAddresses,
		rmnRemoteAddresses:        rmnRemoteAddresses,
		destChainConfigs:          destChainConfigs,
		feeQuoterAddresses:        feeQuoterAddresses,
		nativeDecimals:            nativeDecimals,
		executionVisibilityWindow: executionVisibilityWindow,
		readerStalenessThreshold:  readerStalenessThreshold,
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
	feeQuoterAddress := f.feeQuoterAddresses[chainSelector]
	hasPricerConfig := isValidAddress(feeQuoterAddress)
	if feeQuoterAddress != "" && !hasPricerConfig {
		return nil, fmt.Errorf("cannot get accessor for chain %d: invalid fee quoter address %q", chainSelector, feeQuoterAddress)
	}
	// Only the gas price reader uses the decimals, so other services ignore this setting.
	nativeDecimals := uint8(defaultNativeDecimals)
	if configured, ok := f.nativeDecimals[chainSelector]; ok && hasPricerConfig {
		if configured > pricereader.MaxNativeTokenDecimals {
			return nil, fmt.Errorf(
				"cannot get accessor for chain %d: invalid native token decimals %d, the maximum is %d",
				chainSelector, configured, pricereader.MaxNativeTokenDecimals,
			)
		}
		nativeDecimals = configured
	}
	if !hasSourceReaderConfig && !hasDestinationConfig && !hasPricerConfig {
		return nil, fmt.Errorf(
			"cannot get accessor for chain %d: no source, destination or pricer services are configured",
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
			ReaderStalenessThreshold:  f.readerStalenessThreshold,
			Monitoring:                monitoring.NewNoopExecutorMonitoring(),
		})
		if err != nil {
			if sourceParams == nil && !hasPricerConfig {
				closeErr := runtime.Close()
				return nil, errors.Join(fmt.Errorf("failed to create EVM destination reader: %w", err), closeErr)
			}
			chainLggr.Warnw("Failed to create EVM destination reader, DestinationReader will be unavailable", "error", err)
		} else {
			evmDestReader = dr
		}
	}

	// The fee quoter services and the gas price reader are optional. They exist only with a fee quoter address.
	var feeQuoterReader *pricereader.EVMFeeQuoterReader
	var feeQuoterWriter chainaccess.FeeQuoterWriter
	var gasPriceReader chainaccess.GasPriceReader
	if hasPricerConfig {
		feeQuoterWriter = pricereader.NewLoggingFeeQuoterWriter(chainLggr, common.HexToAddress(feeQuoterAddress))
		daOracle := func(ctx context.Context) (pricereader.DAGasPriceOracle, error) {
			oracle, err := runtime.DAGasPriceOracle(ctx)
			// A nil L1Oracle must become a plain nil, so that the reader sees no oracle.
			if err != nil || oracle == nil {
				return nil, err
			}
			return oracle, nil
		}
		var err error
		if gasPriceReader, err = pricereader.NewEVMGasPriceReader(chainClient, daOracle, nativeDecimals); err != nil {
			closeErr := runtime.Close()
			return nil, errors.Join(fmt.Errorf("failed to create EVM gas price reader for chain %d: %w", chainSelector, err), closeErr)
		}
		if feeQuoterReader, err = pricereader.NewEVMFeeQuoterReader(common.HexToAddress(feeQuoterAddress), chainClient, nil); err != nil {
			closeErr := runtime.Close()
			return nil, errors.Join(fmt.Errorf("failed to create EVM fee quoter reader for chain %d: %w", chainSelector, err), closeErr)
		}
	}

	keyName := contracttransmitter.DefaultKeyName
	if destCfg.TransmitterKeyName != "" {
		keyName = destCfg.TransmitterKeyName
	}

	acc := buildAccessor(
		chainLggr,
		chainSelector,
		runtime,
		offRampAddr,
		keyName,
		nil,
		evmDestReader,
		nil,
		feeQuoterReader,
		feeQuoterWriter,
		gasPriceReader,
	)
	acc.sourceParams = sourceParams
	acc.db = f.db
	return acc, nil
}

type accessor struct {
	destinationReader   chainaccess.DestinationReader
	contractTransmitter chainaccess.ContractTransmitter
	feeQuoterReader     *pricereader.EVMFeeQuoterReader
	feeQuoterWriter     chainaccess.FeeQuoterWriter
	gasPriceReader      chainaccess.GasPriceReader

	// serviceAddressesErr is the last failure to load the transmitter addresses for the fee quoter reader.
	mu                  sync.Mutex
	serviceAddressesErr error

	// sourceMu guards the lazily built source reader and the dependencies that select it.
	// sourceParams is nil for an accessor with no source config, such as the executor's.
	sourceMu     sync.Mutex
	sourceParams *SourceReaderParams
	sourceReader chainaccess.SourceReader
	sourceErr    error
	sourceBuilt  bool
	// logPoller is set only by a successful SetSourceReaderDeps and selects the LogPoller reader.
	logPoller      logpoller.LogPoller
	db             *lazy.Lazy[*sql.DB]
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
	feeQuoterReader *pricereader.EVMFeeQuoterReader,
	feeQuoterWriter chainaccess.FeeQuoterWriter,
	gasPriceReader chainaccess.GasPriceReader,
) chainaccess.Accessor {
	return buildAccessor(lggr, chainSelector, runtime, offRampAddr, keyName, sourceReader, destinationReader,
		contractTransmitter, feeQuoterReader, feeQuoterWriter, gasPriceReader)
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
	feeQuoterReader *pricereader.EVMFeeQuoterReader,
	feeQuoterWriter chainaccess.FeeQuoterWriter,
	gasPriceReader chainaccess.GasPriceReader,
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
		feeQuoterReader:     feeQuoterReader,
		feeQuoterWriter:     feeQuoterWriter,
		gasPriceReader:      gasPriceReader,
	}
}

// SetKeystore builds and starts chainlink-evm's transaction manager for a
// destination accessor. Source-only accessors do not need signing services.
func (a *accessor) SetKeystore(ctx context.Context, ks keystore.Keystore) error {
	if a == nil {
		return errors.New("EVM accessor is nil")
	}
	a.setFeeQuoterServiceAddresses(ctx, ks)
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
			// SetSourceReaderDeps already connected, so this returns the cached database.
			db, dbErr := a.evmDB(ctx)
			if dbErr != nil || db == nil {
				a.sourceErr = errors.Join(dbErr, errors.New("EVM database is not available"))
			} else {
				cfg := NewLogPollerConfig(a.logPoller, a.newORM(lpRuntime, db), a.lpVerifierID)
				a.sourceReader, a.sourceErr = NewLogPollerSourceReader(ctx, *a.sourceParams, cfg)
			}
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

// setFeeQuoterServiceAddresses gives the fee quoter reader the transmitter addresses.
// A missing key is not fatal, but Degraded reports it until a later call succeeds.
func (a *accessor) setFeeQuoterServiceAddresses(ctx context.Context, ks keystore.Keystore) {
	if a.feeQuoterReader == nil || a.runtime == nil {
		return
	}
	addresses, err := a.runtime.TransmitterAddresses(ctx, ks, a.keyName)
	if err != nil {
		err = fmt.Errorf("fee quoter reader for chain %d has no transmitter addresses, so the service is reported as not authorized: %w", a.chainSelector, err)
		a.lggr.Warnw("Could not load the transmitter addresses", "error", err)
	} else {
		a.feeQuoterReader.SetServiceAddresses(addresses)
	}
	a.mu.Lock()
	a.serviceAddressesErr = err
	a.mu.Unlock()
}

// The accessor is a health.DegradedReporter. The interface is not imported to keep the health package out.
var _ interface{ Degraded() error } = (*accessor)(nil)

// Degraded returns an error when a configured service works only in part. The accessor stays usable.
func (a *accessor) Degraded() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.serviceAddressesErr
}

func (a *accessor) FeeQuoterReader() (chainaccess.FeeQuoterReader, error) {
	if a == nil || a.feeQuoterReader == nil {
		return nil, errors.New("fee quoter reader not available")
	}
	return a.feeQuoterReader, nil
}

// FeeQuoterWriter returns a writer that only logs the updates. It does not send transactions yet.
func (a *accessor) FeeQuoterWriter() (chainaccess.FeeQuoterWriter, error) {
	if a == nil || a.feeQuoterWriter == nil {
		return nil, errors.New("fee quoter writer not available")
	}
	return a.feeQuoterWriter, nil
}

func (a *accessor) GasPriceReader() (chainaccess.GasPriceReader, error) {
	if a == nil || a.gasPriceReader == nil {
		return nil, errors.New("gas price reader not available")
	}
	return a.gasPriceReader, nil
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
