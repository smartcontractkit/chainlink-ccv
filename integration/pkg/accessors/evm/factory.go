package evm

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
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

// NewFactory creates an EVM AccessorFactory from caller-owned reader dependencies.
//
// Deprecated: standalone applications should use CreateAccessorFactory, which owns
// production chainlink-evm clients, head trackers, and transaction managers. This
// constructor remains available for integrations that inject their own read services;
// its accessors do not provide a ContractTransmitter.
func NewFactory(
	lggr logger.Logger,
	// TODO: use ethereum address instead of string
	onRampAddresses, rmnRemoteAddresses map[protocol.ChainSelector]string,
	headTrackers map[protocol.ChainSelector]heads.Tracker,
	chainClients map[protocol.ChainSelector]client.Client,
	destChainConfigs map[protocol.ChainSelector]chainaccess.DestinationChainConfig,
	executionVisibilityWindow time.Duration,
	rpcURLs map[protocol.ChainSelector]string,
) chainaccess.AccessorFactory {
	_ = rpcURLs // Kept in the deprecated signature for source compatibility.
	return newFactory(
		lggr,
		onRampAddresses,
		rmnRemoteAddresses,
		destChainConfigs,
		executionVisibilityWindow,
		func(_ context.Context, chainSelector protocol.ChainSelector, _ logger.Logger) (chainRuntime, error) {
			chainClient, ok := chainClients[chainSelector]
			if !ok || chainClient == nil {
				return nil, fmt.Errorf("chain client is not set for chain %d", chainSelector)
			}
			return &injectedReaderRuntime{
				chainClient: chainClient,
				headTracker: headTrackers[chainSelector],
			}, nil
		},
	)
}

// isValidAddress reports whether s is a non-empty hex address that is not the zero address.
func isValidAddress(s string) bool {
	return s != "" && common.HexToAddress(s) != (common.Address{})
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

	chainLggr := logger.With(f.lggr, "chainSelector", chainSelector)
	runtime, err := f.newRuntime(ctx, chainSelector, chainLggr)
	if err != nil {
		return nil, fmt.Errorf("failed to start EVM services for chain %d: %w", chainSelector, err)
	}

	// SourceReader is optional: if on-ramp or RMN-remote addresses are absent
	// (for example, executor-only config), the runtime can still provide the
	// destination reader and transmitter.
	var evmSourceReader chainaccess.SourceReader
	if isValidAddress(f.onRampAddresses[chainSelector]) && isValidAddress(f.rmnRemoteAddresses[chainSelector]) {
		headTracker := runtime.HeadTracker()
		if headTracker == nil {
			_ = runtime.Close()
			return nil, fmt.Errorf("head tracker is not set for chain %d", chainSelector)
		}
		sr, err := NewEVMSourceReader(
			runtime.ChainClient(),
			headTracker,
			common.HexToAddress(f.onRampAddresses[chainSelector]),
			common.HexToAddress(f.rmnRemoteAddresses[chainSelector]),
			onramp.OnRampCCIPMessageSent{}.Topic().Hex(),
			chainSelector,
			chainLggr,
			nil,
		)
		if err != nil {
			closeErr := runtime.Close()
			return nil, errors.Join(fmt.Errorf("failed to create EVM source reader: %w", err), closeErr)
		}
		evmSourceReader = sr
	}

	var evmDestReader chainaccess.DestinationReader
	var offRampAddr common.Address
	destCfg := f.destChainConfigs[chainSelector]
	if isValidAddress(destCfg.OffRampAddress) {
		offRampAddr = common.HexToAddress(destCfg.OffRampAddress)
		dr, err := destinationreader.NewEvmDestinationReader(destinationreader.Params{
			Lggr:                      chainLggr,
			ChainSelector:             chainSelector,
			ChainClient:               runtime.ChainClient(),
			OfframpAddress:            destCfg.OffRampAddress,
			RmnRemoteAddress:          destCfg.RmnAddress,
			ExecutionVisabilityWindow: f.executionVisibilityWindow,
			Monitoring:                monitoring.NewNoopExecutorMonitoring(),
		})
		if err != nil {
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
	return &accessor{
		lggr:                lggr,
		chainSelector:       chainSelector,
		runtime:             runtime,
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
	a.contractTransmitter = ct
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

// Close releases the production services owned by this accessor.
func (a *accessor) Close() error {
	if a == nil || a.runtime == nil {
		return nil
	}
	return a.runtime.Close()
}

// injectedReaderRuntime adapts the deprecated dependency-injection constructor
// without taking ownership of the caller's services.
type injectedReaderRuntime struct {
	chainClient client.Client
	headTracker heads.Tracker
}

func (r *injectedReaderRuntime) ChainClient() client.Client { return r.chainClient }
func (r *injectedReaderRuntime) HeadTracker() heads.Tracker { return r.headTracker }

func (r *injectedReaderRuntime) NewContractTransmitter(
	context.Context,
	protocol.ChainSelector,
	keystore.Keystore,
	string,
	common.Address,
) (chainaccess.ContractTransmitter, error) {
	// The deprecated injected runtime intentionally supports reads only. Treat
	// keystore injection as a no-op so KeystoreRegistry does not reject an
	// otherwise usable reader accessor; ContractTransmitter remains unavailable.
	return nil, nil
}

func (r *injectedReaderRuntime) Close() error { return nil }
