package evm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/onramp"
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

type factory struct {
	lggr logger.Logger

	// SourceReader dependencies.
	// TODO: put these in a single map.
	onRampAddresses    map[protocol.ChainSelector]string
	rmnRemoteAddresses map[protocol.ChainSelector]string
	headTrackers       map[protocol.ChainSelector]heads.Tracker
	chainClients       map[protocol.ChainSelector]client.Client

	// DestinationReader dependencies.
	destChainConfigs          map[protocol.ChainSelector]chainaccess.DestinationChainConfig
	executionVisibilityWindow time.Duration

	// ContractTransmitter dependencies.
	// rpcURLs holds the primary HTTP RPC URL for each chain. The contract transmitter dials its
	// own ethclient rather than sharing the multi-node client used by the readers.
	rpcURLs               map[protocol.ChainSelector]string
	transmitterPrivateKey string
}

// NewFactory creates a new EVM AccessorFactory.
// Head trackers and chain clients are injectable because different execution contexts may use different
// constructions / implementations of these objects.
func NewFactory(
	lggr logger.Logger,
	// TODO: use ethereum address instead of string
	onRampAddresses, rmnRemoteAddresses map[protocol.ChainSelector]string,
	headTrackers map[protocol.ChainSelector]heads.Tracker,
	chainClients map[protocol.ChainSelector]client.Client,
	destChainConfigs map[protocol.ChainSelector]chainaccess.DestinationChainConfig,
	executionVisibilityWindow time.Duration,
	rpcURLs map[protocol.ChainSelector]string,
	transmitterPrivateKey string,
) chainaccess.AccessorFactory {
	if executionVisibilityWindow == 0 {
		executionVisibilityWindow = defaultExecutionVisibilityWindow
	}
	return &factory{
		lggr:                      lggr,
		onRampAddresses:           onRampAddresses,
		rmnRemoteAddresses:        rmnRemoteAddresses,
		headTrackers:              headTrackers,
		chainClients:              chainClients,
		destChainConfigs:          destChainConfigs,
		executionVisibilityWindow: executionVisibilityWindow,
		rpcURLs:                   rpcURLs,
		transmitterPrivateKey:     transmitterPrivateKey,
	}
}

func appendErrorIfNil(errs []error, ob any, errStr string) []error {
	if ob == nil {
		errs = append(errs, errors.New(errStr))
	}
	return errs
}

func (f *factory) GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (chainaccess.Accessor, error) {
	var errs []error
	if f == nil {
		errs = append(errs, errors.New("evm accessor factory is nil"))
	} else {
		errs = appendErrorIfNil(errs, f.onRampAddresses, "onramp addresses are nil")
		errs = appendErrorIfNil(errs, f.rmnRemoteAddresses, "rmn remote addresses are nil")
		errs = appendErrorIfNil(errs, f.headTrackers, "head trackers are nil")
		errs = appendErrorIfNil(errs, f.chainClients, "chain clients are nil")
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("cannot get accessor for chain %d: %w", chainSelector, errors.Join(errs...))
	}

	family, err := chainsel.GetSelectorFamily(uint64(chainSelector))
	if err != nil {
		return nil, fmt.Errorf("failed to get selector family for %d - update chain-selectors library?: %w", chainSelector, err)
	}
	if family != chainsel.FamilyEVM {
		return nil, fmt.Errorf("skipping chain, only evm is supported for chain %d, family %s", chainSelector, family)
	}

	chainClient, ok := f.chainClients[chainSelector]
	if !ok {
		return nil, fmt.Errorf("chain client is not set for chain %d", chainSelector)
	}

	// SourceReader is optional: if on-ramp or RMN-remote addresses are absent (e.g. executor-only
	// config), we skip it rather than returning an error. DestinationReader and ContractTransmitter
	// can still be built from chain_configuration alone.
	var evmSourceReader chainaccess.SourceReader
	if f.onRampAddresses[chainSelector] != "" && f.rmnRemoteAddresses[chainSelector] != "" {
		headTracker, ok := f.headTrackers[chainSelector]
		if !ok {
			return nil, fmt.Errorf("head tracker is not set for chain %d", chainSelector)
		}
		sr, err := NewEVMSourceReader(
			chainClient,
			headTracker,
			common.HexToAddress(f.onRampAddresses[chainSelector]),
			common.HexToAddress(f.rmnRemoteAddresses[chainSelector]),
			onramp.OnRampCCIPMessageSent{}.Topic().Hex(),
			chainSelector,
			f.lggr,
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create EVM source reader: %w", err)
		}
		evmSourceReader = sr
	}

	var evmDestReader chainaccess.DestinationReader
	var offRampAddr common.Address
	var keyName string
	if destCfg, ok := f.destChainConfigs[chainSelector]; ok {
		keyName = destCfg.TransmitterKeyName
		if destCfg.OffRampAddress != "" {
			offRampAddr = common.HexToAddress(destCfg.OffRampAddress)
			dr, err := destinationreader.NewEvmDestinationReader(destinationreader.Params{
				Lggr:                      f.lggr,
				ChainSelector:             chainSelector,
				ChainClient:               chainClient,
				OfframpAddress:            destCfg.OffRampAddress,
				RmnRemoteAddress:          destCfg.RmnAddress,
				ExecutionVisabilityWindow: f.executionVisibilityWindow,
				Monitoring:                monitoring.NewNoopExecutorMonitoring(),
			})
			if err != nil {
				f.lggr.Warnw("Failed to create EVM destination reader, DestinationReader will be unavailable", "chainSelector", chainSelector, "error", err)
			} else {
				evmDestReader = dr
			}
		}
	}

	rpcURL := f.rpcURLs[chainSelector]
	evmContractTransmitter := f.newContractTransmitter(ctx, chainSelector)

	return newAccessor(f.lggr, chainSelector, rpcURL, offRampAddr, keyName, evmSourceReader, evmDestReader, evmContractTransmitter), nil
}

func (f *factory) newContractTransmitter(ctx context.Context, chainSelector protocol.ChainSelector) chainaccess.ContractTransmitter {
	destCfg, ok := f.destChainConfigs[chainSelector]
	if !ok || destCfg.OffRampAddress == "" || f.transmitterPrivateKey == "" {
		return nil
	}
	rpcURL, hasURL := f.rpcURLs[chainSelector]
	if !hasURL {
		f.lggr.Warnw("No RPC URL for chain, ContractTransmitter will be unavailable", "chainSelector", chainSelector)
		return nil
	}
	ct, err := contracttransmitter.NewEVMContractTransmitterFromRPC(
		ctx,
		f.lggr,
		chainSelector,
		rpcURL,
		f.transmitterPrivateKey,
		common.HexToAddress(destCfg.OffRampAddress),
	)
	if err != nil {
		f.lggr.Warnw("Failed to create EVM contract transmitter, ContractTransmitter will be unavailable", "chainSelector", chainSelector, "error", err)
		return nil
	}
	return ct
}

type accessor struct {
	sourceReader        chainaccess.SourceReader
	destinationReader   chainaccess.DestinationReader
	contractTransmitter chainaccess.ContractTransmitter

	// stored for lazy keystore transmitter construction via SetKeystore
	lggr          logger.Logger
	chainSelector protocol.ChainSelector
	rpcURL        string
	offRampAddr   common.Address
	keyName       string
}

func newAccessor(
	lggr logger.Logger,
	chainSelector protocol.ChainSelector,
	rpcURL string,
	offRampAddr common.Address,
	keyName string,
	sourceReader chainaccess.SourceReader,
	destinationReader chainaccess.DestinationReader,
	contractTransmitter chainaccess.ContractTransmitter,
) chainaccess.Accessor {
	return &accessor{
		lggr:                lggr,
		chainSelector:       chainSelector,
		rpcURL:              rpcURL,
		offRampAddr:         offRampAddr,
		keyName:             keyName,
		sourceReader:        sourceReader,
		destinationReader:   destinationReader,
		contractTransmitter: contractTransmitter,
	}
}

// SetKeystore builds and installs a keystore-backed ContractTransmitter, replacing any
// previously set transmitter (e.g. the env-var fallback). No-op when ks is nil,
// keyName is empty, or no RPC URL is available for this chain.
func (a *accessor) SetKeystore(ks keystore.Keystore) {
	if ks == nil || a.keyName == "" || a.rpcURL == "" {
		return
	}
	ct, err := contracttransmitter.NewEVMContractTransmitterFromKeystore(
		context.Background(),
		a.lggr,
		a.chainSelector,
		a.rpcURL,
		ks,
		a.keyName,
		a.offRampAddr,
	)
	if err != nil {
		a.lggr.Warnw("Failed to create keystore contract transmitter", "chainSelector", a.chainSelector, "error", err)
		return
	}
	a.contractTransmitter = ct
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
