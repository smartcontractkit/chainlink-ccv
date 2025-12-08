package evm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/burn_mint_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/fee_quoter"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/lock_release_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/sequences/tokens"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/onramp"
	burnminterc677ops "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/burn_mint_erc677"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/link"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/weth"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/token_admin_registry"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/changesets"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/burn_mint_erc677"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/erc20"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"

	chainsel "github.com/smartcontractkit/chain-selectors"
	evmadapters "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/adapters"
	evmchangesets "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/changesets"
	offrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/offramp"
	onrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/onramp"
	feequoterwrapper "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/fee_quoter"
	routeroperations "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	routerwrapper "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_2_0/router"
	tokenscore "github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	changesetscore "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
)

const (
	// These qualifiers are used to distinguish between multiple deployments of the committee verifier proxy and mock receiver
	// on the same chain.
	// In the smoke test deployments these are the qualifiers that are used by default.
	DefaultCommitteeVerifierQualifier = "default"
	DefaultReceiverQualifier          = "default"

	SecondaryCommitteeVerifierQualifier = "secondary"
	SecondaryReceiverQualifier          = "secondary"

	TertiaryCommitteeVerifierQualifier = "tertiary"
	TertiaryReceiverQualifier          = "tertiary"

	QuaternaryReceiverQualifier = "quaternary"

	CommitteeVerifierGasForVerification = 500_000

	TokenMaxSupply       = "100000000000000000000000000000" // 100 billion in 18 decimals
	TokenDeployerBalance = "1000000000000000000000000000"   // 1 billion in 18 decimals
	DefaultDecimals      = 18
)

var (
	ccipMessageSentTopic = onramp.OnRampCCIPMessageSent{}.Topic()

	tokenPoolVersions = []string{
		"1.6.1",
		"1.7.0",
	}
)

// TokenCombination represents a source and destination pool combination.
type TokenCombination struct {
	sourcePoolType          string
	sourcePoolVersion       string
	sourcePoolCCVQualifiers []string
	destPoolType            string
	destPoolVersion         string
	destPoolCCVQualifiers   []string
	expectedReceiptIssuers  int
	expectedVerifierResults int
}

// SourcePoolAddressRef returns the address ref for the source token pool that can be used to query the datastore.
func (s TokenCombination) SourcePoolAddressRef() datastore.AddressRef {
	return datastore.AddressRef{
		Type:      datastore.ContractType(s.sourcePoolType),
		Version:   semver.MustParse(s.sourcePoolVersion),
		Qualifier: fmt.Sprintf("TEST (%s %s %v to %s %s %v)", s.sourcePoolType, s.sourcePoolVersion, s.sourcePoolCCVQualifiers, s.destPoolType, s.destPoolVersion, s.destPoolCCVQualifiers),
	}
}

// DestPoolAddressRef returns the address ref for the destination token pool that can be used to query the datastore.
func (s TokenCombination) DestPoolAddressRef() datastore.AddressRef {
	return datastore.AddressRef{
		Type:      datastore.ContractType(s.destPoolType),
		Version:   semver.MustParse(s.destPoolVersion),
		Qualifier: fmt.Sprintf("TEST (%s %s %v to %s %s %v)", s.destPoolType, s.destPoolVersion, s.destPoolCCVQualifiers, s.sourcePoolType, s.sourcePoolVersion, s.sourcePoolCCVQualifiers),
	}
}

// SourcePoolCCVQualifiers returns the CCV qualifiers for the source token pool.
func (s TokenCombination) SourcePoolCCVQualifiers() []string {
	return s.sourcePoolCCVQualifiers
}

// DestPoolCCVQualifiers returns the CCV qualifiers for the destination token pool.
func (s TokenCombination) DestPoolCCVQualifiers() []string {
	return s.destPoolCCVQualifiers
}

// ExpectedReceiptIssuers returns the expected number of receipt issuers for the token combination.
func (s TokenCombination) ExpectedReceiptIssuers() int {
	return s.expectedReceiptIssuers
}

// ExpectedVerifierResults returns the expected number of verifier results for the token combination.
func (s TokenCombination) ExpectedVerifierResults() int {
	return s.expectedVerifierResults
}

func (s TokenCombination) FinalityConfig() uint16 {
	if semver.MustParse(s.sourcePoolVersion).GreaterThanEqual(semver.MustParse("1.7.0")) {
		return 1 // We can use fast-finality if source pool is 1.7.0 or higher
	}
	return 0 // Otherwise use default finality
}

// allTokenCombinations returns all possible token combinations.
func AllTokenCombinations() []TokenCombination {
	return []TokenCombination{
		{ // 1.6.1 burn -> 1.6.1 mint
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "1.6.1",
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "1.6.1",
			expectedReceiptIssuers:  3, // default CCV, token pool, executor
			expectedVerifierResults: 1, // default CCV
		},
		// TODO: Re-enable when chainlink-ccip repo adds ERC20LockBox deployment support
		// { // 1.7.0 lock -> 1.7.0 release
		// 	sourcePoolType:          string(lock_release_token_pool.ContractType),
		// 	sourcePoolVersion:       "1.7.0",
		// 	sourcePoolCCVQualifiers: []string{DefaultCommitteeVerifierQualifier},
		// 	destPoolType:            string(lock_release_token_pool.ContractType),
		// 	destPoolVersion:         "1.7.0",
		// 	destPoolCCVQualifiers:   []string{DefaultCommitteeVerifierQualifier},
		// 	expectedReceiptIssuers:  3, // default CCV, token pool, executor
		// 	expectedVerifierResults: 1, // default CCV
		// },
		{ // 1.7.0 burn -> 1.7.0 mint
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "1.7.0",
			sourcePoolCCVQualifiers: []string{DefaultCommitteeVerifierQualifier},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "1.7.0",
			destPoolCCVQualifiers:   []string{DefaultCommitteeVerifierQualifier},
			expectedReceiptIssuers:  3, // default CCV, token pool, executor
			expectedVerifierResults: 1, // default CCV
		},
		{ // 1.6.1 burn -> 1.7.0 mint
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "1.6.1",
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "1.7.0",
			destPoolCCVQualifiers:   []string{DefaultCommitteeVerifierQualifier},
			expectedReceiptIssuers:  3, // default CCV, token pool, executor
			expectedVerifierResults: 1, // default CCV
		},
		{ // 1.7.0 burn -> 1.6.1 mint
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "1.7.0",
			sourcePoolCCVQualifiers: []string{DefaultCommitteeVerifierQualifier},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "1.6.1",
			expectedReceiptIssuers:  3, // default CCV, token pool, executor
			expectedVerifierResults: 1, // default CCV
		},
		{ // 1.7.0 burn -> 1.7.0 mint (Default and Secondary CCV)
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "1.7.0",
			sourcePoolCCVQualifiers: []string{DefaultCommitteeVerifierQualifier, SecondaryCommitteeVerifierQualifier},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "1.7.0",
			destPoolCCVQualifiers:   []string{DefaultCommitteeVerifierQualifier, SecondaryCommitteeVerifierQualifier},
			expectedReceiptIssuers:  4, // default CCV, secondary CCV, token pool, executor
			expectedVerifierResults: 2, // default CCV, secondary CCV
		},
		{ // 1.7.0 burn -> 1.7.0 mint (No CCV)
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "1.7.0",
			sourcePoolCCVQualifiers: []string{},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "1.7.0",
			destPoolCCVQualifiers:   []string{},
			expectedReceiptIssuers:  3, // default CCV, token pool, executor
			expectedVerifierResults: 1, // default CCV
		},
		{ // 1.7.0 burn -> 1.7.0 mint (Secondary CCV)
			sourcePoolType:          string(burn_mint_token_pool.ContractType),
			sourcePoolVersion:       "1.7.0",
			sourcePoolCCVQualifiers: []string{SecondaryCommitteeVerifierQualifier},
			destPoolType:            string(burn_mint_token_pool.ContractType),
			destPoolVersion:         "1.7.0",
			destPoolCCVQualifiers:   []string{SecondaryCommitteeVerifierQualifier},
			expectedReceiptIssuers:  4, // default CCV, secondary CCV, token pool, executor
			expectedVerifierResults: 2, // default CCV, secondary CCV
		},
	}
}

func All17TokenCombinations() []TokenCombination {
	combinations := []TokenCombination{}
	for _, tc := range AllTokenCombinations() {
		if semver.MustParse(tc.sourcePoolVersion).Equal(semver.MustParse("1.7.0")) && semver.MustParse(tc.destPoolVersion).Equal(semver.MustParse("1.7.0")) {
			combinations = append(combinations, tc)
		}
	}
	return combinations
}

type CCIP17EVM struct {
	e             *deployment.Environment
	ds            datastore.DataStore
	chain         evm.Chain
	logger        zerolog.Logger
	chainDetails  chainsel.ChainDetails
	ethClient     *ethclient.Client
	onRamp        *onramp.OnRamp
	offRamp       *offramp.OffRamp
	offRampPoller *eventPoller[cciptestinterfaces.ExecutionStateChangedEvent]
	onRampPoller  *eventPoller[cciptestinterfaces.MessageSentEvent]
	pollersMu     sync.Mutex
}

// NewEmptyCCIP17EVM creates a new CCIP17EVM with a logger that logs to the console.
func NewEmptyCCIP17EVM() *CCIP17EVM {
	return &CCIP17EVM{
		logger: log.
			Output(zerolog.ConsoleWriter{Out: os.Stderr}).
			Level(zerolog.DebugLevel).
			With().
			Fields(map[string]any{"component": "CCIP17EVM"}).
			Logger(),
	}
}

// NewCCIP17EVM creates new smart-contracts wrappers with utility functions for CCIP17EVM implementation.
func NewCCIP17EVM(ctx context.Context, logger zerolog.Logger, e *deployment.Environment, chainID, wsURL string) (*CCIP17EVM, error) {
	gas := &GasSettings{
		FeeCapMultiplier: 2,
		TipCapMultiplier: 2,
	}
	var (
		chainDetails  chainsel.ChainDetails
		ethClient     *ethclient.Client
		onRamp        *onramp.OnRamp
		offRamp       *offramp.OffRamp
		offRampPoller eventPoller[cciptestinterfaces.ExecutionStateChangedEvent]
		onRampPoller  eventPoller[cciptestinterfaces.MessageSentEvent]
	)
	chainDetails, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
	if err != nil {
		return nil, fmt.Errorf("get chain details for chain %s: %w", chainID, err)
	}

	client, _, _, err := ETHClient(ctx, wsURL, gas)
	if err != nil {
		return nil, fmt.Errorf("create eth client for chain %s: %w", chainID, err)
	}
	ethClient = client

	onRampAddressRef, err := e.DataStore.Addresses().Get(datastore.NewAddressRefKey(
		chainDetails.ChainSelector,
		datastore.ContractType(onrampoperations.ContractType),
		semver.MustParse(onrampoperations.Deploy.Version()),
		"",
	))
	if err != nil {
		return nil, fmt.Errorf("get on ramp address for chain %d (id %s) from datastore: %w", chainDetails.ChainSelector, chainID, err)
	}
	offRampAddressRef, err := e.DataStore.Addresses().Get(datastore.NewAddressRefKey(
		chainDetails.ChainSelector,
		datastore.ContractType(offrampoperations.ContractType),
		semver.MustParse(offrampoperations.Deploy.Version()),
		"",
	))
	if err != nil {
		return nil, fmt.Errorf("get off ramp address for chain %d (id %s) from datastore: %w", chainDetails.ChainSelector, chainID, err)
	}
	onRamp, err = onramp.NewOnRamp(common.HexToAddress(onRampAddressRef.Address), client)
	if err != nil {
		return nil, fmt.Errorf("create on ramp wrapper for chain %d (id %s): %w", chainDetails.ChainSelector, chainID, err)
	}
	offRamp, err = offramp.NewOffRamp(common.HexToAddress(offRampAddressRef.Address), client)
	if err != nil {
		return nil, fmt.Errorf("create off ramp wrapper for chain %d (id %s): %w", chainDetails.ChainSelector, chainID, err)
	}

	return &CCIP17EVM{
		e:             e,
		ds:            e.DataStore,
		chain:         e.BlockChains.EVMChains()[chainDetails.ChainSelector],
		logger:        logger,
		chainDetails:  chainDetails,
		ethClient:     ethClient,
		onRamp:        onRamp,
		offRamp:       offRamp,
		offRampPoller: &offRampPoller,
		onRampPoller:  &onRampPoller,
	}, nil
}

func (m *CCIP17EVM) getOrCreateOnRampPoller() (*eventPoller[cciptestinterfaces.MessageSentEvent], error) {
	m.pollersMu.Lock()
	defer m.pollersMu.Unlock()
	onRamp := m.onRamp
	ethClient := m.ethClient

	pollFn := func(start, end uint64) (map[eventKey]cciptestinterfaces.MessageSentEvent, error) {
		filter, err := onRamp.FilterCCIPMessageSent(&bind.FilterOpts{
			Start: start,
			End:   &end,
		}, nil, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create filter: %w", err)
		}
		defer filter.Close()

		events := make(map[eventKey]cciptestinterfaces.MessageSentEvent)
		for filter.Next() {
			event := filter.Event
			key := eventKey{chainSelector: event.DestChainSelector, seqNo: event.SequenceNumber}

			message, err := protocol.DecodeMessage(event.EncodedMessage)
			if err != nil {
				m.logger.Warn().Err(err).Uint64("seqNo", event.SequenceNumber).Msg("Failed to decode message, skipping")
				continue
			}

			ev := cciptestinterfaces.MessageSentEvent{
				MessageID:      event.MessageId,
				SequenceNumber: event.SequenceNumber,
				Message:        message,
				ReceiptIssuers: make([]protocol.UnknownAddress, 0, len(event.Receipts)),
				VerifierBlobs:  event.VerifierBlobs,
			}
			for _, receipt := range event.Receipts {
				ev.ReceiptIssuers = append(ev.ReceiptIssuers, protocol.UnknownAddress(receipt.Issuer.Bytes()))
			}
			events[key] = ev
		}

		if err := filter.Error(); err != nil {
			return nil, fmt.Errorf("filter error: %w", err)
		}
		return events, nil
	}

	poller := newEventPoller(ethClient, m.logger, "CCIPMessageSent", pollFn)
	m.onRampPoller = poller
	return poller, nil
}

func (m *CCIP17EVM) getOrCreateOffRampPoller() (*eventPoller[cciptestinterfaces.ExecutionStateChangedEvent], error) {
	m.pollersMu.Lock()
	defer m.pollersMu.Unlock()

	ethClient := m.ethClient
	offRamp := m.offRamp

	pollFn := func(start, end uint64) (map[eventKey]cciptestinterfaces.ExecutionStateChangedEvent, error) {
		filter, err := offRamp.FilterExecutionStateChanged(&bind.FilterOpts{
			Start: start,
			End:   &end,
		}, nil, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create filter: %w", err)
		}
		defer filter.Close()

		events := make(map[eventKey]cciptestinterfaces.ExecutionStateChangedEvent)
		for filter.Next() {
			event := filter.Event
			key := eventKey{chainSelector: event.SourceChainSelector, seqNo: event.SequenceNumber}
			events[key] = cciptestinterfaces.ExecutionStateChangedEvent{
				MessageID:      event.MessageId,
				SequenceNumber: event.SequenceNumber,
				State:          cciptestinterfaces.MessageExecutionState(event.State),
				ReturnData:     event.ReturnData,
			}
		}

		if err := filter.Error(); err != nil {
			return nil, fmt.Errorf("filter error: %w", err)
		}
		return events, nil
	}

	poller := newEventPoller(ethClient, m.logger, "ExecutionStateChanged", pollFn)
	m.offRampPoller = poller
	return poller, nil
}

// fetchAllSentEventsBySelector fetch all CCIPMessageSent events from on ramp contract.
func (m *CCIP17EVM) fetchAllSentEventsBySelector(ctx context.Context, from, to uint64) ([]*onramp.OnRampCCIPMessageSent, error) {
	if from != m.chain.ChainSelector() {
		return nil, fmt.Errorf("fetchAllSentEventsBySelector: chain %d not found in environment chains %v", from, m.chain.ChainSelector())
	}

	l := m.logger
	filter, err := m.onRamp.FilterCCIPMessageSent(&bind.FilterOpts{
		Context: ctx,
	}, []uint64{to}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create filter: %w", err)
	}
	defer func() {
		if err := filter.Close(); err != nil {
			l.Warn().Err(err).Msg("Failed to close filter")
		}
	}()

	var events []*onramp.OnRampCCIPMessageSent

	for filter.Next() {
		event := filter.Event
		events = append(events, event)

		l.Info().
			Any("TxHash", event.Raw.TxHash.Hex()).
			Any("SeqNo", event.SequenceNumber).
			Str("MsgID", hexutil.Encode(event.MessageId[:])).
			Msg("Found CCIPMessageSent event")
	}

	if err := filter.Error(); err != nil {
		return nil, fmt.Errorf("filter error: %w", err)
	}

	l.Info().Int("count", len(events)).Msg("Total CCIPMessageSent events found")
	return events, nil
}

// fetchAllExecEventsBySelector fetch all ExecutionStateChanged events from off ramp contract.
func (m *CCIP17EVM) fetchAllExecEventsBySelector(ctx context.Context, from, to uint64) ([]*offramp.OffRampExecutionStateChanged, error) {
	if from != m.chain.ChainSelector() {
		return nil, fmt.Errorf("fetchAllExecEventsBySelectors: chain %d not found in environment chains %v", from, m.chain.ChainSelector())
	}

	l := m.logger
	filter, err := m.offRamp.FilterExecutionStateChanged(&bind.FilterOpts{
		Context: ctx,
	}, []uint64{to}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create filter: %w", err)
	}
	defer func() {
		if err := filter.Close(); err != nil {
			l.Warn().Err(err).Msg("Failed to close filter")
		}
	}()

	var events []*offramp.OffRampExecutionStateChanged

	for filter.Next() {
		event := filter.Event
		events = append(events, event)

		l.Info().
			Any("State", event.State).
			Any("TxHash", event.Raw.TxHash.Hex()).
			Any("SeqNo", event.SequenceNumber).
			Str("MsgID", hexutil.Encode(event.MessageId[:])).
			Str("Error", hexutil.Encode(filter.Event.ReturnData)).
			Msg("Found ExecutionStateChanged event")
	}

	if err := filter.Error(); err != nil {
		return nil, fmt.Errorf("filter error: %w", err)
	}

	l.Info().Int("count", len(events)).Msg("Total ExecutionStateChanged events found for selector and sequence")
	return events, nil
}

func (m *CCIP17EVM) GetExpectedNextSequenceNumber(ctx context.Context, from, to uint64) (uint64, error) {
	if from != m.chain.ChainSelector() {
		return 0, fmt.Errorf("GetExpectedNextSequenceNumber: chain %d not found in environment chains %v", from, m.chain.ChainSelector())
	}

	return m.onRamp.GetExpectedNextSequenceNumber(&bind.CallOpts{Context: ctx}, to)
}

// WaitOneSentEventBySeqNo wait and fetch strictly one CCIPMessageSent event by selector and sequence number and selector.
func (m *CCIP17EVM) WaitOneSentEventBySeqNo(ctx context.Context, from, to, seq uint64, timeout time.Duration) (cciptestinterfaces.MessageSentEvent, error) {
	if from != m.chain.ChainSelector() {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("WaitOneSentEventBySeqNo: chain %d not found in environment chains %v", from, m.chain.ChainSelector())
	}

	l := m.logger
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	l.Info().Uint64("from", from).Uint64("to", to).Uint64("seq", seq).Msg("Awaiting CCIPMessageSent event")
	poller, err := m.getOrCreateOnRampPoller()
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, err
	}
	resultCh := poller.register(ctx, to, seq)

	select {
	case <-ctx.Done():
		return cciptestinterfaces.MessageSentEvent{}, ctx.Err()
	case result := <-resultCh:
		if result.err != nil {
			return cciptestinterfaces.MessageSentEvent{}, result.err
		}
		return result.event, nil
	}
}

// WaitOneExecEventBySeqNo wait and fetch strictly one ExecutionStateChanged event by sequence number and selector.
func (m *CCIP17EVM) WaitOneExecEventBySeqNo(ctx context.Context, from, to, seq uint64, timeout time.Duration) (cciptestinterfaces.ExecutionStateChangedEvent, error) {
	if to != m.chain.ChainSelector() {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("WaitOneExecEventBySeqNo: chain %d not found in environment chains %v", from, m.chain.ChainSelector())
	}

	l := m.logger
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	l.Info().Uint64("from", from).Uint64("to", to).Uint64("seq", seq).Msg("Awaiting ExecutionStateChanged event")

	poller, err := m.getOrCreateOffRampPoller()
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, err
	}

	resultCh := poller.register(ctx, from, seq)

	select {
	case <-ctx.Done():
		l.Info().Msg("Context done while waiting for ExecutionStateChanged event")
		return cciptestinterfaces.ExecutionStateChangedEvent{}, ctx.Err()
	case result := <-resultCh:
		if result.err != nil {
			return cciptestinterfaces.ExecutionStateChangedEvent{}, result.err
		}
		return result.event, nil
	}
}

func (m *CCIP17EVM) GetEOAReceiverAddress(chainSelector uint64) (protocol.UnknownAddress, error) {
	if m.chain.ChainSelector() != chainSelector {
		return nil, fmt.Errorf("GetEOAReceiverAddress: chain %d not found in environment chains %v", chainSelector, m.chain.ChainSelector())
	}

	// returns the same address for each chain for now - we might need to extend this in the future if we'd ever
	// need to access any funds on the EOA itself.
	return protocol.UnknownAddress(common.HexToAddress("0x3Aa5ebB10DC797CAC828524e59A333d0A371443d").Bytes()), nil
}

func (m *CCIP17EVM) GetSenderAddress(chainSelector uint64) (protocol.UnknownAddress, error) {
	if m.chain.ChainSelector() != chainSelector {
		return nil, fmt.Errorf("GetSenderAddress: chain %d not found in environment chains %v", chainSelector, m.chain.ChainSelector())
	}

	// Return the chain deployer key address
	return protocol.UnknownAddress(m.chain.DeployerKey.From.Bytes()), nil
}

func (m *CCIP17EVM) GetTokenBalance(ctx context.Context, chainSelector uint64, address, tokenAddress protocol.UnknownAddress) (*big.Int, error) {
	if m.chain.ChainSelector() != chainSelector {
		return nil, fmt.Errorf("GetTokenBalance: chain %d not found in environment chains %v", chainSelector, m.chain.ChainSelector())
	}

	tkn, err := erc20.NewERC20(common.HexToAddress(tokenAddress.String()), m.chain.Client)
	if err != nil {
		return nil, fmt.Errorf("failed to create erc20 wrapper: %w", err)
	}
	balance, err := tkn.BalanceOf(&bind.CallOpts{Context: ctx}, common.HexToAddress(address.String()))
	if err != nil {
		return nil, fmt.Errorf("failed to get balance: %w", err)
	}
	return balance, nil
}

// ensureERC20HasBalanceAndAllowance ensures that the given owner has at least `amount`
// balance of `token` and that `spender` has at least `amount` allowance.
func (m *CCIP17EVM) ensureERC20HasBalanceAndAllowance(
	ctx context.Context,
	chain evm.Chain,
	auth *bind.TransactOpts,
	token, owner, spender common.Address,
	amount *big.Int,
) (bool, error) {
	tkn, err := erc20.NewERC20(token, chain.Client)
	if err != nil {
		return false, fmt.Errorf("failed to create erc20 wrapper: %w", err)
	}
	balance, err := tkn.BalanceOf(&bind.CallOpts{Context: ctx}, owner)
	if err != nil {
		return false, fmt.Errorf("failed to get balance: %w", err)
	}
	if balance.Cmp(amount) < 0 {
		return false, fmt.Errorf("insufficient balance: have %s, need %s", balance.String(), amount.String())
	}
	allowance, err := tkn.Allowance(&bind.CallOpts{Context: ctx}, owner, spender)
	if err != nil {
		return false, fmt.Errorf("failed to get allowance: %w", err)
	}
	if allowance.Cmp(amount) < 0 {
		l := m.logger
		l.Info().
			Str("Token", token.Hex()).
			Str("Spender", spender.Hex()).
			Str("Owner", owner.Hex()).
			Str("Amount", amount.String()).
			Msg("Insufficient allowance, approving")
		tx, err := tkn.Approve(&bind.TransactOpts{
			Context: ctx,
			From:    auth.From,
			Signer:  auth.Signer,
		}, spender, amount)
		if err != nil {
			return false, fmt.Errorf("failed to approve spending of %s for %s: %w", amount.String(), spender.Hex(), err)
		}
		l.Info().Str("TxHash", tx.Hash().Hex()).Msg("Waiting for approve transaction to be mined")
		receipt, err := bind.WaitMined(ctx, chain.Client, tx.Hash())
		if err != nil {
			return false, fmt.Errorf("failed to wait for approve transaction to be mined: %w", err)
		}
		if receipt.Status != types.ReceiptStatusSuccessful {
			return false, fmt.Errorf("approve transaction failed: %s", receipt.TxHash.Hex())
		}
		l.Info().Msg("Approval successful")
	}
	return true, nil
}

func (m *CCIP17EVM) haveEnoughTransferTokens(ctx context.Context, chain evm.Chain, auth *bind.TransactOpts, routerAddress, token common.Address, amount *big.Int) (hasEnough bool, err error) {
	// Transfer token is a vanilla ERC20; check owner's balance and router's allowance.
	return m.ensureERC20HasBalanceAndAllowance(ctx, chain, auth, token, chain.DeployerKey.From, routerAddress, amount)
}

func (m *CCIP17EVM) haveEnoughFeeTokens(ctx context.Context, chain evm.Chain, auth *bind.TransactOpts, routerAddress, feeToken common.Address, amount *big.Int) (hasEnough bool, msgValue *big.Int, err error) {
	wrappedNativeRef, err := m.ds.Addresses().Get(datastore.NewAddressRefKey(chain.Selector, datastore.ContractType(weth.ContractType), semver.MustParse(weth.Deploy.Version()), ""))
	if err != nil {
		return false, nil, fmt.Errorf("failed to get wrapped native address: %w", err)
	}
	linkRef, err := m.ds.Addresses().Get(datastore.NewAddressRefKey(chain.Selector, datastore.ContractType(link.ContractType), semver.MustParse(link.Deploy.Version()), ""))
	if err != nil {
		return false, nil, fmt.Errorf("failed to get link address: %w", err)
	}
	wrappedNative := common.HexToAddress(wrappedNativeRef.Address)
	link := common.HexToAddress(linkRef.Address)
	// TODO: should check if fee token is enabled somehow? Check feeQuoter contract?
	switch feeToken {
	case common.Address{}:
		// if no fee token is specified, pure native token is used, so this is just a BalanceAt check.
		balance, err := chain.Client.BalanceAt(ctx, chain.DeployerKey.From, nil)
		if err != nil {
			return false, nil, fmt.Errorf("failed to get balance: %w", err)
		}
		// msg.Value is equal to amount in the native token case
		return balance.Cmp(amount) >= 0, amount, nil
	case wrappedNative, link:
		ok, err := m.ensureERC20HasBalanceAndAllowance(ctx, chain, auth, feeToken, chain.DeployerKey.From, routerAddress, amount)
		if err != nil {
			return false, nil, err
		}
		if !ok {
			return false, nil, nil
		}
		return true, big.NewInt(0), nil
	default:
		return false, nil, fmt.Errorf("unsupported fee token: %s", feeToken.String())
	}
}

func (m *CCIP17EVM) validateTokenBalances(ctx context.Context, srcChain evm.Chain, routerAddress common.Address, fields cciptestinterfaces.MessageFields, fee *big.Int, tokenAmounts []routeroperations.EVMTokenAmount, validateBalances bool, l zerolog.Logger) (*big.Int, error) {
	haveEnoughFeeTokens, msgValue, err := m.haveEnoughFeeTokens(ctx, srcChain, srcChain.DeployerKey, routerAddress, common.HexToAddress(fields.FeeToken.String()), fee)
	if err != nil {
		return nil, fmt.Errorf("failed to check if have enough tokens: %w", err)
	}

	if !validateBalances {
		return msgValue, nil
	}

	if !haveEnoughFeeTokens {
		return nil, fmt.Errorf("not enough tokens to send message, feeToken: %s, fee: %s, msgValue: %s", fields.FeeToken.String(), fee.String(), msgValue.String())
	}

	if len(tokenAmounts) > 0 {
		haveEnoughTransferTokens, err := m.haveEnoughTransferTokens(ctx, srcChain, srcChain.DeployerKey, routerAddress, common.HexToAddress(tokenAmounts[0].Token.String()), tokenAmounts[0].Amount)
		if err != nil {
			return nil, fmt.Errorf("failed to check if have enough tokens: %w", err)
		}
		if !haveEnoughTransferTokens {
			return nil, fmt.Errorf("not enough tokens to send in a message, token: %s, amount: %s", tokenAmounts[0].Token.String(), tokenAmounts[0].Amount.String())
		}
	}

	l.Info().
		Str("FeeToken", fields.FeeToken.String()).
		Str("Amount", fee.String()).
		Str("MsgValue", msgValue.String()).
		Msg("Have enough tokens to send message")

	return msgValue, nil
}

func (m *CCIP17EVM) SendMessage(ctx context.Context, src, dest uint64, fields cciptestinterfaces.MessageFields, opts cciptestinterfaces.MessageOptions) (cciptestinterfaces.MessageSentEvent, error) {
	return m.SendMessageWithNonce(ctx, src, dest, fields, opts, nil, false)
}

func (m *CCIP17EVM) SendMessageWithNonce(ctx context.Context, src, dest uint64, fields cciptestinterfaces.MessageFields, opts cciptestinterfaces.MessageOptions, nonce *atomic.Int64, disableTokenAmountCheck bool) (cciptestinterfaces.MessageSentEvent, error) {
	l := m.logger
	if m.chain.ChainSelector() != src {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("SendMessage: chain %d not found in environment chains %v", src, m.chain.ChainSelector())
	}
	srcChain := m.chain

	destFamily, err := chainsel.GetSelectorFamily(dest)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get destination family: %w", err)
	}

	routerRef, err := m.ds.Addresses().Get(datastore.NewAddressRefKey(srcChain.Selector, datastore.ContractType(routeroperations.ContractType), semver.MustParse(routeroperations.Deploy.Version()), ""))
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get router address: %w", err)
	}

	routerAddress := common.HexToAddress(routerRef.Address)
	rout, err := routerwrapper.NewRouter(routerAddress, srcChain.Client)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("create router wrapper: %w", err)
	}

	// Even though it is called "tokenAmounts", but we only support one token amount.
	var tokenAmounts []routeroperations.EVMTokenAmount
	if fields.TokenAmount.Amount != nil {
		tokenAmounts = []routeroperations.EVMTokenAmount{{
			Token:  common.HexToAddress(fields.TokenAmount.TokenAddress.String()),
			Amount: fields.TokenAmount.Amount,
		}}
	}

	extraArgs := serializeExtraArgs(opts, destFamily)
	msg := routerwrapper.ClientEVM2AnyMessage{
		Receiver:     common.LeftPadBytes(common.HexToAddress(fields.Receiver.String()).Bytes(), 32),
		Data:         fields.Data,
		TokenAmounts: tokenAmounts,
		FeeToken:     common.HexToAddress(fields.FeeToken.String()),
		ExtraArgs:    extraArgs,
	}
	fee, err := rout.GetFee(
		&bind.CallOpts{
			Context: ctx,
		}, dest,
		msg,
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get fee: %w", err)
	}

	msgValue, err := m.validateTokenBalances(ctx, srcChain, routerAddress, fields, fee, tokenAmounts, !disableTokenAmountCheck, l)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, err
	}

	var loadNonce *big.Int = nil
	if nonce != nil {
		loadNonce = big.NewInt(nonce.Load())
	}
	deployerKeyCopy := &bind.TransactOpts{
		From:   srcChain.DeployerKey.From,
		Signer: srcChain.DeployerKey.Signer,
		Nonce:  loadNonce,
		Value:  msgValue,
	}
	if nonce != nil {
		nonce.Add(1)
	}
	tx, err := rout.CcipSend(deployerKeyCopy, dest, msg)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to send CCIP message: %w, extraArgs: %x", err, extraArgs)
	}

	txHash := tx.Hash()

	_, err = srcChain.Confirm(tx)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to confirm transaction: %w", err)
	}

	receipt, err := srcChain.Client.TransactionReceipt(ctx, txHash)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	var messageSentEvent *onramp.OnRampCCIPMessageSent
	for _, log := range receipt.Logs {
		if log.Topics[0] == ccipMessageSentTopic {
			messageSentEvent, err = m.onRamp.ParseCCIPMessageSent(*log)
			if err != nil {
				l.Warn().Err(err).Msg("Failed to parse CCIPMessageSent event")
				continue
			}
			break
		}
	}

	if messageSentEvent == nil {
		return cciptestinterfaces.MessageSentEvent{}, errors.New("no CCIPMessageSent event found")
	}

	dcc, err := m.onRamp.GetDestChainConfig(&bind.CallOpts{
		Context: ctx,
	}, dest)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get dest chain config: %w", err)
	}

	message, err := protocol.DecodeMessage(messageSentEvent.EncodedMessage)
	if err != nil {
		// Fail here - indicates a bug in the decoder which is critical.
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to decode message: %w", err)
	}
	result := cciptestinterfaces.MessageSentEvent{
		MessageID:      messageSentEvent.MessageId,
		SequenceNumber: messageSentEvent.SequenceNumber,
		Message:        message,
		ReceiptIssuers: make([]protocol.UnknownAddress, 0, len(messageSentEvent.Receipts)),
		VerifierBlobs:  messageSentEvent.VerifierBlobs,
	}
	for _, receipt := range messageSentEvent.Receipts {
		result.ReceiptIssuers = append(result.ReceiptIssuers, protocol.UnknownAddress(receipt.Issuer.Bytes()))
	}

	l.Info().
		Bool("Executed", receipt != nil).
		Uint64("SrcChainSelector", srcChain.Selector).
		Uint64("DestChainSelector", dest).
		Str("SrcRouter", rout.Address().Hex()).
		Str("MessageID", hexutil.Encode(result.MessageID[:])).
		Any("DefaultCCVs", dcc.DefaultCCVs).
		Any("LaneMandatedCCVs", dcc.LaneMandatedCCVs).
		Any("DefaultExecutor", dcc.DefaultExecutor).
		Any("OffRamp", hexutil.Encode(dcc.OffRamp)).
		Int("NumReceipts", len(result.ReceiptIssuers)).
		Int("NumVerifierBlobs", len(result.VerifierBlobs)).
		Any("ReceiptIssuers", result.ReceiptIssuers).
		Uint64("SeqNo", result.SequenceNumber).
		Msg("CCIP message sent")

	return result, nil
}

func serializeExtraArgs(opts cciptestinterfaces.MessageOptions, destFamily string) []byte {
	switch destFamily {
	case chainsel.FamilyEVM:
		switch opts.Version {
		case 1: // EVMExtraArgsV1
			return serializeExtraArgsV1(opts)
		case 2: // GenericExtraArgsV2
			return serializeExtraArgsV2(opts)
		case 3: // EVMExtraArgsV3
			return serializeExtraArgsV3(opts)
		default:
			panic(fmt.Sprintf("unsupported message extra args version: %d", opts.Version))
		}
	case chainsel.FamilySolana:
		switch opts.Version {
		case 1: // SVMExtraArgsV1
			return serializeExtraArgsSVMV1(opts)
		default:
			panic(fmt.Sprintf("unsupported message extra args version for family %s: %d", destFamily, opts.Version))
		}
	default:
		panic(fmt.Sprintf("unsupported destination family: %s", destFamily))
	}
}

func serializeExtraArgsV1(opts cciptestinterfaces.MessageOptions) []byte {
	evmExtraArgsV1Type, err := abi.NewType("tuple", "EVMExtraArgsV1", []abi.ArgumentMarshaling{
		{Name: "gasLimit", Type: "uint256"},
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create EVMExtraArgsV1 tuple type: %v", err))
	}

	arguments := abi.Arguments{
		{
			Type: evmExtraArgsV1Type,
			Name: "extraArgs",
		},
	}

	type EVMExtraArgsV1 struct {
		GasLimit *big.Int
	}

	packed, err := arguments.Pack(EVMExtraArgsV1{GasLimit: big.NewInt(int64(opts.ExecutionGasLimit))})
	if err != nil {
		panic(fmt.Sprintf("failed to pack extraArgs: %v", err))
	}

	selector, _ := hexutil.Decode("0x97a657c9")
	return append(selector, packed...)
}

func serializeExtraArgsV2(opts cciptestinterfaces.MessageOptions) []byte {
	genericExtraArgsV2Type, err := abi.NewType("tuple", "GenericExtraArgsV2", []abi.ArgumentMarshaling{
		{Name: "gasLimit", Type: "uint256"},
		{Name: "allowOutOfOrderExecution", Type: "bool"},
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create GenericExtraArgsV2 tuple type: %v", err))
	}

	arguments := abi.Arguments{
		{
			Type: genericExtraArgsV2Type,
			Name: "extraArgs",
		},
	}

	type GenericExtraArgsV2 struct {
		GasLimit                 *big.Int
		AllowOutOfOrderExecution bool
	}

	packed, err := arguments.Pack(GenericExtraArgsV2{
		GasLimit:                 big.NewInt(int64(opts.ExecutionGasLimit)),
		AllowOutOfOrderExecution: opts.OutOfOrderExecution,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to pack extraArgs: %v", err))
	}

	selector, _ := hexutil.Decode("0x181dcf10")
	return append(selector, packed...)
}

func serializeExtraArgsV3(opts cciptestinterfaces.MessageOptions) []byte {
	extraArgs, err := NewV3ExtraArgs(
		opts.FinalityConfig,
		opts.ExecutionGasLimit,
		opts.Executor.String(),
		opts.ExecutorArgs,
		opts.TokenArgs,
		opts.CCVs,
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create V3 extra args: %v", err))
	}
	return extraArgs
}

func serializeExtraArgsSVMV1(_ cciptestinterfaces.MessageOptions) []byte {
	// // Extra args tag for chains that use the Solana VM.
	// bytes4 public constant SVM_EXTRA_ARGS_V1_TAG = 0x1f3b3aba;

	// struct SVMExtraArgsV1 {
	//   uint32 computeUnits;
	//   uint64 accountIsWritableBitmap;
	//   bool allowOutOfOrderExecution;
	//   bytes32 tokenReceiver;
	//   // Additional accounts needed for execution of CCIP receiver. Must be empty if message.receiver is zero.
	//   // Token transfer related accounts are specified in the token pool lookup table on SVM.
	//   bytes32[] accounts;
	// }
	return nil // TODO: implement when solana ported to 1.7 tests.
}

func (m *CCIP17EVM) ExposeMetrics(
	ctx context.Context,
	source, dest uint64,
) ([]string, *prometheus.Registry, error) {
	msgSentTotal.Reset()
	msgExecTotal.Reset()
	srcDstLatency.Reset()

	reg := prometheus.NewRegistry()
	reg.MustRegister(msgSentTotal, msgExecTotal, srcDstLatency)

	lp := NewLokiPusher()
	tp := NewTempoPusher()
	err := ProcessLaneEvents(ctx, m, lp, tp, &LaneStreamConfig{
		FromSelector:      source,
		ToSelector:        dest,
		AggregatorAddress: "localhost:50051",
		AggregatorSince:   0,
	})
	if err != nil {
		return nil, nil, err
	}
	err = ProcessLaneEvents(ctx, m, lp, tp, &LaneStreamConfig{
		FromSelector:      dest,
		ToSelector:        source,
		AggregatorAddress: "localhost:50051",
		AggregatorSince:   0,
	})
	if err != nil {
		return nil, nil, err
	}
	return []string{}, reg, nil
}

func (m *CCIP17EVM) DeployLocalNetwork(ctx context.Context, bc *blockchain.Input) (*blockchain.Output, error) {
	l := m.logger
	l.Info().Msg("Deploying EVM networks")
	out, err := blockchain.NewBlockchainNetwork(bc)
	if err != nil {
		return nil, fmt.Errorf("failed to create blockchain network: %w", err)
	}
	return out, nil
}

func (m *CCIP17EVM) ConfigureNodes(ctx context.Context, bc *blockchain.Input) (string, error) {
	l := m.logger
	l.Info().Msg("Configuring CL nodes")
	name := fmt.Sprintf("node-evm-%s", uuid.New().String()[0:5])
	finality := 1
	return fmt.Sprintf(`
       [[EVM]]
       LogPollInterval = '1s'
       BlockBackfillDepth = 100
       ChainID = '%s'
       MinIncomingConfirmations = 1
       MinContractPayment = '0.0000001 link'
       FinalityDepth = %d

       [[EVM.Nodes]]
       Name = '%s'
       WsUrl = '%s'
       HttpUrl = '%s'`,
		bc.ChainID,
		finality,
		name,
		bc.Out.Nodes[0].InternalWSUrl,
		bc.Out.Nodes[0].InternalHTTPUrl,
	), nil
}

func toCommitteeVerifierParams(committees []cciptestinterfaces.OnChainCommittees) []sequences.CommitteeVerifierParams {
	params := make([]sequences.CommitteeVerifierParams, 0, len(committees))

	toCommon := func(addrs [][]byte) []common.Address {
		var result []common.Address
		for _, addr := range addrs {
			if len(addr) != common.AddressLength {
				panic(fmt.Sprintf("invalid address length: %d", len(addr)))
			}
			result = append(result, common.BytesToAddress(addr))
		}
		return result
	}

	// TODO: deploy the offchain verifiers that correspond to these contracts.
	for _, c := range committees {
		params = append(params, sequences.CommitteeVerifierParams{
			Version: semver.MustParse(committee_verifier.Deploy.Version()),
			// TODO: add mocked contract here
			FeeAggregator: common.HexToAddress("0x01"),
			SignatureConfigArgs: committee_verifier.SetSignatureConfigArgs{
				Signers:   toCommon(c.Signers),
				Threshold: c.Threshold,
			},
			Qualifier: c.CommitteeQualifier,
		})
	}

	return params
}

func (m *CCIP17EVM) DeployContractsForSelector(ctx context.Context, env *deployment.Environment, selector uint64, committees []cciptestinterfaces.OnChainCommittees) (datastore.DataStore, error) {
	l := m.logger
	l.Info().Msg("Configuring contracts for selector")
	l.Info().Any("Selector", selector).Msg("Deploying for chain selectors")
	runningDS := datastore.NewMemoryDataStore()

	l.Info().Uint64("Selector", selector).Msg("Configuring per-chain contracts bundle")
	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		env.Logger,
		operations.NewMemoryReporter(),
	)
	env.OperationsBundle = bundle

	usdPerLink, ok := new(big.Int).SetString("15000000000000000000", 10) // $15
	if !ok {
		return nil, errors.New("failed to parse USDPerLINK")
	}
	usdPerWeth, ok := new(big.Int).SetString("2000000000000000000000", 10) // $2000
	if !ok {
		return nil, errors.New("failed to parse USDPerWETH")
	}

	mcmsReaderRegistry := changesetscore.NewMCMSReaderRegistry() // TODO: Integrate actual registry if MCMS support is required.
	out, err := evmchangesets.DeployChainContracts(mcmsReaderRegistry).Apply(*env, changesetscore.WithMCMS[evmchangesets.DeployChainContractsCfg]{
		Cfg: evmchangesets.DeployChainContractsCfg{
			ChainSel: selector,
			Params: sequences.ContractParams{
				// TODO: Router contract implementation is missing
				RMNRemote: sequences.RMNRemoteParams{
					Version: semver.MustParse(rmn_remote.Deploy.Version()),
				},
				OffRamp: sequences.OffRampParams{
					Version:              semver.MustParse(offrampoperations.Deploy.Version()),
					GasForCallExactCheck: 5_000,
				},
				// Deploy multiple committee verifiers in order to test different receiver
				// configurations.
				CommitteeVerifiers: toCommitteeVerifierParams(committees),
				OnRamp: sequences.OnRampParams{
					Version:       semver.MustParse(onrampoperations.Deploy.Version()),
					FeeAggregator: common.HexToAddress("0x01"),
				},
				Executor: sequences.ExecutorParams{
					Version:       semver.MustParse(executor.Deploy.Version()),
					MaxCCVsPerMsg: 10,
					DynamicConfig: executor.SetDynamicConfigArgs{
						FeeAggregator:         common.HexToAddress("0x01"),
						MinBlockConfirmations: 0,
						CcvAllowlistEnabled:   false,
					},
				},
				FeeQuoter: sequences.FeeQuoterParams{
					Version: semver.MustParse(fee_quoter.Deploy.Version()),
					// expose in TOML config
					MaxFeeJuelsPerMsg:              big.NewInt(2e18),
					LINKPremiumMultiplierWeiPerEth: 9e17, // 0.9 ETH
					WETHPremiumMultiplierWeiPerEth: 1e18, // 1.0 ETH
					USDPerLINK:                     usdPerLink,
					USDPerWETH:                     usdPerWeth,
				},
				// TODO: How to generate this from the committees param?
				MockReceivers: []sequences.MockReceiverParams{
					{
						// single required verifier (default), no optional verifiers, no optional threshold
						Version: semver.MustParse(mock_receiver.Deploy.Version()),
						RequiredVerifiers: []datastore.AddressRef{
							{
								Type:          datastore.ContractType(committee_verifier.ResolverProxyType),
								Version:       semver.MustParse(committee_verifier.Deploy.Version()),
								ChainSelector: selector,
								Qualifier:     DefaultCommitteeVerifierQualifier,
							},
						},
						Qualifier: DefaultReceiverQualifier,
					},
					{
						// single required verifier (secondary), no optional verifiers, no optional threshold
						Version: semver.MustParse(mock_receiver.Deploy.Version()),
						RequiredVerifiers: []datastore.AddressRef{
							{
								Type:          datastore.ContractType(committee_verifier.ResolverProxyType),
								Version:       semver.MustParse(committee_verifier.Deploy.Version()),
								ChainSelector: selector,
								Qualifier:     SecondaryCommitteeVerifierQualifier,
							},
						},
						Qualifier: SecondaryReceiverQualifier,
					},
					{
						// single required verifier (secondary), single optional verifier (tertiary), optional threshold=1
						// this means that the message should only be executed after the required and optional verifiers have signed.
						// optional threshold being 1, with one optional, means that it must be retrieved.
						Version: semver.MustParse(mock_receiver.Deploy.Version()),
						RequiredVerifiers: []datastore.AddressRef{
							{
								Type:          datastore.ContractType(committee_verifier.ResolverProxyType),
								Version:       semver.MustParse(committee_verifier.Deploy.Version()),
								ChainSelector: selector,
								Qualifier:     SecondaryCommitteeVerifierQualifier,
							},
						},
						OptionalVerifiers: []datastore.AddressRef{
							{
								Type:          datastore.ContractType(committee_verifier.ResolverProxyType),
								Version:       semver.MustParse(committee_verifier.Deploy.Version()),
								ChainSelector: selector,
								Qualifier:     TertiaryCommitteeVerifierQualifier,
							},
						},
						OptionalThreshold: 1,
						Qualifier:         TertiaryReceiverQualifier,
					},
					{
						Version: semver.MustParse(mock_receiver.Deploy.Version()),
						RequiredVerifiers: []datastore.AddressRef{
							{
								Type:          datastore.ContractType(committee_verifier.ResolverProxyType),
								Version:       semver.MustParse(committee_verifier.Deploy.Version()),
								ChainSelector: selector,
								Qualifier:     DefaultCommitteeVerifierQualifier,
							},
						},
						OptionalVerifiers: []datastore.AddressRef{
							{
								Type:          datastore.ContractType(committee_verifier.ResolverProxyType),
								Version:       semver.MustParse(committee_verifier.Deploy.Version()),
								ChainSelector: selector,
								Qualifier:     SecondaryCommitteeVerifierQualifier,
							},
							{
								Type:          datastore.ContractType(committee_verifier.ResolverProxyType),
								Version:       semver.MustParse(committee_verifier.Deploy.Version()),
								ChainSelector: selector,
								Qualifier:     TertiaryCommitteeVerifierQualifier,
							},
						},
						OptionalThreshold: 1,
						Qualifier:         QuaternaryReceiverQualifier,
					},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	err = runningDS.Merge(out.DataStore.Seal())
	if err != nil {
		return nil, err
	}
	env.DataStore = runningDS.Seal()

	for _, combo := range AllTokenCombinations() {
		// For any given token combination, every chain needs to support the source and destination pools.
		if err := m.deployTokenAndPool(env, mcmsReaderRegistry, runningDS, selector, combo.SourcePoolAddressRef()); err != nil {
			return nil, fmt.Errorf("failed to deploy %s token: %w", combo.SourcePoolAddressRef().Qualifier, err)
		}
		if err := m.deployTokenAndPool(env, mcmsReaderRegistry, runningDS, selector, combo.DestPoolAddressRef()); err != nil {
			return nil, fmt.Errorf("failed to deploy %s token: %w", combo.DestPoolAddressRef().Qualifier, err)
		}
	}

	return runningDS.Seal(), nil
}

func (m *CCIP17EVM) deployTokenAndPool(
	env *deployment.Environment,
	mcmsReaderRegistry *changesetscore.MCMSReaderRegistry,
	runningDS *datastore.MemoryDataStore,
	selector uint64,
	tokenPoolRef datastore.AddressRef,
) error {
	chain, ok := env.BlockChains.EVMChains()[selector]
	if !ok {
		return fmt.Errorf("evm chain not found for selector %d", selector)
	}

	maxSupply, ok := big.NewInt(0).SetString(TokenMaxSupply, 10)
	if !ok {
		return errors.New("failed to parse max supply")
	}
	deployerBalance, ok := big.NewInt(0).SetString(TokenDeployerBalance, 10)
	if !ok {
		return errors.New("failed to parse deployer balance")
	}

	out, err := evmchangesets.DeployBurnMintTokenAndPool(mcmsReaderRegistry).Apply(*env, changesetscore.WithMCMS[evmchangesets.DeployBurnMintTokenAndPoolCfg]{
		Cfg: evmchangesets.DeployBurnMintTokenAndPoolCfg{
			Accounts: map[common.Address]*big.Int{
				chain.DeployerKey.From: deployerBalance,
			},
			TokenInfo: tokens.TokenInfo{
				Name:      tokenPoolRef.Qualifier,
				Decimals:  DefaultDecimals,
				MaxSupply: maxSupply,
			},
			DeployTokenPoolCfg: evmchangesets.DeployTokenPoolCfg{
				ChainSel:           selector,
				TokenPoolType:      tokenPoolRef.Type,
				TokenPoolVersion:   tokenPoolRef.Version,
				TokenSymbol:        tokenPoolRef.Qualifier,
				LocalTokenDecimals: DefaultDecimals,
				Router: datastore.AddressRef{
					Type:    datastore.ContractType(routeroperations.ContractType),
					Version: semver.MustParse(routeroperations.Deploy.Version()),
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to deploy %s token and pool: %w", tokenPoolRef.Qualifier, err)
	}

	err = runningDS.Merge(out.DataStore.Seal())
	if err != nil {
		return fmt.Errorf("failed to merge datastore for %s token: %w", tokenPoolRef.Qualifier, err)
	}

	tokenPoolRef, err = runningDS.Addresses().Get(datastore.NewAddressRefKey(selector, tokenPoolRef.Type, tokenPoolRef.Version, tokenPoolRef.Qualifier))
	if err != nil {
		return fmt.Errorf("failed to get deployed token pool ref for %s token: %w", tokenPoolRef.Qualifier, err)
	}

	if tokenPoolRef.Type == datastore.ContractType(lock_release_token_pool.ContractType) {
		err = m.fundLockReleaseTokenPool(
			env,
			selector,
			tokenPoolRef,
			new(big.Int).Div(deployerBalance, big.NewInt(10)),
		)
		if err != nil {
			return fmt.Errorf("failed to fund lock-release token pool for %s token: %w", tokenPoolRef.Qualifier, err)
		}
		return nil
	}

	return nil
}

func (m *CCIP17EVM) GetMaxDataBytes(ctx context.Context, remoteChainSelector uint64) (uint32, error) {
	if remoteChainSelector != m.chain.ChainSelector() {
		return 0, fmt.Errorf("GetMaxDataBytes: chain %d not found in environment chains %v", remoteChainSelector, m.chain.ChainSelector())
	}

	feeQuoterRef, err := m.ds.Addresses().Get(datastore.NewAddressRefKey(remoteChainSelector, datastore.ContractType(fee_quoter.ContractType), semver.MustParse(fee_quoter.Deploy.Version()), ""))
	if err != nil {
		return 0, fmt.Errorf("failed to get fee quoter address: %w", err)
	}
	feeQuoter, err := feequoterwrapper.NewFeeQuoter(common.HexToAddress(feeQuoterRef.Address), m.ethClient)
	if err != nil {
		return 0, fmt.Errorf("failed to new fee quoter contract: %w", err)
	}
	destChainConfig, err := feeQuoter.GetDestChainConfig(&bind.CallOpts{Context: ctx}, remoteChainSelector)
	if err != nil {
		return 0, fmt.Errorf("failed to get dest chain config: %w", err)
	}
	return destChainConfig.MaxDataBytes, nil
}

func (m *CCIP17EVM) configureTokenForTransfer(
	e *deployment.Environment,
	tokenAdapterRegistry *tokenscore.TokenAdapterRegistry,
	mcmsReaderRegistry *changesetscore.MCMSReaderRegistry,
	selector uint64,
	remoteSelectors []uint64,
	localRef datastore.AddressRef,
	remoteRef datastore.AddressRef,
	ccvQualifiers []string,
) error {
	tokensRemoteChains := make(map[uint64]tokenscore.RemoteChainConfig[*datastore.AddressRef, datastore.AddressRef])
	for _, rs := range remoteSelectors {
		ccvRefs := make([]datastore.AddressRef, 0, len(ccvQualifiers))
		for _, qualifier := range ccvQualifiers {
			ccvRefs = append(ccvRefs, datastore.AddressRef{
				Type:      datastore.ContractType(committee_verifier.ResolverProxyType),
				Version:   semver.MustParse(committee_verifier.Deploy.Version()),
				Qualifier: qualifier,
			})
		}

		tokensRemoteChains[rs] = tokenscore.RemoteChainConfig[*datastore.AddressRef, datastore.AddressRef]{
			RemotePool: &remoteRef,
			InboundRateLimiterConfig: tokenscore.RateLimiterConfig{
				IsEnabled: false,
				Capacity:  big.NewInt(0),
				Rate:      big.NewInt(0),
			},
			OutboundRateLimiterConfig: tokenscore.RateLimiterConfig{
				IsEnabled: false,
				Capacity:  big.NewInt(0),
				Rate:      big.NewInt(0),
			},
			OutboundCCVs: ccvRefs,
			InboundCCVs:  ccvRefs,
		}
	}

	_, err := tokenscore.ConfigureTokensForTransfers(tokenAdapterRegistry, mcmsReaderRegistry).Apply(*e, tokenscore.ConfigureTokensForTransfersConfig{
		Tokens: []tokenscore.TokenTransferConfig{
			{
				ChainSelector: selector,
				TokenPoolRef:  localRef,
				RegistryRef: datastore.AddressRef{
					Type:    datastore.ContractType(token_admin_registry.ContractType),
					Version: semver.MustParse(token_admin_registry.Deploy.Version()),
				},
				RemoteChains: tokensRemoteChains,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to configure %s token for transfers: %w", localRef.Qualifier, err)
	}

	return nil
}

func toComitteeVerifier(selector uint64, committees []cciptestinterfaces.OnChainCommittees) []adapters.CommitteeVerifier[datastore.AddressRef] {
	committeeVerifiers := make([]adapters.CommitteeVerifier[datastore.AddressRef], 0, len(committees))
	for _, committee := range committees {
		committeeVerifiers = append(committeeVerifiers, adapters.CommitteeVerifier[datastore.AddressRef]{
			Implementation: datastore.AddressRef{
				Type:          datastore.ContractType(committee_verifier.ContractType),
				Version:       semver.MustParse(committee_verifier.Deploy.Version()),
				ChainSelector: selector,
				Qualifier:     committee.CommitteeQualifier,
			},
			Resolver: datastore.AddressRef{
				Type:          datastore.ContractType(committee_verifier.ResolverType),
				Version:       semver.MustParse(committee_verifier.Deploy.Version()),
				ChainSelector: selector,
				Qualifier:     committee.CommitteeQualifier,
			},
		})
	}
	return committeeVerifiers
}

// TODO: How to generate all the default/secondary/tertiary things from the committee param?
func (m *CCIP17EVM) ConnectContractsWithSelectors(ctx context.Context, e *deployment.Environment, selector uint64, remoteSelectors []uint64, committees []cciptestinterfaces.OnChainCommittees) error {
	// TODO: how does this even work?
	/*
		if selector != m.chain.ChainSelector() {
			return fmt.Errorf("ConnectContractsWithSelectors: chain %d not found in environment chains %v", selector, m.chain.ChainSelector())
		}
	*/

	l := m.logger
	l.Info().Uint64("FromSelector", selector).Any("ToSelectors", remoteSelectors).Msg("Connecting contracts with selectors")
	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)
	e.OperationsBundle = bundle

	remoteChains := make(map[uint64]adapters.RemoteChainConfig[datastore.AddressRef, datastore.AddressRef])
	for _, rs := range remoteSelectors {
		remoteChains[rs] = adapters.RemoteChainConfig[datastore.AddressRef, datastore.AddressRef]{
			AllowTrafficFrom: true,
			OnRamp: datastore.AddressRef{
				Type:    datastore.ContractType(onrampoperations.ContractType),
				Version: semver.MustParse(onrampoperations.Deploy.Version()),
			},
			OffRamp: datastore.AddressRef{
				Type:    datastore.ContractType(offrampoperations.ContractType),
				Version: semver.MustParse(offrampoperations.Deploy.Version()),
			},
			DefaultInboundCCVs: []datastore.AddressRef{
				{
					Type:          datastore.ContractType(committee_verifier.ResolverProxyType),
					Version:       semver.MustParse(committee_verifier.Deploy.Version()),
					ChainSelector: selector,
					Qualifier:     DefaultCommitteeVerifierQualifier, // TODO: pull this from committees param?
				},
			},
			// LaneMandatedInboundCCVs: []datastore.AddressRef{},
			DefaultOutboundCCVs: []datastore.AddressRef{
				{
					Type:          datastore.ContractType(committee_verifier.ResolverProxyType),
					Version:       semver.MustParse(committee_verifier.Deploy.Version()),
					ChainSelector: selector,
					Qualifier:     DefaultCommitteeVerifierQualifier, // TODO: pull this from committees param?
				},
			},
			// LaneMandatedOutboundCCVs: []datastore.AddressRef{},
			DefaultExecutor: datastore.AddressRef{
				Type:    datastore.ContractType(executor.ContractType),
				Version: semver.MustParse(executor.Deploy.Version()),
			},
			CommitteeVerifierDestChainConfig: adapters.CommitteeVerifierDestChainConfig{
				AllowlistEnabled:   false,
				GasForVerification: CommitteeVerifierGasForVerification,
				FeeUSDCents:        0, // TODO: set proper fee
				PayloadSizeBytes:   0, // TODO: set proper payload size
			},
			FeeQuoterDestChainConfig: adapters.FeeQuoterDestChainConfig{
				IsEnabled:                   true,
				MaxDataBytes:                30_000,
				MaxPerMsgGasLimit:           3_000_000,
				DestGasOverhead:             300_000,
				DefaultTokenFeeUSDCents:     25,
				DestGasPerPayloadByteBase:   16,
				DefaultTokenDestGasOverhead: 90_000,
				DefaultTxGasLimit:           200_000,
				NetworkFeeUSDCents:          10,
				ChainFamilySelector:         [4]byte{0x28, 0x12, 0xd5, 0x2c}, // EVM
				LinkFeeMultiplierPercent:    90,
				USDPerUnitGas:               big.NewInt(1e6),
			},
			ExecutorDestChainConfig: adapters.ExecutorDestChainConfig{
				Enabled:     true,
				USDCentsFee: 0, // TODO: set proper fee
			},
			AddressBytesLength:   20,      // TODO: set proper address bytes length, should be evm-agnostic
			BaseExecutionGasCost: 150_000, // TODO: set proper base execution gas cost
		}
	}

	mcmsReaderRegistry := changesetscore.NewMCMSReaderRegistry()
	chainFamilyRegistry := adapters.NewChainFamilyRegistry()
	chainFamilyRegistry.RegisterChainFamily("evm", &evmadapters.ChainFamilyAdapter{})
	_, err := changesets.ConfigureChainsForLanes(chainFamilyRegistry, mcmsReaderRegistry).Apply(*e, changesets.ConfigureChainsForLanesConfig{
		Chains: []changesets.ChainConfig{
			{
				ChainSelector: selector,
				RemoteChains:  remoteChains,
				FeeQuoter: datastore.AddressRef{
					Type:    datastore.ContractType(fee_quoter.ContractType),
					Version: semver.MustParse(fee_quoter.Deploy.Version()),
				},
				OnRamp: datastore.AddressRef{
					Type:    datastore.ContractType(onrampoperations.ContractType),
					Version: semver.MustParse(onrampoperations.Deploy.Version()),
				},
				OffRamp: datastore.AddressRef{
					Type:    datastore.ContractType(offrampoperations.ContractType),
					Version: semver.MustParse(offrampoperations.Deploy.Version()),
				},
				Router: datastore.AddressRef{
					Type:    datastore.ContractType(routeroperations.ContractType),
					Version: semver.MustParse(routeroperations.Deploy.Version()),
				},
				CommitteeVerifiers: toComitteeVerifier(selector, committees),
			},
		},
	})
	if err != nil {
		return err
	}

	tokenAdapterRegistry := tokenscore.NewTokenAdapterRegistry()
	for _, poolVersion := range tokenPoolVersions {
		tokenAdapterRegistry.RegisterTokenAdapter("evm", semver.MustParse(poolVersion), &evmadapters.TokenAdapter{})
	}

	for _, combo := range AllTokenCombinations() {
		// For any given token combination, every chain needs to support the source and destination pools.
		l.Info().Str("Token", combo.SourcePoolAddressRef().Qualifier).Msg("Configuring source token for transfer")
		if err := m.configureTokenForTransfer(e, tokenAdapterRegistry, mcmsReaderRegistry, selector, remoteSelectors, combo.SourcePoolAddressRef(), combo.DestPoolAddressRef(), combo.SourcePoolCCVQualifiers()); err != nil {
			return fmt.Errorf("failed to configure %s tokens for transfers: %w", combo.SourcePoolAddressRef().Qualifier, err)
		}
		l.Info().Str("Token", combo.DestPoolAddressRef().Qualifier).Msg("Configuring destination token for transfer")
		if err := m.configureTokenForTransfer(e, tokenAdapterRegistry, mcmsReaderRegistry, selector, remoteSelectors, combo.DestPoolAddressRef(), combo.SourcePoolAddressRef(), combo.DestPoolCCVQualifiers()); err != nil {
			return fmt.Errorf("failed to configure %s tokens for transfers: %w", combo.DestPoolAddressRef().Qualifier, err)
		}
	}

	return nil
}

func (m *CCIP17EVM) FundAddresses(ctx context.Context, bc *blockchain.Input, addresses []protocol.UnknownAddress, nativeAmount *big.Int) error {
	client, _, _, err := ETHClient(ctx, bc.Out.Nodes[0].ExternalWSUrl, &GasSettings{
		FeeCapMultiplier: 2,
		TipCapMultiplier: 2,
	})
	if err != nil {
		return fmt.Errorf("could not create basic eth client: %w", err)
	}
	chainInfo, err := chainsel.GetChainDetailsByChainIDAndFamily(bc.ChainID, chainsel.FamilyEVM)
	if err != nil {
		return fmt.Errorf("could not get chain details: %w", err)
	}
	for _, addr := range addresses {
		a, _ := nativeAmount.Float64()
		addrStr := common.BytesToAddress(addr).Hex()
		m.logger.Info().Uint64("ChainSelector", chainInfo.ChainSelector).Str("Address", addrStr).Msg("Funding address")
		if err := FundNodeEIP1559(ctx, client, getNetworkPrivateKey(), addrStr, a); err != nil {
			return fmt.Errorf("failed to fund address %s: %w", addrStr, err)
		}
		bal, err := client.BalanceAt(ctx, common.HexToAddress(addrStr), nil)
		if err != nil {
			return fmt.Errorf("failed to get balance: %w", err)
		}
		m.logger.Info().Uint64("ChainSelector", chainInfo.ChainSelector).Str("Address", addrStr).Int64("Balance", bal.Int64()).Msg("Address balance")
	}
	return nil
}

func (m *CCIP17EVM) FundNodes(ctx context.Context, ns []*simple_node_set.Input, bc *blockchain.Input, linkAmount, nativeAmount *big.Int) error {
	l := m.logger
	l.Info().Msg("Funding CL nodes with ETH and LINK")
	nodeClients := make([]*clclient.ChainlinkClient, 0)
	for _, n := range ns {
		nc, err := clclient.New(n.Out.CLNodes)
		if err != nil {
			return fmt.Errorf("connecting to CL nodes: %w", err)
		}
		nodeClients = append(nodeClients, nc...)
	}
	ethKeyAddressesSrc := make([]string, 0)
	for i, nc := range nodeClients {
		addrSrc, err := nc.ReadPrimaryETHKey(bc.ChainID)
		if err != nil {
			return fmt.Errorf("getting primary ETH key from OCR node %d (src chain): %w", i, err)
		}
		ethKeyAddressesSrc = append(ethKeyAddressesSrc, addrSrc.Attributes.Address)
		l.Info().
			Int("Idx", i).
			Str("ETHKeySrc", addrSrc.Attributes.Address).
			Msg("Node info")
	}
	clientSrc, _, _, err := ETHClient(ctx, bc.Out.Nodes[0].ExternalWSUrl, &GasSettings{
		FeeCapMultiplier: 2,
		TipCapMultiplier: 2,
	})
	if err != nil {
		return fmt.Errorf("could not create basic eth client: %w", err)
	}
	for _, addr := range ethKeyAddressesSrc {
		a, _ := nativeAmount.Float64()
		if err := FundNodeEIP1559(ctx, clientSrc, getNetworkPrivateKey(), addr, a); err != nil {
			return fmt.Errorf("failed to fund CL nodes on src chain: %w", err)
		}
	}
	return nil
}

// GetContractAddrForSelector get contract address by type and chain selector.
func GetContractAddrForSelector(addresses []string, selector uint64, contractType datastore.ContractType) (common.Address, error) {
	var contractAddr common.Address
	for _, addr := range addresses {
		var refs []datastore.AddressRef
		err := json.Unmarshal([]byte(addr), &refs)
		if err != nil {
			return common.Address{}, err
		}
		for _, ref := range refs {
			if ref.ChainSelector == selector && ref.Type == contractType {
				contractAddr = common.HexToAddress(ref.Address)
			}
		}
	}
	return contractAddr, nil
}

// fundLockReleaseTokenPool funds a lock/release token pool by transferring tokens from deployer.
func (m *CCIP17EVM) fundLockReleaseTokenPool(
	env *deployment.Environment,
	selector uint64,
	tokenPoolRef datastore.AddressRef,
	amount *big.Int,
) error {
	poolType := datastore.ContractType(lock_release_token_pool.ContractType)
	qualifier := tokenPoolRef.Qualifier
	// Get token address reference
	tokenRef, err := env.DataStore.Addresses().Get(datastore.NewAddressRefKey(selector, datastore.ContractType(burnminterc677ops.ContractType), semver.MustParse(burnminterc677ops.Deploy.Version()), qualifier))
	if err != nil {
		return fmt.Errorf("failed to get token address for %s %s pool: %w", qualifier, poolType, err)
	}

	txOps := env.BlockChains.EVMChains()[selector].DeployerKey
	client := env.BlockChains.EVMChains()[selector].Client

	// Create token contract instance
	tokenAddress := common.HexToAddress(tokenRef.Address)
	token, err := burn_mint_erc677.NewBurnMintERC677(tokenAddress, client)
	if err != nil {
		return fmt.Errorf("failed to create ERC20 token instance: %w", err)
	}

	// Transfer tokens from deployer to the token pool
	tx, err := token.Transfer(txOps, common.HexToAddress(tokenPoolRef.Address), amount)
	if err != nil {
		return fmt.Errorf("failed to create transfer transaction: %w", err)
	}

	// Wait for transfer transaction to be mined
	receipt, err := bind.WaitMined(context.Background(), client, tx.Hash())
	if err != nil {
		return fmt.Errorf("failed to wait for transfer transaction to be mined: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("transfer transaction failed with status: %d", receipt.Status)
	}

	return nil
}

func (m *CCIP17EVM) ManuallyExecuteMessage(
	ctx context.Context,
	message protocol.Message,
	gasLimit uint64,
	ccvs []protocol.UnknownAddress,
	verifierResults [][]byte,
) (cciptestinterfaces.ExecutionStateChangedEvent, error) {
	destChainSelector := uint64(message.DestChainSelector)
	if destChainSelector != m.chain.ChainSelector() {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("ManuallyExecuteMessage: chain %d not found in environment chains %v", destChainSelector, m.chain.ChainSelector())
	}

	offRamp := m.offRamp
	privateKeyString := getNetworkPrivateKey()
	privKey, err := crypto.HexToECDSA(privateKeyString)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to parse private key: %w", err)
	}
	chainID, err := m.ethClient.ChainID(ctx)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get chain ID: %w", err)
	}

	transactOpts := bind.NewKeyedTransactor(privKey, chainID)
	transactOpts.GasLimit = gasLimit

	encodedMsg, err := message.Encode()
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to encode message: %w", err)
	}

	ccvAddresses := make([]common.Address, 0, len(ccvs))
	for _, ccv := range ccvs {
		ccvAddresses = append(ccvAddresses, common.HexToAddress(ccv.String()))
	}

	results := make([]string, 0, len(verifierResults))
	for _, result := range verifierResults {
		results = append(results, hexutil.Encode(result))
	}
	m.logger.Info().
		Str("MessageID", message.MustMessageID().String()).
		Any("Message", message).
		Any("CCVs", ccvAddresses).
		Int("NumVerifierResults", len(verifierResults)).
		Strs("VerifierResults", results).
		Uint64("ChainSelector", destChainSelector).
		Msg("Executing message")

	tx, err := offRamp.Execute(&bind.TransactOpts{
		From:     transactOpts.From,
		Signer:   transactOpts.Signer,
		Context:  ctx,
		GasLimit: gasLimit,
	}, encodedMsg, ccvAddresses, verifierResults)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to execute off ramp: %w", err)
	}

	receipt, err := bind.WaitMined(ctx, m.ethClient, tx.Hash())
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to wait for execution transaction to be mined: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("execution transaction failed with status: %d", receipt.Status)
	}

	// fetch the event from the receipt's logs
	topic := offramp.OffRampExecutionStateChanged{}.Topic()
	var event cciptestinterfaces.ExecutionStateChangedEvent
	for _, lg := range receipt.Logs {
		if lg.Address == offRamp.Address() &&
			lg.Topics[0] == topic {
			parsedLog, err := offRamp.ParseExecutionStateChanged(*lg)
			if err != nil {
				m.logger.Warn().Err(err).Msg("Failed to parse execution state changed event")
				continue
			}
			event = cciptestinterfaces.ExecutionStateChangedEvent{
				MessageID:      parsedLog.MessageId,
				SequenceNumber: parsedLog.SequenceNumber,
				State:          cciptestinterfaces.MessageExecutionState(parsedLog.State),
				ReturnData:     parsedLog.ReturnData,
			}
			break
		}
	}

	m.logger.Info().
		Str("TxHash", tx.Hash().Hex()).
		Uint64("ChainSelector", destChainSelector).
		Any("Event", event).
		Msg("Execution transaction mined")

	return event, nil
}
