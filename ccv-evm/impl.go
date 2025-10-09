package ccv_evm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/changesets"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/ccv_aggregator"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/ccv_proxy"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/executor_onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/fee_quoter_v2"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/sequences"
	ccvAggregator "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	ccvProxy "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_proxy"
	cciptestinterfaces "github.com/smartcontractkit/chainlink-ccv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	ccvAggregatorOps "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/ccv_aggregator"
	ccvProxyOps "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/ccv_proxy"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

type CCIP17EVM struct {
	e                      *deployment.Environment
	chainDetailsBySelector map[uint64]chainsel.ChainDetails
	ethClients             map[uint64]*ethclient.Client
	proxyBySelector        map[uint64]*ccvProxy.CCVProxy
	aggBySelector          map[uint64]*ccvAggregator.CCVAggregator
}

// NewCCIP17EVM creates new smart-contracts wrappers with utility functions for CCIP17EVM implementation
func NewCCIP17EVM(ctx context.Context, e *deployment.Environment, chainIDs []string, wsURLs []string) (*CCIP17EVM, error) {
	if len(chainIDs) != len(wsURLs) {
		return nil, fmt.Errorf("len(chainIDs) != len(wsURLs) ; %d != %d", len(chainIDs), len(wsURLs))
	}

	gas := &GasSettings{
		FeeCapMultiplier: 2,
		TipCapMultiplier: 2,
	}
	var (
		chainDetailsBySelector = make(map[uint64]chainsel.ChainDetails)
		ethClients             = make(map[uint64]*ethclient.Client)
		proxyBySelector        = make(map[uint64]*ccvProxy.CCVProxy)
		aggBySelector          = make(map[uint64]*ccvAggregator.CCVAggregator)
	)
	for i := range chainIDs {
		chainDetails, err := chainsel.GetChainDetailsByChainIDAndFamily(chainIDs[i], chainsel.FamilyEVM)
		if err != nil {
			return nil, fmt.Errorf("get chain details for chain %s: %w", chainIDs[i], err)
		}

		chainDetailsBySelector[chainDetails.ChainSelector] = chainDetails

		client, _, _, err := ETHClient(ctx, wsURLs[i], gas)
		if err != nil {
			return nil, fmt.Errorf("create eth client for chain %s: %w", chainIDs[i], err)
		}
		ethClients[chainDetails.ChainSelector] = client

		proxyAddressRef, err := e.DataStore.Addresses().Get(datastore.NewAddressRefKey(
			chainDetails.ChainSelector,
			datastore.ContractType(ccvProxyOps.ContractType),
			semver.MustParse("1.7.0"),
			"",
		))
		if err != nil {
			return nil, fmt.Errorf("get proxy address for chain %d (id %s) from datastore: %w", chainDetails.ChainSelector, chainIDs[i], err)
		}
		aggAddressRef, err := e.DataStore.Addresses().Get(datastore.NewAddressRefKey(
			chainDetails.ChainSelector,
			datastore.ContractType(ccvAggregatorOps.ContractType),
			semver.MustParse("1.7.0"),
			"",
		))
		if err != nil {
			return nil, fmt.Errorf("get aggregator address for chain %d (id %s) from datastore: %w", chainDetails.ChainSelector, chainIDs[i], err)
		}
		proxy, err := ccvProxy.NewCCVProxy(common.HexToAddress(proxyAddressRef.Address), client)
		if err != nil {
			return nil, fmt.Errorf("create proxy wrapper for chain %d (id %s): %w", chainDetails.ChainSelector, chainIDs[i], err)
		}
		aggregator, err := ccvAggregator.NewCCVAggregator(common.HexToAddress(aggAddressRef.Address), client)
		if err != nil {
			return nil, fmt.Errorf("create aggregator wrapper for chain %d (id %s): %w", chainDetails.ChainSelector, chainIDs[i], err)
		}

		proxyBySelector[chainDetails.ChainSelector] = proxy
		aggBySelector[chainDetails.ChainSelector] = aggregator
	}

	return &CCIP17EVM{
		e:                      e,
		chainDetailsBySelector: chainDetailsBySelector,
		ethClients:             ethClients,
		proxyBySelector:        proxyBySelector,
		aggBySelector:          aggBySelector,
	}, nil
}

// fetchAllSentEventsBySelector fetch all CCIPMessageSent events from proxy contract
func (m *CCIP17EVM) fetchAllSentEventsBySelector(ctx context.Context, from, to uint64) ([]*ccvProxy.CCVProxyCCIPMessageSent, error) {
	l := zerolog.Ctx(ctx)
	proxy, ok := m.proxyBySelector[from]
	if !ok {
		return nil, fmt.Errorf("no proxy for selector %d", from)
	}
	filter, err := proxy.FilterCCIPMessageSent(&bind.FilterOpts{}, []uint64{to}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create filter: %w", err)
	}
	defer filter.Close()

	var events []*ccvProxy.CCVProxyCCIPMessageSent

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

// fetchAllExecEventsBySelector fetch all ExecutionStateChanged events from aggregator contract
func (m *CCIP17EVM) fetchAllExecEventsBySelector(ctx context.Context, from, to uint64) ([]*ccvAggregator.CCVAggregatorExecutionStateChanged, error) {
	l := zerolog.Ctx(ctx)
	agg, ok := m.aggBySelector[from]
	if !ok {
		return nil, fmt.Errorf("no aggregator for selector %d", from)
	}
	filter, err := agg.FilterExecutionStateChanged(&bind.FilterOpts{}, []uint64{to}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create filter: %w", err)
	}
	defer filter.Close()

	var events []*ccvAggregator.CCVAggregatorExecutionStateChanged

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
	p, ok := m.proxyBySelector[from]
	if !ok {
		return 0, fmt.Errorf("failed to assert proxy by selector")
	}
	return p.GetExpectedNextSequenceNumber(&bind.CallOpts{Context: ctx}, to)
}

// WaitOneSentEventBySeqNo wait and fetch strictly one CCIPMessageSent event by selector and sequence number and selector
func (m *CCIP17EVM) WaitOneSentEventBySeqNo(ctx context.Context, from, to uint64, seq uint64, timeout time.Duration) (any, error) {
	l := zerolog.Ctx(ctx)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	proxy, ok := m.proxyBySelector[from]
	if !ok {
		return nil, fmt.Errorf("no proxy for selector %d", from)
	}

	l.Info().Msg("Awaiting CCIPMessageSent event")

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			filter, err := proxy.FilterCCIPMessageSent(&bind.FilterOpts{}, []uint64{to}, []uint64{seq}, nil)
			if err != nil {
				l.Warn().Err(err).Msg("Failed to create filter")
				continue
			}
			var eventFound *ccvProxy.CCVProxyCCIPMessageSent
			eventCount := 0

			for filter.Next() {
				eventCount++
				if eventCount > 1 {
					filter.Close()
					return nil, fmt.Errorf("received multiple events for the same sequence number and selector")
				}
				eventFound = filter.Event
				l.Info().
					Any("TxHash", filter.Event.Raw.TxHash.Hex()).
					Any("SeqNo", filter.Event.SequenceNumber).
					Str("MsgID", hexutil.Encode(filter.Event.MessageId[:])).
					Msg("Received CCIPMessageSent event")
			}
			if err := filter.Error(); err != nil {
				l.Warn().Err(err).Msg("Filter error")
			}
			filter.Close()
			if eventFound != nil {
				return eventFound, nil
			}
		}
	}
}

// WaitOneExecEventBySeqNo wait and fetch strictly one ExecutionStateChanged event by sequence number and selector
func (m *CCIP17EVM) WaitOneExecEventBySeqNo(ctx context.Context, from, to uint64, seq uint64, timeout time.Duration) (any, error) {
	l := zerolog.Ctx(ctx)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	agg, ok := m.aggBySelector[to]
	if !ok {
		return nil, fmt.Errorf("no aggregator for selector %d", to)
	}

	l.Info().Msg("Awaiting ExecutionStateChanged event")

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			filter, err := agg.FilterExecutionStateChanged(&bind.FilterOpts{}, []uint64{from}, []uint64{seq}, nil)
			if err != nil {
				l.Warn().Err(err).Msg("Failed to create filter")
				continue
			}

			var eventFound *ccvAggregator.CCVAggregatorExecutionStateChanged
			eventCount := 0

			for filter.Next() {
				eventCount++
				if eventCount > 1 {
					filter.Close()
					return nil, fmt.Errorf("received multiple events for the same sequence number and selector")
				}

				eventFound = filter.Event
				l.Info().
					Any("State", filter.Event.State).
					Any("TxHash", filter.Event.Raw.TxHash.Hex()).
					Any("SeqNo", filter.Event.SequenceNumber).
					Str("MsgID", hexutil.Encode(filter.Event.MessageId[:])).
					Msg("Received ExecutionStateChanged event")
			}

			if err := filter.Error(); err != nil {
				l.Warn().Err(err).Msg("Filter error")
			}

			filter.Close()

			if eventFound != nil {
				return eventFound, nil
			}
		}
	}
}

func (m *CCIP17EVM) SendMessage(ctx context.Context, src, dest uint64, fields cciptestinterfaces.MessageFields, opts cciptestinterfaces.MessageOptions) error {
	l := zerolog.Ctx(ctx)
	chains := m.e.BlockChains.EVMChains()
	if chains == nil {
		return errors.New("no EVM chains found")
	}

	srcChain, ok := chains[src]
	if !ok {
		return fmt.Errorf("source chain %d not found in environment chains %v", src, chains)
	}

	destFamily, err := chainsel.GetSelectorFamily(dest)
	if err != nil {
		return fmt.Errorf("failed to get destination family: %w", err)
	}

	routerRef, err := m.e.DataStore.Addresses().Get(datastore.NewAddressRefKey(srcChain.Selector, datastore.ContractType(router.ContractType), semver.MustParse("1.2.0"), ""))
	if err != nil {
		return fmt.Errorf("failed to get router address: %w", err)
	}

	routerAddress := common.HexToAddress(routerRef.Address)

	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		m.e.Logger,
		operations.NewMemoryReporter(),
	)

	var tokenAmounts []router.EVMTokenAmount
	for _, tokenAmount := range fields.TokenAmounts {
		tokenAmounts = append(tokenAmounts, router.EVMTokenAmount{
			Token:  common.HexToAddress(tokenAmount.TokenAddress.String()),
			Amount: tokenAmount.Amount,
		})
	}

	ccipSendArgs := router.CCIPSendArgs{
		DestChainSelector: dest,
		EVM2AnyMessage: router.EVM2AnyMessage{
			Receiver:     common.LeftPadBytes(common.HexToAddress(fields.Receiver.String()).Bytes(), 32),
			Data:         fields.Data,
			TokenAmounts: tokenAmounts,
			FeeToken:     common.HexToAddress(fields.FeeToken.String()),
			ExtraArgs:    serializeExtraArgs(opts, destFamily),
		},
	}

	// Send CCIP message with value
	sendReport, err := operations.ExecuteOperation(bundle, router.CCIPSend, srcChain, contract.FunctionInput[router.CCIPSendArgs]{
		ChainSelector: src,
		Address:       routerAddress,
		Args:          ccipSendArgs,
	})
	if err != nil {
		return fmt.Errorf("failed to send CCIP message: %w", err)
	}
	l.Info().Bool("Executed", sendReport.Output.Executed).
		Uint64("SrcChainSelector", sendReport.Output.ChainSelector).
		Uint64("DestChainSelector", dest).
		Str("SrcRouter", sendReport.Output.Tx.To). // TODO: how to get the message id?
		Msg("CCIP message sent")
	return nil
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

	packed, err := arguments.Pack(EVMExtraArgsV1{GasLimit: big.NewInt(int64(opts.GasLimit))})
	if err != nil {
		panic(fmt.Sprintf("failed to pack extraArgs: %v", err))
	}

	selector, _ := hexutil.Decode("0x97a657c9")
	return append(selector, packed...)
}

func serializeExtraArgsV2(opts cciptestinterfaces.MessageOptions) []byte {
	// 	// Tag to indicate a gas limit (or dest chain equivalent processing units) and Out Of Order Execution. This tag is
	//   // available for multiple chain families. If there is no chain family specific tag, this is the default available
	//   // for a chain.
	//   // Note: not available for Solana VM based chains.
	//   bytes4 public constant GENERIC_EXTRA_ARGS_V2_TAG = 0x181dcf10;

	//   /// @param gasLimit: gas limit for the callback on the destination chain.
	//   /// @param allowOutOfOrderExecution: if true, it indicates that the message can be executed in any order relative to
	//   /// other messages from the same sender. This value's default varies by chain. On some chains, a particular value is
	//   /// enforced, meaning if the expected value is not set, the message request will revert.
	//   /// @dev Fully compatible with the previously existing EVMExtraArgsV2.
	//   struct GenericExtraArgsV2 {
	//     uint256 gasLimit;
	//     bool allowOutOfOrderExecution;
	//   }
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
		GasLimit:                 big.NewInt(int64(opts.GasLimit)),
		AllowOutOfOrderExecution: opts.OutOfOrderExecution,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to pack extraArgs: %v", err))
	}

	selector, _ := hexutil.Decode("0x181dcf10")
	return append(selector, packed...)
}

func serializeExtraArgsV3(opts cciptestinterfaces.MessageOptions) []byte {
	ccvComponents := []abi.ArgumentMarshaling{
		{Name: "ccvAddress", Type: "address"},
		{Name: "args", Type: "bytes"},
	}

	evmExtraArgsV3Type, err := abi.NewType("tuple", "EVMExtraArgsV3", []abi.ArgumentMarshaling{
		{Name: "requiredCCV", Type: "tuple[]", Components: ccvComponents},
		{Name: "optionalCCV", Type: "tuple[]", Components: ccvComponents},
		{Name: "optionalThreshold", Type: "uint8"},
		{Name: "finalityConfig", Type: "uint16"},
		{Name: "executor", Type: "address"},
		{Name: "executorArgs", Type: "bytes"},
		{Name: "tokenArgs", Type: "bytes"},
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create EVMExtraArgsV3 tuple type: %v", err))
	}

	arguments := abi.Arguments{
		{
			Type: evmExtraArgsV3Type,
			Name: "extraArgs",
		},
	}

	type CCV struct {
		CcvAddress common.Address
		Args       []byte
	}

	type EVMExtraArgsV3 struct {
		RequiredCCV       []CCV
		OptionalCCV       []CCV
		OptionalThreshold uint8
		FinalityConfig    uint16
		Executor          common.Address
		ExecutorArgs      []byte
		TokenArgs         []byte
	}

	var requiredCCVs []CCV
	for _, ccv := range opts.MandatoryCCVs {
		requiredCCVs = append(requiredCCVs, CCV{
			CcvAddress: common.HexToAddress(ccv.CCVAddress.String()),
			Args:       ccv.Args,
		})
	}

	var optionalCCVs []CCV
	for _, ccv := range opts.OptionalCCVs {
		optionalCCVs = append(optionalCCVs, CCV{
			CcvAddress: common.HexToAddress(ccv.CCVAddress.String()),
			Args:       ccv.Args,
		})
	}

	packed, err := arguments.Pack(EVMExtraArgsV3{
		RequiredCCV:       requiredCCVs,
		OptionalCCV:       optionalCCVs,
		OptionalThreshold: opts.OptionalThreshold,
		FinalityConfig:    opts.FinalityConfig,
		Executor:          common.HexToAddress(opts.Executor.String()),
		ExecutorArgs:      opts.ExecutorArgs,
		TokenArgs:         opts.TokenArgs,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to pack extraArgs: %v", err))
	}

	selector, _ := hexutil.Decode("0x302326cb")
	return append(selector, packed...)
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
	chainIDs []string,
	wsURLs []string,
) ([]string, *prometheus.Registry, error) {
	msgSentTotal.Reset()
	msgExecTotal.Reset()
	srcDstLatency.Reset()

	reg := prometheus.NewRegistry()
	reg.MustRegister(msgSentTotal, msgExecTotal, srcDstLatency)

	lp := NewLokiPusher()
	tp := NewTempoPusher()
	c, err := NewCCIP17EVM(ctx, m.e, chainIDs, wsURLs)
	if err != nil {
		return nil, nil, err
	}
	err = ProcessLaneEvents(ctx, c, lp, tp, &LaneStreamConfig{
		FromSelector:      source,
		ToSelector:        dest,
		AggregatorAddress: "localhost:50051",
		AggregatorSince:   0,
	})
	if err != nil {
		return nil, nil, err
	}
	err = ProcessLaneEvents(ctx, c, lp, tp, &LaneStreamConfig{
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
	l := zerolog.Ctx(ctx)
	l.Info().Msg("Deploying EVM networks")
	out, err := blockchain.NewBlockchainNetwork(bc)
	if err != nil {
		return nil, fmt.Errorf("failed to create blockchain network: %w", err)
	}
	return out, nil
}

func (m *CCIP17EVM) ConfigureNodes(ctx context.Context, bc *blockchain.Input) (string, error) {
	l := zerolog.Ctx(ctx)
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

// getCommitteeSignatureConfig returns the committee configuration for a specific chain selector
func getCommitteeSignatureConfig(selector uint64) commit_offramp.SetSignatureConfigArgs {
	// Default configuration with 2 signers and threshold=2
	defaultConfig := commit_offramp.SetSignatureConfigArgs{
		Threshold: 2,
		Signers: []common.Address{
			// TODO: why are these addresses hardcoded? where are they fetched from?
			common.HexToAddress("0x6b3131d871c63c7fa592863e173cba2da5ffa68b"),
			common.HexToAddress("0x099125558781da4bcdb16e457e15d997ecac68a8"),
		},
	}

	// Special configuration for chain 3337 (selector 4793464827907405086) - threshold=1
	if selector == 4793464827907405086 {
		return commit_offramp.SetSignatureConfigArgs{
			Threshold: 1,
			Signers: []common.Address{
				common.HexToAddress("0x6b3131d871c63c7fa592863e173cba2da5ffa68b"),
			},
		}
	}

	return defaultConfig
}

func (m *CCIP17EVM) DeployContractsForSelector(ctx context.Context, env *deployment.Environment, selector uint64) (datastore.DataStore, error) {
	l := zerolog.Ctx(ctx)
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

	out, err := changesets.DeployChainContracts.Apply(*env, changesets.DeployChainContractsCfg{
		ChainSel: selector,
		Params: sequences.ContractParams{
			// TODO: Router contract implementation is missing
			RMNRemote:     sequences.RMNRemoteParams{},
			CCVAggregator: sequences.CCVAggregatorParams{},
			CommitOnRamp: sequences.CommitOnRampParams{
				// TODO: add mocked contract here
				FeeAggregator: common.HexToAddress("0x01"),
			},
			CCVProxy: sequences.CCVProxyParams{
				FeeAggregator: common.HexToAddress("0x01"),
			},
			ExecutorOnRamp: sequences.ExecutorOnRampParams{
				MaxCCVsPerMsg: 10,
			},
			FeeQuoter: sequences.FeeQuoterParams{
				// expose in TOML config
				MaxFeeJuelsPerMsg:              big.NewInt(2e18),
				TokenPriceStalenessThreshold:   uint32(24 * 60 * 60),
				LINKPremiumMultiplierWeiPerEth: 9e17, // 0.9 ETH
				WETHPremiumMultiplierWeiPerEth: 1e18, // 1.0 ETH
				USDPerLINK:                     usdPerLink,
				USDPerWETH:                     usdPerWeth,
			},
			CommitOffRamp: sequences.CommitOffRampParams{
				SignatureConfigArgs: getCommitteeSignatureConfig(selector),
			},
		},
	})
	if err != nil {
		return nil, err
	}

	addresses, err := out.DataStore.Addresses().Fetch()
	if err != nil {
		return nil, err
	}
	_, err = json.Marshal(addresses)
	if err != nil {
		return nil, err
	}
	env.DataStore = runningDS.Seal()
	return out.DataStore.Seal(), nil
}

func (m *CCIP17EVM) ConnectContractsWithSelectors(ctx context.Context, e *deployment.Environment, selector uint64, remoteSelectors []uint64) error {
	l := zerolog.Ctx(ctx)
	l.Info().Uint64("FromSelector", selector).Any("ToSelectors", remoteSelectors).Msg("Connecting contracts with selectors")
	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)
	e.OperationsBundle = bundle

	remoteChains := make(map[uint64]changesets.RemoteChainConfig)

	for _, rs := range remoteSelectors {
		remoteChains[rs] = changesets.RemoteChainConfig{
			AllowTrafficFrom: true,
			CCIPMessageSource: datastore.AddressRef{
				Type:    datastore.ContractType(ccv_proxy.ContractType),
				Version: semver.MustParse("1.7.0"),
			},
			CCIPMessageDest: datastore.AddressRef{
				Type:    datastore.ContractType(ccv_aggregator.ContractType),
				Version: semver.MustParse("1.7.0"),
			},
			DefaultCCVOffRamps: []datastore.AddressRef{
				{Type: datastore.ContractType(commit_offramp.ContractType), Version: semver.MustParse("1.7.0")},
			},
			// LaneMandatedCCVOffRamps: []datastore.AddressRef{},
			DefaultCCVOnRamps: []datastore.AddressRef{
				{Type: datastore.ContractType(commit_onramp.ContractType), Version: semver.MustParse("1.7.0")},
			},
			// LaneMandatedCCVOnRamps: []datastore.AddressRef{},
			DefaultExecutor: datastore.AddressRef{
				Type:    datastore.ContractType(executor_onramp.ContractType),
				Version: semver.MustParse("1.7.0"),
			},
			CommitOnRampDestChainConfig: sequences.CommitOnRampDestChainConfig{
				AllowlistEnabled: false,
			},
			FeeQuoterDestChainConfig: fee_quoter_v2.DestChainConfig{
				IsEnabled:                         true,
				MaxNumberOfTokensPerMsg:           10,
				MaxDataBytes:                      30_000,
				MaxPerMsgGasLimit:                 3_000_000,
				DestGasOverhead:                   300_000,
				DefaultTokenFeeUSDCents:           25,
				DestGasPerPayloadByteBase:         16,
				DestGasPerPayloadByteHigh:         40,
				DestGasPerPayloadByteThreshold:    3000,
				DestDataAvailabilityOverheadGas:   100,
				DestGasPerDataAvailabilityByte:    16,
				DestDataAvailabilityMultiplierBps: 1,
				DefaultTokenDestGasOverhead:       90_000,
				DefaultTxGasLimit:                 200_000,
				GasMultiplierWeiPerEth:            11e17, // Gas multiplier in wei per eth is scaled by 1e18, so 11e17 is 1.1 = 110%
				NetworkFeeUSDCents:                10,
				ChainFamilySelector:               [4]byte{0x28, 0x12, 0xd5, 0x2c}, // EVM
			},
		}
	}

	_, err := changesets.ConfigureChainForLanes.Apply(*e, changesets.ConfigureChainForLanesCfg{
		ChainSel:     selector,
		RemoteChains: remoteChains,
	})
	if err != nil {
		return err
	}
	return nil
}

func (m *CCIP17EVM) FundNodes(ctx context.Context, ns []*simple_node_set.Input, bc *blockchain.Input, linkAmount, nativeAmount *big.Int) error {
	l := zerolog.Ctx(ctx)
	l.Info().Msg("Funding CL nodes with ETH and LINK")
	nodeClients, err := clclient.New(ns[0].Out.CLNodes)
	if err != nil {
		return fmt.Errorf("connecting to CL nodes: %w", err)
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
