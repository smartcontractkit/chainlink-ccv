package ccv_evm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
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
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/sequences"
	ccvAggregator "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	ccvProxy "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_proxy"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
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
	Chain1337Details       chainsel.ChainDetails
	Chain2337Details       chainsel.ChainDetails
	Chain3337Details       chainsel.ChainDetails
	ChainDetailsBySelector map[uint64]chainsel.ChainDetails
	ProxyBySelector        map[uint64]*ccvProxy.CCVProxy
	AggBySelector          map[uint64]*ccvAggregator.CCVAggregator
}

// NewCCIP17EVM creates new smart-contracts wrappers with utility functions for CCIP17EVM implementation
func NewCCIP17EVM(ctx context.Context, addresses []string, chainIDs []string, wsURLs []string) (*CCIP17EVM, error) {
	srcChain, err := chainsel.GetChainDetailsByChainIDAndFamily(chainIDs[0], chainsel.FamilyEVM)
	if err != nil {
		return nil, err
	}
	dstChain, err := chainsel.GetChainDetailsByChainIDAndFamily(chainIDs[1], chainsel.FamilyEVM)
	if err != nil {
		return nil, err
	}
	thirdChain, err := chainsel.GetChainDetailsByChainIDAndFamily(chainIDs[2], chainsel.FamilyEVM)
	if err != nil {
		return nil, err
	}

	gas := &GasSettings{
		FeeCapMultiplier: 2,
		TipCapMultiplier: 2,
	}
	rpcSrc, _, _, err := ETHClient(ctx, wsURLs[0], gas)
	if err != nil {
		return nil, err
	}
	rpcDst, _, _, err := ETHClient(ctx, wsURLs[1], gas)
	if err != nil {
		return nil, err
	}
	rpcThird, _, _, err := ETHClient(ctx, wsURLs[2], gas)
	if err != nil {
		return nil, err
	}

	proxySrcAddr, err := GetContractAddrForSelector(addresses, srcChain.ChainSelector, datastore.ContractType(ccvProxyOps.ContractType))
	if err != nil {
		return nil, err
	}
	proxyDstAddr, err := GetContractAddrForSelector(addresses, dstChain.ChainSelector, datastore.ContractType(ccvProxyOps.ContractType))
	if err != nil {
		return nil, err
	}
	proxySrc, err := ccvProxy.NewCCVProxy(proxySrcAddr, rpcSrc)
	if err != nil {
		return nil, err
	}
	proxyDst, err := ccvProxy.NewCCVProxy(proxyDstAddr, rpcDst)
	if err != nil {
		return nil, err
	}

	proxyThirdAddr, err := GetContractAddrForSelector(addresses, thirdChain.ChainSelector, datastore.ContractType(ccvProxyOps.ContractType))
	if err != nil {
		return nil, err
	}
	proxyThird, err := ccvProxy.NewCCVProxy(proxyThirdAddr, rpcThird)
	if err != nil {
		return nil, err
	}

	aggSrcAddr, err := GetContractAddrForSelector(addresses, srcChain.ChainSelector, datastore.ContractType(ccvAggregatorOps.ContractType))
	if err != nil {
		return nil, err
	}
	aggDstAddr, err := GetContractAddrForSelector(addresses, dstChain.ChainSelector, datastore.ContractType(ccvAggregatorOps.ContractType))
	if err != nil {
		return nil, err
	}
	aggSrc, err := ccvAggregator.NewCCVAggregator(aggSrcAddr, rpcSrc)
	if err != nil {
		return nil, err
	}
	aggDst, err := ccvAggregator.NewCCVAggregator(aggDstAddr, rpcDst)
	if err != nil {
		return nil, err
	}

	aggThirdAddr, err := GetContractAddrForSelector(addresses, thirdChain.ChainSelector, datastore.ContractType(ccvAggregatorOps.ContractType))
	if err != nil {
		return nil, err
	}
	aggThird, err := ccvAggregator.NewCCVAggregator(aggThirdAddr, rpcThird)
	if err != nil {
		return nil, err
	}

	// Build the maps
	proxyBySelector := map[uint64]*ccvProxy.CCVProxy{
		srcChain.ChainSelector:   proxySrc,
		dstChain.ChainSelector:   proxyDst,
		thirdChain.ChainSelector: proxyThird,
	}
	aggBySelector := map[uint64]*ccvAggregator.CCVAggregator{
		srcChain.ChainSelector:   aggSrc,
		dstChain.ChainSelector:   aggDst,
		thirdChain.ChainSelector: aggThird,
	}
	chainDetailsBySelector := map[uint64]chainsel.ChainDetails{
		srcChain.ChainSelector:   srcChain,
		dstChain.ChainSelector:   dstChain,
		thirdChain.ChainSelector: thirdChain,
	}

	return &CCIP17EVM{
		Chain1337Details:       srcChain,
		Chain2337Details:       dstChain,
		Chain3337Details:       thirdChain,
		ChainDetailsBySelector: chainDetailsBySelector,
		ProxyBySelector:        proxyBySelector,
		AggBySelector:          aggBySelector,
	}, nil
}

// fetchAllSentEventsBySelector fetch all CCIPMessageSent events from proxy contract
func (m *CCIP17EVM) fetchAllSentEventsBySelector(ctx context.Context, from, to uint64) ([]*ccvProxy.CCVProxyCCIPMessageSent, error) {
	l := zerolog.Ctx(ctx)
	proxy, ok := m.ProxyBySelector[from]
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
	agg, ok := m.AggBySelector[from]
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
	p, ok := m.ProxyBySelector[from]
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
	proxy, ok := m.ProxyBySelector[from]
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

	agg, ok := m.AggBySelector[to]
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

func (m *CCIP17EVM) SendArgsV2Message(ctx context.Context, e *deployment.Environment, addresses []string, src, dest uint64) error {
	l := zerolog.Ctx(ctx)
	chains := e.BlockChains.EVMChains()
	if chains == nil {
		return errors.New("no EVM chains found")
	}

	srcChain := chains[src]

	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)
	e.OperationsBundle = bundle

	routerAddr, err := GetContractAddrForSelector(addresses, srcChain.Selector, datastore.ContractType(router.ContractType))
	if err != nil {
		return fmt.Errorf("failed to get router address: %w", err)
	}

	rcv := MustGetContractAddressForSelector(addresses, dest, mock_receiver.ContractType)

	ccipSendArgs := router.CCIPSendArgs{
		DestChainSelector: dest,
		EVM2AnyMessage: router.EVM2AnyMessage{
			Receiver:     common.LeftPadBytes(rcv.Bytes(), 32),
			Data:         []byte{},
			TokenAmounts: []router.EVMTokenAmount{},
			ExtraArgs:    []byte{},
		},
	}

	// Send CCIP message with value
	sendReport, err := operations.ExecuteOperation(bundle, router.CCIPSend, srcChain, contract.FunctionInput[router.CCIPSendArgs]{
		ChainSelector: src,
		Address:       routerAddr,
		Args:          ccipSendArgs,
	})
	if err != nil {
		return fmt.Errorf("failed to send CCIP message: %w", err)
	}
	l.Info().Bool("Executed", sendReport.Output.Executed).
		Uint64("SrcChainSelector", sendReport.Output.ChainSelector).
		Uint64("DestChainSelector", dest).
		Str("SrcRouter", sendReport.Output.Tx.To).
		Msg("CCIP message sent")
	return nil
}

func (m *CCIP17EVM) SendArgsV3Message(
	ctx context.Context,
	e *deployment.Environment,
	addresses []string, selectors []uint64,
	src, dest uint64, finality uint16,
	execAddr, receiverAddr string,
	execArgs, tokenArgs []byte,
	ccv, optCcv []protocol.CCV,
	threshold uint8,
) error {
	l := zerolog.Ctx(ctx)
	chains := e.BlockChains.EVMChains()
	if chains == nil {
		return errors.New("no EVM chains found")
	}
	if !slices.Contains(selectors, src) {
		return fmt.Errorf("source selector %d not found in environment selectors %v", src, selectors)
	}
	if !slices.Contains(selectors, dest) {
		return fmt.Errorf("destination selector %d not found in environment selectors %v", dest, selectors)
	}

	srcChain := chains[src]

	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)
	e.OperationsBundle = bundle

	routerAddr, err := GetContractAddrForSelector(addresses, srcChain.Selector, datastore.ContractType(router.ContractType))
	if err != nil {
		return fmt.Errorf("failed to get router address: %w", err)
	}

	argsV3, err := NewV3ExtraArgs(finality, execAddr, execArgs, tokenArgs, ccv, optCcv, threshold)
	if err != nil {
		return fmt.Errorf("failed to generate GenericExtraArgsV3: %w", err)
	}
	ccipSendArgs := router.CCIPSendArgs{
		DestChainSelector: dest,
		EVM2AnyMessage: router.EVM2AnyMessage{
			Receiver:     common.LeftPadBytes(common.HexToAddress(receiverAddr).Bytes(), 32),
			Data:         []byte{},
			TokenAmounts: []router.EVMTokenAmount{},
			ExtraArgs:    argsV3,
		},
	}

	// TODO: not supported right now
	//feeReport, err := operations.ExecuteOperation(bundle, router.GetFee, srcChain, contract.FunctionInput[router.CCIPSendArgs]{
	//	ChainSelector: srcChain.Selector,
	//	Address:       routerAddr,
	//	Args:          ccipSendArgs,
	//})
	//if err != nil {
	//	return fmt.Errorf("failed to get fee: %w", err)
	//}
	//ccipSendArgs.Value = feeReport.Output

	// Send CCIP message with value
	sendReport, err := operations.ExecuteOperation(bundle, router.CCIPSend, srcChain, contract.FunctionInput[router.CCIPSendArgs]{
		ChainSelector: src,
		Address:       routerAddr,
		Args:          ccipSendArgs,
	})
	if err != nil {
		return fmt.Errorf("failed to send CCIP message: %w", err)
	}

	l.Info().Bool("Executed", sendReport.Output.Executed).
		Uint64("SrcChainSelector", sendReport.Output.ChainSelector).
		Uint64("DestChainSelector", dest).
		Str("SrcRouter", sendReport.Output.Tx.To).
		Msg("CCIP message sent")

	return nil
}

func (m *CCIP17EVM) ExposeMetrics(ctx context.Context, addresses []string, chainIDs []string, wsURLs []string) ([]string, *prometheus.Registry, error) {
	msgSentTotal.Reset()
	msgExecTotal.Reset()
	srcDstLatency.Reset()

	reg := prometheus.NewRegistry()
	reg.MustRegister(msgSentTotal, msgExecTotal, srcDstLatency)

	lp := NewLokiPusher()
	tp := NewTempoPusher()
	c, err := NewCCIP17EVM(ctx, addresses, chainIDs, wsURLs)
	if err != nil {
		return nil, nil, err
	}
	err = ProcessLaneEvents(ctx, c, lp, tp, &LaneStreamConfig{
		FromSelector:      c.Chain1337Details.ChainSelector,
		ToSelector:        c.Chain2337Details.ChainSelector,
		AggregatorAddress: "localhost:50051",
		AggregatorSince:   0,
	})
	if err != nil {
		return nil, nil, err
	}
	err = ProcessLaneEvents(ctx, c, lp, tp, &LaneStreamConfig{
		FromSelector:      c.Chain2337Details.ChainSelector,
		ToSelector:        c.Chain1337Details.ChainSelector,
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
