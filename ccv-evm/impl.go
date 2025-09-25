package ccv_evm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/changesets"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/executor_onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/fee_quoter_v2"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/sequences"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

type CCIP17EVM struct{}

func (m *CCIP17EVM) SendExampleArgsV2Message(ctx context.Context, e *deployment.Environment, addresses []string, selectors []uint64, src, dest uint64) error {
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

	receiver := "0x3Aa5ebB10DC797CAC828524e59A333d0A371443c"
	ccipSendArgs := router.CCIPSendArgs{
		DestChainSelector: dest,
		EVM2AnyMessage: router.EVM2AnyMessage{
			Receiver:     common.LeftPadBytes(common.HexToAddress(receiver).Bytes(), 32),
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

func (m *CCIP17EVM) SendExampleArgsV3Message(ctx context.Context, e *deployment.Environment, addresses []string, selectors []uint64, src, dest uint64, finality uint16, execAddr string, execArgs, tokenArgs []byte, ccv, optCcv []types.CCV, threshold uint8) error {
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
	receiverAddress := "0x3Aa5ebB10DC797CAC828524e59A333d0A371443c"

	ccipSendArgs := router.CCIPSendArgs{
		DestChainSelector: dest,
		EVM2AnyMessage: router.EVM2AnyMessage{
			Receiver:     common.LeftPadBytes(common.HexToAddress(receiverAddress).Bytes(), 32),
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
	c, err := NewContracts(ctx, addresses, chainIDs, wsURLs)
	if err != nil {
		return nil, nil, err
	}
	err = ProcessLaneEvents(ctx, lp, tp, &LaneStreamConfig{
		From:              c.Proxy1337,
		To:                c.Agg2337,
		FromSelector:      c.Chain1337Details.ChainSelector,
		ToSelector:        c.Chain2337Details.ChainSelector,
		AggregatorAddress: "localhost:50051",
		AggregatorSince:   0,
	})
	if err != nil {
		return nil, nil, err
	}
	err = ProcessLaneEvents(ctx, lp, tp, &LaneStreamConfig{
		From:              c.Proxy2337,
		To:                c.Agg1337,
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

func (m *CCIP17EVM) SendMessage(ctx context.Context, router string, msg []byte) ([]byte, error) {
	l := zerolog.Ctx(ctx)
	l.Info().Msg("Sending CCIP message")
	return []byte{}, nil
}

func (m *CCIP17EVM) VerifyMessage(ctx context.Context, offRamp string, msgID []byte) error {
	l := zerolog.Ctx(ctx)
	l.Info().Msg("Verifying CCIP message")
	return nil
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
				SignatureConfigArgs: commit_offramp.SignatureConfigArgs{
					Threshold: 2,
					Signers: []common.Address{
						common.HexToAddress("0xffb9f9a3ae881f4b30e791d9e63e57a0e1facd66"),
						common.HexToAddress("0x556bed6675c5d8a948d4d42bbf68c6da6c8968e3"),
					},
				},
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
				Type:    datastore.ContractType(commit_onramp.ContractType),
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
