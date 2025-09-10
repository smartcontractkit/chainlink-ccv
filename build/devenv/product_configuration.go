package ccv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/changesets"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/executor_onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/fee_quoter_v2"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/sequences"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_evm_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const (
	ConfigureNodesNetwork ConfigPhase = iota
	ConfigureProductContractsJobs
)

var Plog = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel).With().Fields(map[string]any{"component": "ccv"}).Logger()

type CCV struct {
	EAFake              *EAFake       `toml:"ea_fake"`
	Jobs                *Jobs         `toml:"jobs"`
	LinkContractAddress string        `toml:"link_contract_address"`
	CLNodesFundingETH   float64       `toml:"cl_nodes_funding_eth"`
	CLNodesFundingLink  float64       `toml:"cl_nodes_funding_link"`
	ChainFinalityDepth  int64         `toml:"chain_finality_depth"`
	VerificationTimeout time.Duration `toml:"verification_timeout"`
	Verify              bool          `toml:"verify"`

	// Contracts (CLDF)
	AddressesMu *sync.Mutex `toml:"-"`
	Addresses   []string    `toml:"addresses"`

	// These are the settings for CLDF missing functionality we cover with ETHClient, we should remove them later
	GasSettings *GasSettings `toml:"gas_settings"`
}

type DeployedContracts struct {
	// your deployed contract structs here with `toml:''` tags
}

type GasSettings struct {
	FeeCapMultiplier int64 `toml:"fee_cap_multiplier"`
	TipCapMultiplier int64 `toml:"tip_cap_multiplier"`
}

type Jobs struct {
	ConfigPollIntervalSeconds time.Duration `toml:"config_poll_interval_sec"` //nolint:staticcheck
	MaxTaskDurationSec        time.Duration `toml:"max_task_duration_sec"`    //nolint:staticcheck
}

type EAFake struct {
	LowValue  int64 `toml:"low_value"`
	HighValue int64 `toml:"high_value"`
}

type ConfigPhase int

func NewCLDFOperationsEnvironment(bc []*blockchain.Input) ([]uint64, *deployment.Environment, error) {
	providers := make([]cldf_chain.BlockChain, 0)
	selectors := make([]uint64, 0)
	for _, b := range bc {
		chainID := b.Out.ChainID
		rpcWSURL := b.Out.Nodes[0].ExternalWSUrl
		rpcHTTPURL := b.Out.Nodes[0].ExternalHTTPUrl

		d, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
		if err != nil {
			return nil, nil, err
		}
		selectors = append(selectors, d.ChainSelector)

		p, err := cldf_evm_provider.NewRPCChainProvider(
			d.ChainSelector,
			cldf_evm_provider.RPCChainProviderConfig{
				DeployerTransactorGen: cldf_evm_provider.TransactorFromRaw(
					getNetworkPrivateKey(),
				),
				RPCs: []deployment.RPC{
					{
						Name:               "default",
						WSURL:              rpcWSURL,
						HTTPURL:            rpcHTTPURL,
						PreferredURLScheme: deployment.URLSchemePreferenceHTTP,
					},
				},
				ConfirmFunctor: cldf_evm_provider.ConfirmFuncGeth(1 * time.Minute),
			},
		).Initialize(context.Background())
		if err != nil {
			return nil, nil, err
		}
		providers = append(providers, p)
	}

	blockchains := cldf_chain.NewBlockChainsFromSlice(providers)

	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	if err != nil {
		return nil, nil, err
	}

	e := deployment.Environment{
		GetContext:  func() context.Context { return context.Background() },
		Logger:      lggr,
		BlockChains: blockchains,
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}
	return selectors, &e, nil
}

func deployContractsForSelector(in *Cfg, e *deployment.Environment, selector uint64) (datastore.DataStore, error) {
	L.Info().Uint64("Selector", selector).Msg("Configuring per-chain contracts bundle")
	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)
	e.OperationsBundle = bundle

	usdPerLink, ok := new(big.Int).SetString("15000000000000000000", 10) // $15
	if !ok {
		return nil, errors.New("failed to parse USDPerLINK")
	}
	usdPerWeth, ok := new(big.Int).SetString("2000000000000000000000", 10) // $2000
	if !ok {
		return nil, errors.New("failed to parse USDPerWETH")
	}

	out, err := changesets.DeployChainContracts.Apply(*e, changesets.DeployChainContractsCfg{
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
					Threshold: 1,
					Signers: []common.Address{
						common.HexToAddress("0x02"),
						common.HexToAddress("0x03"),
						common.HexToAddress("0x04"),
						common.HexToAddress("0x05"),
					},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	addresses, err := out.DataStore.Addresses().Fetch()
	in.CCV.AddressesMu.Lock()
	defer in.CCV.AddressesMu.Unlock()
	a, err := json.Marshal(addresses)
	if err != nil {
		return nil, err
	}
	in.CCV.Addresses = append(in.CCV.Addresses, string(a))
	return out.DataStore.Seal(), nil
}

func configureContractsOnSelectorForLanes(e *deployment.Environment, selector uint64, remoteSelectors []uint64) error {
	L.Info().Uint64("Selector", selector).Msg("Configuring per-chain contracts bundle")
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

func configureJobs(in *Cfg, clNodes []*clclient.ChainlinkClient) error {
	bootstrapNode := clNodes[0]
	workerNodes := clNodes[1:]
	// example bootstrap job, use JD here?
	_ = bootstrapNode

	for _, chainlinkNode := range workerNodes {
		_, err := chainlinkNode.PrimaryEthAddress()
		if err != nil {
			return fmt.Errorf("getting primary ETH address from OCR node have failed: %w", err)
		}
		_, err = chainlinkNode.MustReadOCR2Keys()
		if err != nil {
			return fmt.Errorf("getting OCR keys from OCR node have failed: %w", err)
		}
		_ = in.Fake.Out.ExternalHTTPURL
		_ = in.Fake.Out.InternalHTTPURL

		// create CCV jobs here
	}
	return nil
}

func setupFakes(fakeServiceURL string) error {
	//  example fake service configuration (mocking external adapter responses)
	//  r := resty.New().SetBaseURL(fakeServiceURL)
	//  _, err = r.R().Post(fmt.Sprintf(`/set_ea?low=%d&high=%d`, in.CCV.EAFake.LowValue, in.CCV.EAFake.HighValue))
	//  if err != nil {
	//  	return fmt.Errorf("could not set ea fake values: %w", err)
	//  }
	//  Plog.Info().
	//	  Int64("FeedAnswerLow", in.CCV.EAFake.LowValue).
	//	  Int64("FeedAnswerHigh", in.CCV.EAFake.HighValue).
	//	  Msg("Setting fake external adapter (data feed) values")
	return nil
}

// DefaultProductConfiguration is default product configuration that includes:
// - CL nodes config generation
// - On-chain part deployment using CLDF
func DefaultProductConfiguration(in *Cfg, phase ConfigPhase) error {
	Plog.Info().Msg("Generating CL nodes config")
	pkey := getNetworkPrivateKey()
	if pkey == "" {
		return fmt.Errorf("PRIVATE_KEY environment variable not set")
	}
	switch phase {
	case ConfigureNodesNetwork:
		Plog.Info().Msg("Applying default CL nodes configuration")
		srcBlockchain := in.Blockchains[0].Out.Nodes[0]
		dstBlockchain := in.Blockchains[1].Out.Nodes[0]
		srcChainID := in.Blockchains[0].ChainID
		dstChainID := in.Blockchains[1].ChainID
		// configure node set and generate CL nodes configs
		netConfig := fmt.Sprintf(`
       [[EVM]]
       LogPollInterval = '1s'
       BlockBackfillDepth = 100
       LinkContractAddress = '%s'
       ChainID = '%s'
       MinIncomingConfirmations = 1
       MinContractPayment = '0.0000001 link'
       FinalityDepth = %d

       [[EVM.Nodes]]
       Name = 'src'
       WsUrl = '%s'
       HttpUrl = '%s'

       [[EVM]]
       LogPollInterval = '1s'
       BlockBackfillDepth = 100
       LinkContractAddress = '%s'
       ChainID = '%s'
       MinIncomingConfirmations = 1
       MinContractPayment = '0.0000001 link'
       FinalityDepth = %d

       [[EVM.Nodes]]
       Name = 'dst'
       WsUrl = '%s'
       HttpUrl = '%s'
`,
			in.CCV.LinkContractAddress,
			srcChainID,
			in.CCV.ChainFinalityDepth,
			srcBlockchain.InternalWSUrl,
			srcBlockchain.InternalHTTPUrl,

			in.CCV.LinkContractAddress,
			dstChainID,
			in.CCV.ChainFinalityDepth,
			dstBlockchain.InternalWSUrl,
			dstBlockchain.InternalHTTPUrl,
		) + `
	   [Log]
	   JSONConsole = true
	   Level = 'debug'
	   [Pyroscope]
	   ServerAddress = 'http://host.docker.internal:4040'
	   Environment = 'local'
	   [WebServer]
       SessionTimeout = '999h0m0s'
       HTTPWriteTimeout = '3m'
	   SecureCookies = false
	   HTTPPort = 6688
	   [WebServer.TLS]
	   HTTPSPort = 0
       [WebServer.RateLimit]
       Authenticated = 5000
       Unauthenticated = 5000
	   [JobPipeline]
	   [JobPipeline.HTTPRequest]
	   DefaultTimeout = '1m'
       [Log.File]
       MaxSize = '0b'
	` + `
       [Feature]
       FeedsManager = true
       LogPoller = true
       UICSAKeys = true
       [OCR2]
       Enabled = true
       SimulateTransactions = false
       DefaultTransactionQueueDepth = 1
       [P2P.V2]
       Enabled = true
       ListenAddresses = ['0.0.0.0:6690']
`
		for _, nodeSpec := range in.NodeSets[0].NodeSpecs {
			nodeSpec.Node.TestConfigOverrides = netConfig
		}
		Plog.Info().Msg("Nodes network configuration is generated")
		return nil
	case ConfigureProductContractsJobs:

		//* Funding all CL nodes with ETH *//

		Plog.Info().Msg("Connecting to CL nodes")
		nodeClients, err := clclient.New(in.NodeSets[0].Out.CLNodes)
		if err != nil {
			return fmt.Errorf("connecting to CL nodes: %w", err)
		}
		transmittersSrc, transmittersDst := make([]common.Address, 0), make([]common.Address, 0)
		ethKeyAddressesSrc, ethKeyAddressesDst := make([]string, 0), make([]string, 0)
		for i, nc := range nodeClients {
			addrSrc, err := nc.ReadPrimaryETHKey(in.Blockchains[0].ChainID)
			if err != nil {
				return fmt.Errorf("getting primary ETH key from OCR node %d (src chain): %w", i, err)
			}
			ethKeyAddressesSrc = append(ethKeyAddressesSrc, addrSrc.Attributes.Address)
			transmittersSrc = append(transmittersSrc, common.HexToAddress(addrSrc.Attributes.Address))
			addrDst, err := nc.ReadPrimaryETHKey(in.Blockchains[1].ChainID)
			if err != nil {
				return fmt.Errorf("getting primary ETH key from OCR node %d (dst chain): %w", i, err)
			}
			ethKeyAddressesDst = append(ethKeyAddressesDst, addrDst.Attributes.Address)
			transmittersDst = append(transmittersDst, common.HexToAddress(addrDst.Attributes.Address))
			Plog.Info().
				Int("Idx", i).
				Str("ETHKeySrc", addrSrc.Attributes.Address).
				Str("ETHKeyDst", addrDst.Attributes.Address).
				Msg("Node info")
		}
		clientSrc, _, _, err := ETHClient(in.Blockchains[0].Out.Nodes[0].ExternalWSUrl, in.CCV.GasSettings)
		if err != nil {
			return fmt.Errorf("could not create basic eth client: %w", err)
		}
		clientDst, _, _, err := ETHClient(in.Blockchains[1].Out.Nodes[0].ExternalWSUrl, in.CCV.GasSettings)
		if err != nil {
			return fmt.Errorf("could not create basic eth client: %w", err)
		}
		for _, addr := range ethKeyAddressesSrc {
			if err := FundNodeEIP1559(clientSrc, pkey, addr, in.CCV.CLNodesFundingETH); err != nil {
				return fmt.Errorf("failed to fund CL nodes on src chain: %w", err)
			}
		}
		for _, addr := range ethKeyAddressesDst {
			if err := FundNodeEIP1559(clientDst, pkey, addr, in.CCV.CLNodesFundingETH); err != nil {
				return fmt.Errorf("failed to fund CL nodes on dst chain: %w", err)
			}
		}

		// * Configuring src and dst contracts * //
		selectors, e, err := NewCLDFOperationsEnvironment(in.Blockchains)
		if err != nil {
			return fmt.Errorf("creating CLDF operations environment: %w", err)
		}
		L.Info().Any("Selectors", selectors).Msg("Deploying for chain selectors")
		eg := &errgroup.Group{}
		in.CCV.AddressesMu = &sync.Mutex{}
		runningDS := datastore.NewMemoryDataStore()
		for _, sel := range selectors {
			eg.Go(func() error {
				ds, err := deployContractsForSelector(in, e, sel)
				if err != nil {
					return fmt.Errorf("could not configure contracts for chain selector %d: %w", sel, err)
				}
				return runningDS.Merge(ds)
			})
		}
		if err := eg.Wait(); err != nil {
			return err
		}
		e.DataStore = runningDS.Seal()
		for _, sel := range selectors {
			eg.Go(func() error {
				remoteSelectors := make([]uint64, 0, len(selectors)-1)
				for _, s := range selectors {
					if s != sel {
						remoteSelectors = append(remoteSelectors, s)
					}
				}
				err = configureContractsOnSelectorForLanes(e, sel, remoteSelectors)
				if err != nil {
					return fmt.Errorf("could not configure contracts on chain selector %d for lanes: %w", sel, err)
				}
				return nil
			})
		}
		if err := eg.Wait(); err != nil {
			return err
		}
		if err := configureJobs(in, nodeClients); err != nil {
			return fmt.Errorf("could not configure jobs: %w", err)
		}
		if err := setupFakes(in.Fake.Out.ExternalHTTPURL); err != nil {
			return fmt.Errorf("could not setup fake server: %w", err)
		}

		Plog.Info().Str("BootstrapNode", in.NodeSets[0].Out.CLNodes[0].Node.ExternalURL).Send()
		for _, n := range in.NodeSets[0].Out.CLNodes[1:] {
			Plog.Info().Str("Node", n.Node.ExternalURL).Send()
		}
		// Write CCVProxy addresses from CLDF deployment to verifier config
		if err := writeCCVProxyAddressesToConfig(in); err != nil {
			Plog.Warn().Err(err).Msg("Failed to write CCVProxy addresses to verifier.toml")
		}

		if err := verifyEnvironment(in); err != nil {
			return err
		}
		return nil
	}
	return nil
}

// writeCCVProxyAddressesToConfig writes CCVProxy addresses from CLDF deployment to verifier.toml
func writeCCVProxyAddressesToConfig(in *Cfg) error {
	// Get CLDF addresses
	addresses, err := GetCLDFAddressesPerSelector(in)
	if err != nil {
		return fmt.Errorf("failed to get CLDF addresses: %w", err)
	}

	// Find CCVProxy addresses for chains 1337 and 2337
	ccvProxyAddresses := make(map[string]string)

	for _, addrRefs := range addresses {
		for _, ref := range addrRefs {
			if ref.Type == "CCVProxy" {
				chainKey := fmt.Sprintf("%d", ref.ChainSelector)
				ccvProxyAddresses[chainKey] = ref.Address
				Plog.Info().
					Uint64("chainSelector", ref.ChainSelector).
					Str("address", ref.Address).
					Msg("Found CCVProxy address from CLDF")
			}
		}
	}

	if len(ccvProxyAddresses) == 0 {
		return fmt.Errorf("no CCVProxy addresses found in CLDF deployment")
	}

	in.Verifier.VerifierConfig.BlockchainInfos["1337"].CCVProxyAddress = ccvProxyAddresses["3379446385462418246"]
	in.Verifier.VerifierConfig.BlockchainInfos["2337"].CCVProxyAddress = ccvProxyAddresses["12922642891491394802"]
	in.Verifier.VerifierConfig.CCVProxy1337 = ccvProxyAddresses["3379446385462418246"]
	in.Verifier.VerifierConfig.CCVProxy2337 = ccvProxyAddresses["12922642891491394802"]

	in.Verifier2.VerifierConfig.BlockchainInfos["1337"].CCVProxyAddress = ccvProxyAddresses["3379446385462418246"]
	in.Verifier2.VerifierConfig.BlockchainInfos["2337"].CCVProxyAddress = ccvProxyAddresses["12922642891491394802"]
	in.Verifier2.VerifierConfig.CCVProxy1337 = ccvProxyAddresses["3379446385462418246"]
	in.Verifier2.VerifierConfig.CCVProxy2337 = ccvProxyAddresses["12922642891491394802"]

	// 	// Update verifier config with CCVProxy addresses
	// 	configPath := "../../verifier/verifier.toml"

	// 	// Create config content with CCVProxy addresses
	// 	content := `aggregator_address = "http://localhost:8080"
	// private_key = "test-key-for-development"

	// ccv_proxy_1337 = "%s"
	// ccv_proxy_2337 = "%s"

	// [blockchain_infos]
	// # Blockchain info populated by devenv
	// `

	// 	// Get CCVProxy addresses
	// 	ccvProxy1337 := ccvProxyAddresses["1337"]
	// 	ccvProxy2337 := ccvProxyAddresses["2337"]

	// 	// Write config with CCVProxy addresses
	// 	configContent := fmt.Sprintf(content, ccvProxy1337, ccvProxy2337)

	// 	err = os.WriteFile(configPath, []byte(configContent), 0644)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to write verifier config: %w", err)
	// 	}

	// 	Plog.Info().
	// 		Str("path", configPath).
	// 		Str("ccvProxy1337", ccvProxy1337).
	// 		Str("ccvProxy2337", ccvProxy2337).
	// 		Msg("Updated verifier.toml with CCVProxy addresses from CLDF")

	return nil
}
