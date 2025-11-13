package ccv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/internal/util"
	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/jd"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

const (
	CommonCLNodesConfig = `
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
)

type Cfg struct {
	Mode               services.Mode               `toml:"mode"`
	CLDF               CLDF                        `toml:"cldf"                  validate:"required"`
	JD                 *jd.Input                   `toml:"jd"                    validate:"required"`
	Fake               *services.FakeInput         `toml:"fake"                  validate:"required"`
	Verifier           []*services.VerifierInput   `toml:"verifier"              validate:"required"`
	Executor           *services.ExecutorInput     `toml:"executor"              validate:"required"`
	Indexer            *services.IndexerInput      `toml:"indexer"               validate:"required"`
	Aggregator         []*services.AggregatorInput `toml:"aggregator"            validate:"required"`
	Blockchains        []*blockchain.Input         `toml:"blockchains"           validate:"required"`
	NodeSets           []*ns.Input                 `toml:"nodesets"              validate:"required"`
	CLNodesFundingETH  float64                     `toml:"cl_nodes_funding_eth"`
	CLNodesFundingLink float64                     `toml:"cl_nodes_funding_link"`
}

func checkKeys(in *Cfg) error {
	if getNetworkPrivateKey() != DefaultAnvilKey && in.Blockchains[0].ChainID == "1337" && in.Blockchains[1].ChainID == "2337" {
		return errors.New("you are trying to run simulated chains with a key that do not belong to Anvil, please run 'unset PRIVATE_KEY'")
	}
	if getNetworkPrivateKey() == DefaultAnvilKey && in.Blockchains[0].ChainID != "1337" && in.Blockchains[1].ChainID != "2337" {
		return errors.New("you are trying to run on real networks but is not using the Anvil private key, export your private key 'export PRIVATE_KEY=...'")
	}
	return nil
}

func NewProductConfigurationFromNetwork(typ string) (cciptestinterfaces.CCIP17ProductConfiguration, error) {
	switch typ {
	case "anvil":
		return &evm.CCIP17EVM{}, nil
	case "canton":
		// see devenv-evm implementation and add Canton
		return nil, nil
	default:
		return nil, errors.New("unknown devenv network type " + typ)
	}
}

// NewEnvironment creates a new CCIP CCV environment either locally in Docker or remotely in K8s.
func NewEnvironment() (in *Cfg, err error) {
	ctx := context.Background()
	timeTrack := NewTimeTracker(Plog)

	// track environment startup result and time using getDX app
	defer func() {
		dxTracker := initDxTracker()
		sendStartupMetrics(dxTracker, err, timeTrack.SinceStart().Seconds())
	}()

	ctx = L.WithContext(ctx)
	if err = framework.DefaultNetwork(nil); err != nil {
		return nil, err
	}

	configs := strings.Split(os.Getenv(EnvVarTestConfigs), ",")
	if len(configs) > 1 {
		L.Warn().Msg("Multiple configuration files detected, this feature may be unsupported in the future.")
	}
	in, err = Load[Cfg](configs)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	///////////////////////////////
	// Start: Initialize Configs //
	///////////////////////////////

	// Override the default config to "cl"...
	if in.Mode == "" {
		in.Mode = services.Standalone
	}

	// Verifier configs...
	for i, ver := range in.Verifier {
		services.ApplyVerifierDefaults(ver)
		if ver.Mode != services.Standalone {
			// only generate keys with this method for standalone verifiers.
			continue
		}
		// deterministic key generation algorithm.
		ver.ConfigFilePath = fmt.Sprintf("/app/cmd/verifier/testconfig/%s/verifier-%d.toml", ver.CommitteeName, ver.NodeIndex+1)
		ver.SigningKey = util.XXXNewVerifierPrivateKey(ver.CommitteeName, ver.NodeIndex)

		privateKey, err := commit.ReadPrivateKeyFromString(ver.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}
		_, publicKey, err := commit.NewECDSAMessageSigner(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create message signer: %w", err)
		}
		ver.SigningKeyPublic = publicKey.String()

		in.Verifier[i] = ver // technically not needed because it's a pointer.
	}

	// Executor config...
	if in.Executor != nil {
		services.ApplyExecutorDefaults(in.Executor)
	}

	/////////////////////////////
	// End: Initialize Configs //
	/////////////////////////////

	if err = checkKeys(in); err != nil {
		return nil, err
	}

	// Start fake data provider. This isn't really used, but may be useful in the future.
	_, err = services.NewFake(in.Fake)
	if err != nil {
		return nil, fmt.Errorf("failed to create fake data provider: %w", err)
	}

	// Start blockchains, the services crash if the RPC is not available.
	impls := make([]cciptestinterfaces.CCIP17ProductConfiguration, 0)
	for _, bc := range in.Blockchains {
		var impl cciptestinterfaces.CCIP17ProductConfiguration
		impl, err = NewProductConfigurationFromNetwork(bc.Type)
		if err != nil {
			return nil, err
		}
		impls = append(impls, impl)
	}
	for i, impl := range impls {
		_, err = impl.DeployLocalNetwork(ctx, in.Blockchains[i])
		if err != nil {
			return nil, fmt.Errorf("failed to deploy local networks: %w", err)
		}
	}

	// Start aggregators.
	for _, aggregatorInput := range in.Aggregator {
		_, err = services.NewAggregator(aggregatorInput)
		if err != nil {
			return nil, fmt.Errorf("failed to create aggregator service for committee %s: %w", aggregatorInput.CommitteeName, err)
		}
	}

	// Start indexer.
	// start up the indexer after the aggregators are up to avoid spamming of errors
	// in the logs when it starts before the aggregators are up.
	_, err = services.NewIndexer(in.Indexer)
	if err != nil {
		return nil, fmt.Errorf("failed to create indexer service: %w", err)
	}

	// JD is not currently used.
	/*
		prodJDImage := os.Getenv("JD_IMAGE")

		if in.JD != nil {
			if prodJDImage != "" {
				in.JD.Image = prodJDImage
			}
			if len(in.JD.Image) == 0 {
				Plog.Warn().Msg("No JD image provided, skipping JD service startup")
			} else {
				_, err = jd.NewJD(in.JD)
				if err != nil {
					return nil, fmt.Errorf("failed to create JD service: %w", err)
				}
			}
		} else {
			Plog.Warn().Msg("No JD configuration provided, skipping JD service startup")
		}
	*/

	timeTrack.Record("[infra] deploying blockchains")

	/////////////////////////////
	// Start: Deploy contracts //
	/////////////////////////////

	// TODO: When job specs are supported, contract deploy needs to happen after CL nodes are up (and keys are
	// generated) and before the services have been started.

	addrs := make(map[string][][]byte)

	for _, ver := range in.Verifier {
		// At this point, SigningKeyPublic must be assigned -- either by keygen either manually or by the CL node.
		addrs[ver.CommitteeName] = append(addrs[ver.CommitteeName], hexutil.MustDecode(ver.SigningKeyPublic))
	}

	var committees []cciptestinterfaces.OnChainCommittees
	for committeeName, signers := range addrs {
		committees = append(committees, cciptestinterfaces.OnChainCommittees{
			CommitteeQualifier: committeeName,
			Signers:            signers,
			Threshold:          uint8(len(signers)),
		})
	}

	var selectors []uint64
	var e *deployment.Environment
	// the CLDF datastore is not initialized at this point because contracts are not deployed yet.
	// it will get populated in the loop below.
	in.CLDF.Init()
	selectors, e, err = NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
	if err != nil {
		return nil, fmt.Errorf("creating CLDF operations environment: %w", err)
	}
	L.Info().Any("Selectors", selectors).Msg("Deploying for chain selectors")

	ds := datastore.NewMemoryDataStore()
	for i, impl := range impls {
		var networkInfo chainsel.ChainDetails
		networkInfo, err = chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[i].ChainID, chainsel.FamilyEVM)
		if err != nil {
			return nil, err
		}
		L.Info().Uint64("Selector", networkInfo.ChainSelector).Msg("Deployed chain selector")
		var dsi datastore.DataStore
		dsi, err = impl.DeployContractsForSelector(ctx, e, networkInfo.ChainSelector, committees)
		if err != nil {
			return nil, err
		}
		var addresses []datastore.AddressRef
		addresses, err = dsi.Addresses().Fetch()
		if err != nil {
			return nil, err
		}
		var a []byte
		a, err = json.Marshal(addresses)
		if err != nil {
			return nil, err
		}
		in.CLDF.AddAddresses(string(a))
		if err = ds.Merge(dsi); err != nil {
			return nil, err
		}
	}
	e.DataStore = ds.Seal()

	for i, impl := range impls {
		var networkInfo chainsel.ChainDetails
		networkInfo, err = chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[i].ChainID, chainsel.FamilyEVM)
		if err != nil {
			return nil, err
		}
		selsToConnect := make([]uint64, 0)
		for _, sel := range selectors {
			if sel != networkInfo.ChainSelector {
				selsToConnect = append(selsToConnect, sel)
			}
		}
		err = impl.ConnectContractsWithSelectors(ctx, e, networkInfo.ChainSelector, selsToConnect, committees)
		if err != nil {
			return nil, err
		}
	}
	///////////////////////////
	// END: Deploy contracts //
	///////////////////////////

	////////////////////////////
	// Start: Launch CL Nodes //
	////////////////////////////

	timeTrack.Record("[infra] deploying CL nodes")
	err = launchCLNodes(ctx, in, impls)
	if err != nil {
		return nil, fmt.Errorf("failed to launch CL nodes: %w", err)
	}
	timeTrack.Record("[infra] deployed CL nodes")

	//////////////////////////
	// End: Launch CL Nodes //
	//////////////////////////

	///////////////////////////////////////
	// Start: Launch standalone services //
	///////////////////////////////////////

	_, err = launchStandaloneExecutor(in)
	if err != nil {
		return nil, fmt.Errorf("failed to create standalone executor: %w", err)
	}

	_, err = launchStandaloneVerifiers(in)
	if err != nil {
		return nil, fmt.Errorf("failed to create standalone verifiers: %w", err)
	}

	/////////////////////////////////////
	// End: Launch standalone services //
	/////////////////////////////////////

	timeTrack.Print()
	if err = PrintCLDFAddresses(in); err != nil {
		return nil, err
	}

	return in, Store(in)
}

// launchCLNodes encapsulates the logic required to launch the core node. It may be better to wrap this in a service.
func launchCLNodes(ctx context.Context, in *Cfg, impls []cciptestinterfaces.CCIP17ProductConfiguration) error {
	// Exit early, there are no nodes configured.
	if len(in.NodeSets) == 0 {
		return nil
	}

	hasAService := false
	for _, ver := range in.Verifier {
		hasAService = hasAService || (ver.Mode == services.CL)
	}

	if in.Executor != nil {
		hasAService = hasAService || (in.Executor.Mode == services.CL)
	}

	// Exit early, there are no services configured to deploy on a CL node.
	if !hasAService {
		return nil
	}

	var err error
	clChainConfigs := make([]string, 0)
	clChainConfigs = append(clChainConfigs, CommonCLNodesConfig)
	for i, impl := range impls {
		var clChainConfig string
		clChainConfig, err = impl.ConfigureNodes(ctx, in.Blockchains[i])
		if err != nil {
			return fmt.Errorf("failed to deploy local networks: %w", err)
		}
		clChainConfigs = append(clChainConfigs, clChainConfig)
	}
	allConfigs := strings.Join(clChainConfigs, "\n")
	for _, nodeSpec := range in.NodeSets[0].NodeSpecs {
		nodeSpec.Node.TestConfigOverrides = allConfigs
	}
	Plog.Info().Msg("Nodes network configuration is generated")

	_, err = ns.NewSharedDBNodeSet(in.NodeSets[0], nil)
	if err != nil {
		return fmt.Errorf("failed to create new shared db node set: %w", err)
	}

	// Fund nodes...
	for i, impl := range impls {
		if err = impl.FundNodes(ctx, in.NodeSets, in.Blockchains[i], big.NewInt(1), big.NewInt(5)); err != nil {
			return fmt.Errorf("failed to fund nodes: %w", err)
		}
	}

	// Configured keys on CL nodes
	clClients, err := clclient.New(in.NodeSets[0].Out.CLNodes)
	if err != nil {
		return fmt.Errorf("failed to connect CL node clients")
	}

	// transforming Executor and Verifier configs to Jobs
	for _, cc := range clClients {
		// TODO: generate keys instead of hard coding them
		// TODO: generation could be done by devenv, and imported into CL nodes here, or they could be
		// generated on the CL node and exported for use in the config files for verifier/executor.

		// import hard coded keys into the CL node keystore
		for _, ver := range in.Verifier {
			if len(ver.SigningKey) != 0 { //nolint:nestif // it's a bit complicated
				encryptedJSON, signerAddress, err := encryptedJSONKey(ver.SigningKey, "", keystore.StandardScryptN, keystore.StandardScryptP)
				if err != nil {
					return fmt.Errorf("failed to encrypt verifier signing key (%s): %w", ver.ContainerName, err)
				}

				Plog.Info().
					Str("Verifier", ver.ContainerName).
					Str("Key", ver.SigningKey).
					Str("encryptedJSON", string(encryptedJSON)).
					Str("signerAddress", signerAddress.Hex()).
					Msg("Importing encrypted verifier signing key into CL node")
				// import the key first and then enable it on the rest of the chains.
				for _, chain := range in.Blockchains {
					addressesBefore, err := cc.EthAddressesForChain(chain.ChainID)
					if err != nil {
						return fmt.Errorf("failed to get addresses for chain %s: %w", chain.ChainID, err)
					}

					Plog.Info().
						Str("Key", ver.SigningKey).
						Str("chainID", chain.ChainID).
						Str("signerAddress", signerAddress.Hex()).
						Any("addressesBefore", addressesBefore).
						Msg("Importing verifier signing key into chain")
					resp, err := cc.ImportEVMKey(encryptedJSON, chain.ChainID)
					if err != nil {
						return fmt.Errorf("failed to import verifier signing key (%s) into chain %s: %w", ver.ContainerName, chain.ChainID, err)
					}

					// 201 is returned for creation of a new key, which is expected here.
					if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
						return fmt.Errorf("failed to import verifier signing key (%s) into chain %s: status code %d", ver.ContainerName, chain.ChainID, resp.StatusCode)
					}

					// check if the key was imported
					addressesAfter, err := cc.EthAddressesForChain(chain.ChainID)
					if err != nil {
						return fmt.Errorf("failed to get addresses for chain %s: %w", chain.ChainID, err)
					}
					if !slices.Contains(addressesAfter, signerAddress.Hex()) {
						return fmt.Errorf("verifier signing key (%s) was not imported into chain %s, all addresses: %v", ver.ContainerName, chain.ChainID, addressesAfter)
					}
					Plog.Info().
						Str("Key", ver.SigningKey).
						Str("chainID", chain.ChainID).
						Str("signerAddress", signerAddress.Hex()).
						Any("addressesAfter", addressesAfter).
						Msg("Verifier signing key imported into CL node for chain")
				}

				for _, chain := range in.Blockchains {
					Plog.Info().
						Str("Key", ver.SigningKey).
						Str("chainID", chain.ChainID).
						Str("signerAddress", signerAddress.Hex()).
						Msg("Enabling verifier signing key on chain")
					req := cc.APIClient.R()
					req.QueryParam = url.Values{
						"evmChainID": {chain.ChainID},
						"address":    {signerAddress.Hex()},
						"enabled":    {"true"},
					}
					resp, err := req.Post("/v2/keys/evm/chain")
					if err != nil {
						return fmt.Errorf("failed to enable verifier signing key (%s) on chain %s: %w", ver.ContainerName, chain.ChainID, err)
					}
					if resp.StatusCode() != http.StatusOK {
						return fmt.Errorf("failed to enable verifier signing key (%s) on chain %s: status code %d", ver.ContainerName, chain.ChainID, resp.StatusCode())
					}
					Plog.Info().
						Str("Key", ver.SigningKey).
						Str("chainID", chain.ChainID).
						Str("signerAddress", signerAddress.Hex()).
						Msg("Verifier signing key enabled on chain")
				}
			}
		}
	}
	return nil
}

func launchStandaloneExecutor(in *Cfg) ([]*services.ExecutorOutput, error) {
	var outs []*services.ExecutorOutput
	// Start standalone executor if in standalone mode.
	if in.Executor != nil && in.Executor.Mode == services.Standalone {
		out, err := services.NewExecutor(in.Executor)
		if err != nil {
			return nil, fmt.Errorf("failed to create executor service: %w", err)
		}
		outs = append(outs, out)
	}
	return outs, nil
}

func launchStandaloneVerifiers(in *Cfg) ([]*services.VerifierOutput, error) {
	var outs []*services.VerifierOutput
	// Start standalone verifiers if in standalone mode.
	for _, ver := range in.Verifier {
		if ver.Mode == services.Standalone {
			out, err := services.NewVerifier(ver)
			if err != nil {
				return nil, fmt.Errorf("failed to create verifier service: %w", err)
			}
			outs = append(outs, out)
		}
	}
	return outs, nil
}

func encryptedJSONKey(privKeyHex, password string, scryptN, scryptP int) ([]byte, common.Address, error) {
	// get the address from the given private key
	privKeyBytes, err := commit.ReadPrivateKeyFromString(privKeyHex)
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("failed to read private key: %w", err)
	}

	_, signerAddress, err := commit.NewECDSAMessageSigner(privKeyBytes)
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("failed to create ECDSA message signer: %w", err)
	}

	if len(signerAddress) != 20 {
		return nil, common.Address{}, fmt.Errorf("expected signer address to be 20 bytes, got: %d", len(signerAddress))
	}

	// Code below adapted from ToEncryptedJSON in core/services/keystore/keys/ethkey/export.go.
	id, err := uuid.FromBytes(signerAddress[:16])
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("failed to create UUID from address: %w", err)
	}

	privateKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("failed to convert private key to ECDSA: %w", err)
	}

	signerAddressGeth := common.BytesToAddress(signerAddress[:])

	dKey := &keystore.Key{
		Id:         id,
		Address:    signerAddressGeth,
		PrivateKey: privateKey,
	}

	encryptedJSON, err := keystore.EncryptKey(dKey, password, scryptN, scryptP)
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("failed to encrypt key: %w", err)
	}

	return encryptedJSON, signerAddressGeth, nil
}
