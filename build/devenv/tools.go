package ccv

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	ccvTypes "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

/*
This code should be generalized and moved to devenv library after we finish CCIPv1.7 environment!
*/

type TimeTracker struct {
	logger    zerolog.Logger
	start     time.Time
	last      time.Time
	intervals []interval
}

type interval struct {
	tag   string
	delta time.Duration
}

// NewTimeTracker is a simple utility function that tracks execution time.
func NewTimeTracker(l zerolog.Logger) *TimeTracker { //nolint:gocritic
	now := time.Now()
	return &TimeTracker{
		start:     now,
		last:      now,
		logger:    l,
		intervals: make([]interval, 0),
	}
}

func (t *TimeTracker) Record(tag string) {
	now := time.Now()
	delta := now.Sub(t.last)
	t.intervals = append(t.intervals, interval{
		tag:   tag,
		delta: delta,
	})
	t.last = now
}

func (t *TimeTracker) Print() {
	total := time.Since(t.start)
	t.logger.Debug().Msg("Time tracking results:")
	for _, i := range t.intervals {
		t.logger.Debug().
			Str("Tag", i.tag).
			Str("Duration", i.delta.String()).
			Send()
	}

	t.logger.Debug().
		Str("Duration", total.String()).
		Msg("Total environment boot up time")
}

func GetCLDFAddressesPerSelector(in *Cfg) ([][]datastore.AddressRef, error) {
	addrs := make([][]datastore.AddressRef, 0)
	for _, addr := range in.CCV.Addresses {
		var refs []datastore.AddressRef
		if err := json.Unmarshal([]byte(addr), &refs); err != nil {
			return nil, fmt.Errorf("failed to unmarshal addresses: %w", err)
		}
		addrs = append(addrs, refs)
	}
	return addrs, nil
}

func PrintCLDFAddresses(in *Cfg) error {
	for _, addr := range in.CCV.Addresses {
		var refs []datastore.AddressRef
		if err := json.Unmarshal([]byte(addr), &refs); err != nil {
			return fmt.Errorf("failed to unmarshal addresses: %w", err)
		}
		fmt.Printf("%-30s %-30s %-40s %-30s\n", "Selector", "Type", "Address", "Version")
		fmt.Println("--------------------------------------------------------------------------------------------------------------")

		for _, ref := range refs {
			fmt.Printf("%-30d %-30s %-40s %-30s\n", ref.ChainSelector, ref.Type, ref.Address, ref.Version)
		}
	}
	return nil
}

/*
This is just a basic ETH client, CLDF should provide something like this
*/

const (
	DefaultNativeTransferGasPrice = 21000
)

// ETHClient creates a basic Ethereum client using PRIVATE_KEY env var and tip/cap gas settings.
// used for common operations like funding where creating CLDF environment makes no sense.
func ETHClient(wsURL string, gasSettings *GasSettings) (*ethclient.Client, *bind.TransactOpts, string, error) {
	client, err := ethclient.Dial(wsURL)
	if err != nil {
		return nil, nil, "", fmt.Errorf("could not connect to eth client: %w", err)
	}
	privateKey, err := crypto.HexToECDSA(getNetworkPrivateKey())
	if err != nil {
		return nil, nil, "", fmt.Errorf("could not parse private key: %w", err)
	}
	publicKey := privateKey.PublicKey
	address := crypto.PubkeyToAddress(publicKey).String()
	chainID, err := client.ChainID(context.Background())
	if err != nil {
		return nil, nil, "", fmt.Errorf("could not get chain ID: %w", err)
	}
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("could not create transactor: %w", err)
	}
	fc, tc, err := MultiplyEIP1559GasPrices(client, gasSettings.FeeCapMultiplier, gasSettings.TipCapMultiplier)
	if err != nil {
		return nil, nil, "", fmt.Errorf("could not get bumped gas price: %w", err)
	}
	auth.GasFeeCap = fc
	auth.GasTipCap = tc
	Plog.Info().
		Str("GasFeeCap", fc.String()).
		Str("GasTipCap", tc.String()).
		Msg("Default gas prices set")
	return client, auth, address, nil
}

// MultiplyEIP1559GasPrices returns bumped EIP1159 gas prices increased by multiplier.
func MultiplyEIP1559GasPrices(client *ethclient.Client, fcMult, tcMult int64) (*big.Int, *big.Int, error) {
	feeCap, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, nil, err
	}
	tipCap, err := client.SuggestGasTipCap(context.Background())
	if err != nil {
		return nil, nil, err
	}

	return new(big.Int).Mul(feeCap, big.NewInt(fcMult)), new(big.Int).Mul(tipCap, big.NewInt(tcMult)), nil
}

func blockchainsByChainID(in *Cfg) (map[string]*ethclient.Client, error) {
	bcByChainID := make(map[string]*ethclient.Client)
	for _, bc := range in.Blockchains {
		c, err := ethclient.Dial(bc.Out.Nodes[0].ExternalHTTPUrl)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Ethereum: %w", err)
		}
		bcByChainID[bc.ChainID] = c
	}
	return bcByChainID, nil
}

// NewDefaultCLDFBundle creates a new default CLDF bundle
func NewDefaultCLDFBundle(e *deployment.Environment) operations.Bundle {
	return operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)
}

// GetContractAddrForSelector get contract address by type and chain selector
func GetContractAddrForSelector(in *Cfg, selector uint64, contractType datastore.ContractType) (common.Address, error) {
	return GetContractAddressForSelector(in, selector, router.ContractType)
}

// GetContractAddressForSelector get address for chain selector, mostly used in testing or tools
func GetContractAddressForSelector(in *Cfg, selector uint64, contractType deployment.ContractType) (common.Address, error) {
	var contractAddr common.Address
	for _, addr := range in.CCV.Addresses {
		var refs []datastore.AddressRef
		err := json.Unmarshal([]byte(addr), &refs)
		if err != nil {
			return common.Address{}, err
		}
		for _, ref := range refs {
			if ref.ChainSelector == selector && ref.Type == datastore.ContractType(contractType) {
				contractAddr = common.HexToAddress(ref.Address)
			}
		}
	}
	return contractAddr, nil
}

func MustGetContractAddressForSelector(in *Cfg, selector uint64, contractType deployment.ContractType) common.Address {
	addr, err := GetContractAddressForSelector(in, selector, contractType)
	if err != nil {
		Plog.Fatal().Err(err).Msg("Failed to get contract address")
	}
	return addr
}

// FundNodeEIP1559 funds CL node using RPC URL, recipient address and amount of funds to send (ETH).
// Uses EIP-1559 transaction type.
func FundNodeEIP1559(c *ethclient.Client, pkey, recipientAddress string, amountOfFundsInETH float64) error {
	amount := new(big.Float).Mul(big.NewFloat(amountOfFundsInETH), big.NewFloat(1e18))
	amountWei, _ := amount.Int(nil)

	chainID, err := c.NetworkID(context.Background())
	if err != nil {
		return err
	}
	privateKeyStr := strings.TrimPrefix(pkey, "0x")
	privateKey, err := crypto.HexToECDSA(privateKeyStr)
	if err != nil {
		return err
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("error casting public key to ECDSA")
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	Plog.Info().
		Str("ChainID", chainID.String()).
		Str("From", fromAddress.String()).
		Str("Addr", recipientAddress).
		Str("Wei", amountWei.String()).
		Msg("Funding Node")

	nonce, err := c.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return err
	}
	feeCap, err := c.SuggestGasPrice(context.Background())
	if err != nil {
		return err
	}
	tipCap, err := c.SuggestGasTipCap(context.Background())
	if err != nil {
		return err
	}
	recipient := common.HexToAddress(recipientAddress)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		To:        &recipient,
		Value:     amountWei,
		Gas:       DefaultNativeTransferGasPrice,
		GasFeeCap: feeCap,
		GasTipCap: tipCap,
	})
	signedTx, err := types.SignTx(tx, types.NewLondonSigner(chainID), privateKey)
	if err != nil {
		return err
	}
	err = c.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return err
	}
	if _, err := bind.WaitMined(context.Background(), c, signedTx); err != nil {
		return err
	}
	Plog.Info().Str("Wei", amountWei.String()).Msg("Funded with ETH")
	return nil
}

/*
Ideally, these functions should be exposed by Atlas as a transformation function that can work independently of any backend (PostgreSQL, Kafka or Prometheus)
But for now we use these functions to expose on-chain events (logs) as a custom aggregated metrics (between two on-chain events, for example) in Prometheus
*/

// DecodedLog is an extension of log containing log(event), contract name and chain ID
type DecodedLog[T any] struct {
	types.Log
	Name         string `json:"name"`
	ChainID      int64  `json:"chainId"`
	UnpackedData T      `json:"unpackedData"`
}

// LogStream aggregates all the data we need to import in Loki and Prometheus
type LogStream[T any] struct {
	RawLoki     []interface{}
	DecodedLoki []interface{}
	DecodedProm []*T
}

var prometheusOnce = &sync.Once{}

// ExposePrometheusMetricsFor temporarily exposes Prometheus endpoint so metrics can be scraped
func ExposePrometheusMetricsFor(interval time.Duration) error {
	prometheusOnce.Do(func() {
		http.Handle("/on-chain-metrics", promhttp.Handler())
	})
	go http.ListenAndServe(":9112", nil)
	Plog.Info().Msgf("Exposing Prometheus metrics for %s seconds..", interval.String())
	// 5 scrape intervals for this particular path
	time.Sleep(interval)
	return nil
}

// FilterUnpackEventsWithMeta filters and returns all the logs from block X to block Y with additional metadata
func FilterUnpackEventsWithMeta[T any](ctx context.Context, c *ethclient.Client, abiStr, contractAddr, eventName string, from, to *big.Int) ([]types.Log, []*DecodedLog[T], error) {
	parsedABI, err := abi.JSON(strings.NewReader(abiStr))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ABI: %w", err)
	}
	event, exists := parsedABI.Events[eventName]
	if !exists {
		Plog.Fatal().Str("Event", eventName).Msg("Event not found in ABI")
	}
	cID, err := c.ChainID(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get ChainID: %w", err)
	}
	query := ethereum.FilterQuery{
		FromBlock: from,
		ToBlock:   to,
		Addresses: []common.Address{common.HexToAddress(contractAddr)},
		Topics:    [][]common.Hash{{event.ID}},
	}
	logs, err := c.FilterLogs(ctx, query)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to filter logs: %w", err)
	}
	unpacked := make([]*DecodedLog[T], 0)
	for _, l := range logs {
		unpack := &DecodedLog[T]{
			Log:     l,
			Name:    eventName,
			ChainID: cID.Int64(),
		}
		var payload T

		err = parsedABI.UnpackIntoInterface(&payload, eventName, l.Data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unpack event data: %w", err)
		}
		unpack.UnpackedData = payload
		unpacked = append(unpacked, unpack)
	}
	return logs, unpacked, nil
}

// FilterContractEventsAllChains filters all contract events across all available chains and decodes them using go-ethereum generated binding package, adds contract name and chain ID
func FilterContractEventsAllChains[T any](ctx context.Context, in *Cfg, bcByChainID map[string]*ethclient.Client, abi, contractName string, eventName string, from, to *big.Int) (*LogStream[DecodedLog[T]], error) {
	refsBySelector, err := GetCLDFAddressesPerSelector(in)
	if err != nil {
		return nil, fmt.Errorf("failed to load addresses per selector: %w", err)
	}
	// to simplify the user-facing API we prepare data for both Loki pushes and Prometheus observations
	decodedPromStream := make([]*DecodedLog[T], 0)
	rawLokiStream := make([]interface{}, 0)
	decodedLokiStream := make([]interface{}, 0)
	// find all events for all the contract across the chains
	for _, ref := range refsBySelector {
		for _, r := range ref {
			if r.Type.String() == contractName {
				cID, err := chainsel.GetChainIDFromSelector(r.ChainSelector)
				if err != nil {
					return nil, fmt.Errorf("failed to get chain ID: %w", err)
				}
				_, data, err := FilterUnpackEventsWithMeta[T](ctx, bcByChainID[cID], abi, r.Address, eventName, from, to)
				if err != nil {
					return nil, fmt.Errorf("failed to filter logs: %w", err)
				}
				decodedPromStream = append(decodedPromStream, data...)
			}
		}
	}
	for _, event := range decodedPromStream {
		rawLokiStream = append(rawLokiStream, event)
		decodedLokiStream = append(decodedLokiStream, event.UnpackedData)
	}
	return &LogStream[DecodedLog[T]]{
		RawLoki:     rawLokiStream,
		DecodedLoki: decodedLokiStream,
		DecodedProm: decodedPromStream,
	}, nil
}

/*
CCIPv17 (CCV) specific helpers
*/

// NewV3ExtraArgs encodes v3 extra args params
//
//	// Helper function to create EVMExtraArgsV3 struct
//	function _createV3ExtraArgs(
//	  Client.CCV[] memory requiredCCVs,
//	  Client.CCV[] memory optionalCCVs,
//	  uint8 optionalThreshold
//	) internal pure returns (Client.EVMExtraArgsV3 memory) {
//	  return Client.EVMExtraArgsV3({
//	    requiredCCV: requiredCCVs,
//	    optionalCCV: optionalCCVs,
//	    optionalThreshold: optionalThreshold,
//	    finalityConfig: 12,
//	    executor: address(0), // No executor specified.
//	    executorArgs: "",
//	    tokenArgs: ""
//	  });
//	}
func NewV3ExtraArgs(finalityConfig uint32, execAddr, execArgs, tokenArgs []byte, requiredCCVs, optionalCCVs []ccvTypes.CCV, optionalThreshold uint8) ([]byte, error) {
	const clientABI = `
    [
        {
            "name": "encodeEVMExtraArgsV3",
            "type": "function",
            "inputs": [
                {
                    "components": [
                        {
                            "name": "requiredCCV",
                            "type": "tuple[]",
                            "components": [
                                {"name": "CCVAddress", "type": "bytes"},
                                {"name": "Args", "type": "bytes"},
                                {"name": "ArgsLen", "type": "uint16"}
                            ]
                        },
                        {
                            "name": "optionalCCV", 
                            "type": "tuple[]",
                            "components": [
                                {"name": "CCVAddress", "type": "bytes"},
                                {"name": "Args", "type": "bytes"},
                                {"name": "ArgsLen", "type": "uint16"}
                            ]
                        },
                        {"name": "executor", "type": "bytes"},
                        {"name": "executorArgs", "type": "bytes"},
                        {"name": "tokenArgs", "type": "bytes"},
                        {"name": "finalityConfig", "type": "uint32"},
                        {"name": "requiredCCVLen", "type": "uint16"},
                        {"name": "optionalCCVLen", "type": "uint16"},
                        {"name": "executorArgsLen", "type": "uint16"},
                        {"name": "tokenArgsLen", "type": "uint16"},
                        {"name": "optionalThreshold", "type": "uint8"}
                    ],
                    "name": "args",
                    "type": "tuple"
                }
            ],
            "outputs": [{"type": "bytes"}],
            "stateMutability": "pure"
        }
    ]
    `

	parsedABI, err := abi.JSON(bytes.NewReader([]byte(clientABI)))
	if err != nil {
		return nil, err
	}

	// Convert CCV slices to the expected format
	requiredCCV := make([]struct {
		CCVAddress []byte
		Args       []byte
		ArgsLen    uint16
	}, len(requiredCCVs))

	for i, ccv := range requiredCCVs {
		requiredCCV[i] = struct {
			CCVAddress []byte
			Args       []byte
			ArgsLen    uint16
		}{
			CCVAddress: ccv.CCVAddress,
			Args:       ccv.Args,
			ArgsLen:    ccv.ArgsLen,
		}
	}

	optionalCCV := make([]struct {
		CCVAddress []byte
		Args       []byte
		ArgsLen    uint16
	}, len(optionalCCVs))

	for i, ccv := range optionalCCVs {
		optionalCCV[i] = struct {
			CCVAddress []byte
			Args       []byte
			ArgsLen    uint16
		}{
			CCVAddress: ccv.CCVAddress,
			Args:       ccv.Args,
			ArgsLen:    ccv.ArgsLen,
		}
	}

	args := struct {
		RequiredCCV []struct {
			CCVAddress []byte
			Args       []byte
			ArgsLen    uint16
		}
		OptionalCCV []struct {
			CCVAddress []byte
			Args       []byte
			ArgsLen    uint16
		}
		Executor          []byte
		ExecutorArgs      []byte
		TokenArgs         []byte
		FinalityConfig    uint32
		RequiredCCVLen    uint16
		OptionalCCVLen    uint16
		ExecutorArgsLen   uint16
		TokenArgsLen      uint16
		OptionalThreshold uint8
	}{
		RequiredCCV:       requiredCCV,
		OptionalCCV:       optionalCCV,
		Executor:          execAddr,
		ExecutorArgs:      execArgs,
		TokenArgs:         tokenArgs,
		FinalityConfig:    finalityConfig,
		RequiredCCVLen:    uint16(len(requiredCCVs)),
		OptionalCCVLen:    uint16(len(optionalCCVs)),
		ExecutorArgsLen:   uint16(len(execArgs)),
		TokenArgsLen:      uint16(len(tokenArgs)),
		OptionalThreshold: optionalThreshold,
	}

	encoded, err := parsedABI.Methods["encodeEVMExtraArgsV3"].Inputs.Pack(args)
	if err != nil {
		return nil, err
	}

	tag := []byte{0x30, 0x23, 0x26, 0xcb}
	tag = append(tag, encoded...)
	return tag, nil
}

// SendExampleArgsV2Message sends an example message between two chains (selectors) using ArgsV2
func SendExampleArgsV2Message(in *Cfg, src uint64, dest uint64) error {
	selectors, e, err := NewCLDFOperationsEnvironment(in.Blockchains)
	if err != nil {
		return fmt.Errorf("creating CLDF operations environment: %w", err)
	}

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

	bundle := NewDefaultCLDFBundle(e)
	e.OperationsBundle = bundle

	routerAddr, err := GetContractAddrForSelector(in, srcChain.Selector, datastore.ContractType(router.ContractType))
	if err != nil {
		return fmt.Errorf("failed to get router address: %w", err)
	}

	// Create V2 extra args (default gas limit, no out-of-order execution)
	argsV2 := &ccvTypes.GenericExtraArgsV2{
		GasLimit:                 big.NewInt(200_000),
		AllowOutOfOrderExecution: false,
	}
	receiverAddress := "0x3Aa5ebB10DC797CAC828524e59A333d0A371443c"

	ccipSendArgs := router.CCIPSendArgs{
		DestChainSelector: dest,
		EVM2AnyMessage: router.EVM2AnyMessage{
			Receiver:     common.LeftPadBytes(common.HexToAddress(receiverAddress).Bytes(), 32),
			Data:         []byte{},
			TokenAmounts: []router.EVMTokenAmount{},
			ExtraArgs:    argsV2.ToBytes(),
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

	Plog.Info().Bool("Executed", sendReport.Output.Executed).
		Uint64("SrcChainSelector", sendReport.Output.ChainSelector).
		Uint64("DestChainSelector", dest).
		Str("SrcRouter", sendReport.Output.Tx.To).
		Msg("CCIP message sent")

	return nil
}

// SendExampleArgsV3Message sends an example message between two chains (selectors) using ArgsV3
func SendExampleArgsV3Message(in *Cfg, src uint64, dest uint64, finality uint32, execAddr, execArgs, tokenArgs []byte, ccv []ccvTypes.CCV, optCcv []ccvTypes.CCV, threshold uint8) error {
	selectors, e, err := NewCLDFOperationsEnvironment(in.Blockchains)
	if err != nil {
		return fmt.Errorf("creating CLDF operations environment: %w", err)
	}

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

	bundle := NewDefaultCLDFBundle(e)
	e.OperationsBundle = bundle

	routerAddr, err := GetContractAddrForSelector(in, srcChain.Selector, datastore.ContractType(router.ContractType))
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
			Receiver:     common.LeftPadBytes(srcChain.DeployerKey.From.Bytes(), 32),
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

	Plog.Info().Bool("Executed", sendReport.Output.Executed).
		Uint64("SrcChainSelector", sendReport.Output.ChainSelector).
		Uint64("DestChainSelector", dest).
		Str("SrcRouter", sendReport.Output.Tx.To).
		Msg("CCIP message sent")

	return nil
}
