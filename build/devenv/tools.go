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

func NewCLDFBundle(e *deployment.Environment) operations.Bundle {
	return operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)
}

func GetRouterForSelector(in *Cfg, selector uint64) (common.Address, error) {
	var routerAddr common.Address
	for _, addr := range in.CCV.Addresses {
		var refs []datastore.AddressRef
		err := json.Unmarshal([]byte(addr), &refs)
		if err != nil {
			return common.Address{}, err
		}
		for _, ref := range refs {
			if ref.ChainSelector == selector && ref.Type == datastore.ContractType(router.ContractType) {
				routerAddr = common.HexToAddress(ref.Address)
			}
		}
	}
	return routerAddr, nil
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
This stuff should be exposed by Atlas as a transformation function that can work independently from any backend (PostgreSQL or Prometheus, etc)
But for now we use these functions to expose on-chain events (logs) as a custom aggregated metrics in Prometheus
*/

type UnpackedLog struct {
	types.Log
	Name         string         `json:"name"`
	ChainID      int64          `json:"chainId"`
	BlkTimestamp uint64         `json:"blkTimestamp"`
	UnpackedData map[string]any `json:"unpackedData"`
}

type LogSpec struct {
	EventName string
	ABI       string
	Client    *ethclient.Client
}
type LogsByContractName map[string]LogSpec

var once = &sync.Once{}

func exposePrometheusMetricsFor(interval time.Duration) error {
	once.Do(func() {
		http.Handle("/on-chain-metrics", promhttp.Handler())
	})
	go http.ListenAndServe(":9112", nil)
	Plog.Info().Msgf("Exposing Prometheus metrics for %s seconds..", interval.String())
	// 5 scrape intervals for this particular path
	time.Sleep(interval)
	return nil
}

// ServeOnChainEventsPrometheusFor is serving all the on-chain events we collect as a Prometheus custom handle "/on-chain-metrics"
func ServeOnChainEventsPrometheusFor(in *Cfg, interval time.Duration) error {
	bcs, err := blockchainsByChainID(in)
	if err != nil {
		return err
	}
	if err := CollectAndObserveEvents(in, bcs, nil, nil); err != nil {
		return fmt.Errorf("failed to collect events: %w", err)
	}
	return exposePrometheusMetricsFor(interval)
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

// FilterUnpackEvents filters and returns all the logs from block X to block Y
func FilterUnpackEvents(ctx context.Context, c *ethclient.Client, abiStr, contractAddr, eventName string, from, to *big.Int) ([]types.Log, []*UnpackedLog, error) {
	parsedABI, err := abi.JSON(strings.NewReader(abiStr))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ABI: %w", err)
	}
	event, exists := parsedABI.Events[eventName]
	if !exists {
		Plog.Fatal().Str("event", eventName).Msg("Event not found in ABI")
	}
	cID, err := c.ChainID(context.Background())
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
	unpacked := make([]*UnpackedLog, 0)
	for _, l := range logs {
		blk, err := c.HeaderByNumber(context.Background(), big.NewInt(int64(l.BlockNumber)))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get block by number: %w", err)
		}
		unpack := &UnpackedLog{
			Log:          l,
			Name:         eventName,
			ChainID:      cID.Int64(),
			BlkTimestamp: blk.Time,
		}
		unpackedData := make(map[string]any)
		err = parsedABI.UnpackIntoMap(unpackedData, eventName, l.Data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unpack event data: %w", err)
		}
		unpack.UnpackedData = unpackedData
		unpacked = append(unpacked, unpack)
	}
	return logs, unpacked, nil
}

// filterContractEventsPerSelector filters all contract events and decodes them using go-ethereum generated binding package
func filterContractEventsPerSelector(in *Cfg, bcByChainID map[string]*ethclient.Client, abi, contractName string, eventName string, from, to *big.Int) ([]types.Log, []*UnpackedLog, error) {
	refsBySelector, err := GetCLDFAddressesPerSelector(in)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load addresses per selector: %w", err)
	}
	allLogs, allLogsUnpacked := make([]types.Log, 0), make([]*UnpackedLog, 0)
	for _, ref := range refsBySelector {
		for _, contract := range ref {
			if contract.Type.String() == contractName {
				cID, err := chainsel.GetChainIDFromSelector(contract.ChainSelector)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to get chain ID: %w", err)
				}
				logs, data, err := FilterUnpackEvents(context.Background(), bcByChainID[cID], abi, contract.Address, eventName, from, to)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to filter logs: %w", err)
				}
				allLogs = append(allLogs, logs...)
				allLogsUnpacked = append(allLogsUnpacked, data...)
			}
		}
	}
	return allLogs, allLogsUnpacked, nil
}

func SendMessage(in *Cfg, src uint64, dest uint64) error {
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

	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)
	e.OperationsBundle = bundle

	var routerAddr common.Address
	for _, addr := range in.CCV.Addresses {
		var refs []datastore.AddressRef
		if err := json.Unmarshal([]byte(addr), &refs); err != nil {
			return fmt.Errorf("failed to unmarshal address: %w", err)
		}
		for _, ref := range refs {
			if ref.ChainSelector == src && ref.Type == datastore.ContractType(router.ContractType) {
				routerAddr = common.HexToAddress(ref.Address)
			}
		}
	}
	if routerAddr == (common.Address{}) {
		return fmt.Errorf("router address not found for selector %d", src)
	}

	const clientABI = `
		[
			{
				"name": "encodeGenericExtraArgsV2",
				"type": "function",
				"inputs": [
					{
						"components": [
							{
								"name": "gasLimit",
								"type": "uint256"
							},
							{
								"name": "allowOutOfOrderExecution",
								"type": "bool"
							}
						],
						"name": "args",
						"type": "tuple"
					}
				],
				"outputs": [],
				"stateMutability": "pure"
			}
		]
	`

	parsedABI, err := abi.JSON(bytes.NewReader([]byte(clientABI)))
	if err != nil {
		return fmt.Errorf("failed to parse ABI: %w", err)
	}

	genericExtraArgsV2 := struct {
		GasLimit                 *big.Int
		AllowOutOfOrderExecution bool
	}{
		GasLimit:                 big.NewInt(1_000_000),
		AllowOutOfOrderExecution: true,
	}
	encoded, err := parsedABI.Methods["encodeGenericExtraArgsV2"].Inputs.Pack(genericExtraArgsV2)
	if err != nil {
		return fmt.Errorf("failed to pack arguments: %w", err)
	}

	tag := []byte{0x18, 0x1d, 0xcf, 0x10} // GENERIC_EXTRA_ARGS_V2_TAG
	ccipSendArgs := router.CCIPSendArgs{
		DestChainSelector: dest,
		EVM2AnyMessage: router.EVM2AnyMessage{
			Receiver:     common.LeftPadBytes(srcChain.DeployerKey.From.Bytes(), 32),
			Data:         []byte{},
			TokenAmounts: []router.EVMTokenAmount{},
			ExtraArgs:    append(tag, encoded...),
		},
	}

	feeReport, err := operations.ExecuteOperation(bundle, router.GetFee, srcChain, contract.FunctionInput[router.CCIPSendArgs]{
		ChainSelector: srcChain.Selector,
		Address:       routerAddr,
		Args:          ccipSendArgs,
	})
	if err != nil {
		return fmt.Errorf("failed to get fee: %w", err)
	}

	// Send CCIP message with value
	ccipSendArgs.Value = feeReport.Output
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
		Msg("CCIP message sent!")

	return nil
}
