package ccv

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	bindOffRamp "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/commit_offramp"
	bindOnRamp "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/commit_onramp"
)

var (
	srcDstCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "src_dst_total_requests",
		Help: "Total number of On-chain events",
	})

	srcDstLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "src_dst_total_latency_milliseconds",
		Help:    "Total duration of processing message from src to dst chain",
		Buckets: prometheus.DefBuckets,
	})
)

func runPromServer() error {
	http.Handle("/on-chain-metrics", promhttp.Handler())
	return http.ListenAndServe(":9112", nil)
}

// FilterUnpackFromTo filters and returns all the logs from block X to block Y
func FilterUnpackFromTo(ctx context.Context, c *ethclient.Client, abiStr, contractAddr, eventName string, from, to *big.Int) ([]types.Log, []map[string]any, error) {
	parsedABI, err := abi.JSON(strings.NewReader(abiStr))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ABI: %w", err)
	}
	event, exists := parsedABI.Events[eventName]
	if !exists {
		Plog.Fatal().Str("event", eventName).Msg("Event not found in ABI")
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
	unpacked := make([]map[string]any, 0)
	for _, l := range logs {
		unpack := map[string]interface{}{
			"event":       eventName,
			"blockHash":   l.BlockHash.Hex(),
			"blockNumber": l.BlockNumber,
			"txHash":      l.TxHash.Hex(),
			"txIndex":     l.TxIndex,
			"logIndex":    l.Index,
			"timestamp":   time.Now().Unix(),
			"address":     l.Address.Hex(),
		}
		err = parsedABI.UnpackIntoMap(unpack, eventName, l.Data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unpack event data: %w", err)
		}
		for i, topic := range l.Topics {
			if i > 0 {
				unpack[fmt.Sprintf("topic%d", i)] = topic.Hex()
			}
		}
		unpacked = append(unpacked, unpack)
	}
	return logs, unpacked, nil
}

func ServeEvents(in *Cfg) error {
	events, err := CollectEvents(in)
	if err != nil {
		return fmt.Errorf("failed to collect events: %w", err)
	}
	go runPromServer()
	if err := ObserveEvents(events); err != nil {
		return fmt.Errorf("failed to observe events: %w", err)
	}
	select {}
}

func ObserveEvents(events map[string]map[string]any) error {
	for contractName, data := range events {
		for eventName, eventData := range data {
			Plog.Info().
				Str("Contract", contractName).
				Str("Event", eventName).
				Any("EventData", eventData).
				Msg("Observing event")
			srcDstCounter.Inc()
			// TODO: calculate latency between src and dst events and observe it
		}
	}
	return nil
}

// CollectEvents collects and decodes all the events using ABI provided by go-ethereum bindings package
func CollectEvents(in *Cfg) (map[string]map[string]any, error) {
	contractsToEvents := map[string]struct {
		EventName string
		ABI       string
	}{
		"CommitOnRamp":  {EventName: "ConfigSet", ABI: bindOnRamp.CommitOnRampMetaData.ABI},
		"CommitOffRamp": {EventName: "ConfigSet", ABI: bindOffRamp.CommitOffRampMetaData.ABI},
	}
	contractEvents := make(map[string]map[string]any)
	for contractName, eventData := range contractsToEvents {
		_, unpackedLogs, err := filterContractEvents(in, eventData.ABI, contractName, eventData.EventName)
		if err != nil {
			return nil, fmt.Errorf("failed to push events for contract %s and event %s: %w", contractName, eventData.EventName, err)
		}
		spew.Dump(unpackedLogs)
		if contractEvents[contractName] == nil {
			contractEvents[contractName] = make(map[string]any)
		}
		for _, log := range unpackedLogs {
			contractEvents[contractName][eventData.EventName] = log
		}
	}
	spew.Dump(contractEvents)
	return contractEvents, nil
}

// filterContractEvents filters all contract events and decodes them using go-ethereum generated binding package
func filterContractEvents(in *Cfg, abi, contractName string, eventName string) ([]types.Log, []map[string]any, error) {
	refsBySelector, err := GetCLDFAddressesPerSelector(in)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load addresses per selector: %w", err)
	}
	selectorToURL := map[uint64]string{
		3379446385462418246:  "http://localhost:8545",
		12922642891491394802: "http://localhost:8555",
	}
	allLogs, allData := make([]types.Log, 0), make([]map[string]interface{}, 0)
	for _, ref := range refsBySelector {
		for _, contract := range ref {
			if contract.Type.String() == contractName {
				c, err := ethclient.Dial(selectorToURL[contract.ChainSelector])
				if err != nil {
					return nil, nil, fmt.Errorf("failed to connect to Ethereum: %w", err)
				}
				logs, data, err := FilterUnpackFromTo(context.Background(), c, abi, contract.Address, eventName, nil, nil)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to filter logs: %w", err)
				}
				allLogs = append(allLogs, logs...)
				allData = append(allData, data...)
			}
		}
	}
	return allLogs, allData, nil
}
