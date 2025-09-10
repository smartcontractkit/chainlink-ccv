package ccv

import (
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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

// CollectAndObserveEvents collects, decodes all the events using ABI provided by go-ethereum bindings package and observes them
func CollectAndObserveEvents(in *Cfg, bcByChainID map[string]*ethclient.Client, fromBlk, toBlk *big.Int) error {
	contractsToEvents := LogsByContractName{
		"CommitOnRamp":  {EventName: "ConfigSet", ABI: bindOnRamp.CommitOnRampMetaData.ABI},
		"CommitOffRamp": {EventName: "ConfigSet", ABI: bindOffRamp.CommitOffRampMetaData.ABI},
	}
	contractLogs := make([]*UnpackedLog, 0)
	for contractName, eventData := range contractsToEvents {
		_, unpackedLogs, err := filterContractEventsPerSelector(in, bcByChainID, eventData.ABI, contractName, eventData.EventName, fromBlk, toBlk)
		if err != nil {
			return fmt.Errorf("failed to push events for contract %s and event %s: %w", contractName, eventData.EventName, err)
		}
		contractLogs = append(contractLogs, unpackedLogs...)
	}
	for _, l := range contractLogs {
		// TODO: calculate latency between src and dst CCIPSend events and observe it
		// TODO: this is just an example
		Plog.Info().
			Any("EventData", l).
			Any("LogUnpackedData", l.UnpackedData).
			Msg("Observing event")
		srcDstCounter.Inc()
		var (
			fromTs time.Time
			toTs   time.Time
		)
		if l.ChainID == 1337 && l.Name == "ConfigSet" {
			fromTs = time.Unix(int64(l.BlkTimestamp), 0)
		}
		if l.ChainID == 2337 && l.Name == "ConfigSet" {
			toTs = time.Unix(int64(l.BlkTimestamp), 0)
		}
		if !fromTs.IsZero() && !toTs.IsZero() {
			secs := toTs.Sub(fromTs).Seconds()
			Plog.Info().
				Str("From", fromTs.String()).
				Str("To", toTs.String()).
				Any("Log", l).
				Any("LogUnpackedData", l.UnpackedData).
				Msg("Observing event")
			srcDstLatency.Observe(secs)
		}
	}
	return nil
}
