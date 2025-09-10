package ccv

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	ccvAggregator "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	ccvProxy "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_proxy"
)

var (
	msgSentTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ccip_msg_sent_total",
		Help: "Total number of CCIP messages sent",
	})

	srcDstLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "src_dst_total_latency_milliseconds",
		Help:    "Total duration of processing message from src to dst chain",
		Buckets: prometheus.DefBuckets,
	})
)

// MonitorOnChainLogs is serving all the on-chain events we collect as a Prometheus custom handle "/on-chain-metrics"
func MonitorOnChainLogs(in *Cfg) error {
	bcs, err := blockchainsByChainID(in)
	if err != nil {
		return err
	}
	msgSentEvents, err := FilterContractEventsAllChains[ccvProxy.CCVProxyCCIPMessageSent](
		in,
		bcs,
		ccvProxy.CCVProxyMetaData.ABI,
		"CCVProxy",
		"CCIPMessageSent",
		nil,
		nil,
	)
	execStateChangedEvent, err := FilterContractEventsAllChains[ccvAggregator.CCVAggregatorExecutionStateChanged](
		in,
		bcs,
		ccvAggregator.CCVAggregatorMetaData.ABI,
		"CCVAggregator",
		"ExecutionStateChanged",
		nil,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to collect logs: %w", err)
	}
	logTimeByMsgID := make(map[[32]byte]uint64)
	for _, l := range msgSentEvents {
		Plog.Info().
			Any("EventData", l).
			Any("LogUnpackedData", l.UnpackedData).
			Msg("Observing event")
		if l.ChainID == 1337 && l.Name == "CCIPMessageSent" {
			if payload, ok := any(l.UnpackedData).(ccvProxy.CCVProxyCCIPMessageSent); ok {
				Plog.Info().
					Str("MsgID", fmt.Sprintf("%x", payload.Message.Header.MessageId)).
					Uint64("BlockTimestamp", l.BlockTimestamp).
					Msg("Received CCIPMessageSent log")
				msgSentTotal.Inc()
				logTimeByMsgID[payload.Message.Header.MessageId] = l.BlockTimestamp
			}
		}
	}
	for _, l := range execStateChangedEvent {
		_ = l
		if l.ChainID == 2337 && l.Name == "ExecutionStateChanged" {
			// TODO: get msgID and measure time for each variant of messages, no events emitted yet
			//srcDstLatency.Observe(float64(l.BlockTimestamp))
		}
	}
	return nil
}
