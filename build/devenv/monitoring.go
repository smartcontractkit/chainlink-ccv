package ccv

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	ccvAggregator "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	ccvProxy "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_proxy"
)

const (
	LokiOnChainStreamURL = "http://localhost:3000/explore?panes=%7B%22UYG%22:%7B%22datasource%22:%22P8E80F9AEF21F6940%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22expr%22:%22%7Bjob%3D%5C%22on-chain%5C%22%7D%22,%22queryType%22:%22range%22,%22datasource%22:%7B%22type%22:%22loki%22,%22uid%22:%22P8E80F9AEF21F6940%22%7D,%22editorMode%22:%22code%22%7D%5D,%22range%22:%7B%22from%22:%22now-30m%22,%22to%22:%22now%22%7D%7D%7D&schemaVersion=1&orgId=1"
	PromMetrics          = "http://localhost:3000/explore?panes=%7B%22UYG%22:%7B%22datasource%22:%22PBFA97CFB590B2093%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22expr%22:%22on_chain_ccip_msg_sent_total%22,%22range%22:true,%22datasource%22:%7B%22type%22:%22prometheus%22,%22uid%22:%22PBFA97CFB590B2093%22%7D,%22editorMode%22:%22code%22,%22legendFormat%22:%22__auto%22%7D%5D,%22range%22:%7B%22from%22:%22now-30m%22,%22to%22:%22now%22%7D%7D%7D&schemaVersion=1&orgId=1"
)

var (
	msgSentTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "on_chain_ccip_msg_sent_total",
		Help: "Total number of CCIP messages sent",
	})

	srcDstLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "on_chain_src_dst_total_latency_milliseconds",
		Help:    "Total duration of processing message from src to dst chain",
		Buckets: prometheus.DefBuckets,
	})
)

// MonitorOnChainLogs is converting specified on-chain events (logs) to Loki/Prometheus data
// it does not preserve original timestamps for observation and Loki pushes and scans/uploads the whole range
// in case we need to get realtime metrics this function can be converted to a service that calls this function with
// block ranges for both chains
func MonitorOnChainLogs(in *Cfg) error {
	bcs, err := blockchainsByChainID(in)
	if err != nil {
		return err
	}
	lp := NewLokiPusher()
	ctx := context.Background()

	msgSentStreams, err := FilterContractEventsAllChains[ccvProxy.CCVProxyCCIPMessageSent](
		ctx,
		in,
		bcs,
		ccvProxy.CCVProxyMetaData.ABI,
		"CCVProxy",
		"CCIPMessageSent",
		nil,
		nil,
	)
	executionStateChangedStreams, err := FilterContractEventsAllChains[ccvAggregator.CCVAggregatorExecutionStateChanged](
		ctx,
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
	// process Loki streams
	if err := lp.PushRawAndDecoded(msgSentStreams.RawLoki, msgSentStreams.DecodedLoki, "on-chain"); err != nil {
		return fmt.Errorf("failed to push logs: %w", err)
	}
	if err := lp.PushRawAndDecoded(executionStateChangedStreams.RawLoki, executionStateChangedStreams.DecodedLoki, "on-chain"); err != nil {
		return fmt.Errorf("failed to push logs: %w", err)
	}
	// process Prom metrics
	logTimeByMsgID := make(map[[32]byte]uint64)
	for _, l := range msgSentStreams.DecodedProm {
		if l.ChainID == 1337 && l.Name == "CCIPMessageSent" {
			if payload, ok := any(l.UnpackedData).(ccvProxy.CCVProxyCCIPMessageSent); ok {
				Plog.Info().
					Str("MsgID", fmt.Sprintf("%x", payload.MessageId)).
					Uint64("BlockTimestamp", l.BlockTimestamp).
					Msg("Received CCIPMessageSent log")
				msgSentTotal.Inc()
				logTimeByMsgID[payload.MessageId] = l.BlockTimestamp
			}
		}
	}
	for _, l := range executionStateChangedStreams.DecodedProm {
		if l.ChainID == 2337 && l.Name == "ExecutionStateChanged" {
			if payload, ok := any(l.UnpackedData).(ccvAggregator.CCVAggregatorExecutionStateChanged); ok {
				Plog.Info().
					Str("MsgID", fmt.Sprintf("%x", payload.MessageId)).
					Uint64("BlockTimestamp", l.BlockTimestamp).
					Msg("Received ExecutionStateChanged log")
				// srcDstLatency.Observe(float64(l.BlockTimestamp))
			}
		}
	}
	Plog.Info().Str("LokiStreamURL", LokiOnChainStreamURL).Send()
	Plog.Info().Str("PrometheusMetrics", PromMetrics).Send()
	return nil
}
