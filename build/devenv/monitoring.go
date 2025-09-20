package ccv

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	ccvAggregator "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	ccvProxy "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_proxy"
)

var msgSentTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "msg_sent_total",
	Help: "Total number of CCIP messages sent",
}, []string{"from", "to"})

var msgExecTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "msg_exec_total",
	Help: "Total number of CCIP messages executed",
}, []string{"from", "to"})

var srcDstLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "msg_src_dst_duration_seconds",
	Help:    "Total duration of processing message from src to dst chain",
	Buckets: []float64{1, 2, 5, 10, 15, 20, 30, 45, 60, 90, 120, 180, 240, 300, 400, 500},
}, []string{"from", "to"})

type LaneStreamConfig struct {
	From         *ccvProxy.CCVProxy
	To           *ccvAggregator.CCVAggregator
	FromSelector uint64
	ToSelector   uint64
}

type LaneStreams struct {
	SentEvents []*ccvProxy.CCVProxyCCIPMessageSent
	ExecEvents []*ccvAggregator.CCVAggregatorExecutionStateChanged
}

// MonitorOnChainLogs is converting specified on-chain events (logs) to Loki/Prometheus data
// it does not preserve original timestamps for observation and Loki pushes and scans/uploads the whole range
// in case we need to get realtime metrics this function can be converted to a service that calls this function with
// block ranges for both chains.
func MonitorOnChainLogs(in *Cfg) error {
	lp := NewLokiPusher()
	c, err := NewContracts(in)
	if err != nil {
		return err
	}
	err = ProcessLaneEvents(lp, &LaneStreamConfig{
		From:         c.Proxy1337,
		To:           c.Agg2337,
		FromSelector: c.Chain1337Details.ChainSelector,
		ToSelector:   c.Chain2337Details.ChainSelector,
	})
	if err != nil {
		return err
	}
	err = ProcessLaneEvents(lp, &LaneStreamConfig{
		From:         c.Proxy2337,
		To:           c.Agg1337,
		FromSelector: c.Chain2337Details.ChainSelector,
		ToSelector:   c.Chain1337Details.ChainSelector,
	})
	if err != nil {
		return err
	}
	return nil
}

// ProcessLaneEvents collects, pushes and observes sent and executed messages for lane
func ProcessLaneEvents(lp *LokiPusher, cfg *LaneStreamConfig) error {
	Plog.Info().Uint64("FromSelector", cfg.FromSelector).Uint64("ToSelector", cfg.ToSelector).Msg("Processing events")
	streams, err := FetchLaneEvents(cfg)
	if err != nil {
		return err
	}
	fromSelectorStr := fmt.Sprintf("%d", cfg.FromSelector)
	toSelectorStr := fmt.Sprintf("%d", cfg.ToSelector)
	// push Loki streams
	if err := lp.Push(ToAnySlice(streams.SentEvents), map[string]string{
		"job":  "on-chain-sent",
		"from": fromSelectorStr,
		"to":   toSelectorStr,
	}); err != nil {
		return err
	}
	if err := lp.Push(ToAnySlice(streams.ExecEvents), map[string]string{
		"job":  "on-chain-exec",
		"from": fromSelectorStr,
		"to":   toSelectorStr,
	}); err != nil {
		return err
	}

	// observe as Prometheus metrics
	logTimeByMsgID := make(map[[32]byte]uint64)
	for _, l := range streams.SentEvents {
		logTimeByMsgID[l.MessageId] = l.Raw.BlockTimestamp
		msgSentTotal.WithLabelValues(fromSelectorStr, toSelectorStr).Inc()
	}
	for _, l := range streams.ExecEvents {
		blkTimeStarted, ok := logTimeByMsgID[l.MessageId]
		if !ok {
			continue
		}
		elapsed := l.Raw.BlockTimestamp - blkTimeStarted
		Plog.Debug().
			Any("MsgID", hexutil.Encode(l.MessageId[:])).
			Uint64("Seconds", elapsed).
			Msg("Elapsed time")
		srcDstLatency.WithLabelValues(fromSelectorStr, toSelectorStr).Observe(float64(elapsed))
		msgExecTotal.WithLabelValues(fromSelectorStr, toSelectorStr).Inc()
	}
	return nil
}

// FetchLaneEvents fetch sent and exec events for lane
func FetchLaneEvents(cfg *LaneStreamConfig) (*LaneStreams, error) {
	msgSentEvent, err := FetchAllSentEventsBySelector(cfg.From, cfg.ToSelector)
	if err != nil {
		return nil, err
	}
	execEvents, err := FetchAllExecEventsBySelector(cfg.To, cfg.FromSelector)
	if err != nil {
		return nil, err
	}
	return &LaneStreams{
		SentEvents: msgSentEvent,
		ExecEvents: execEvents,
	}, nil
}
