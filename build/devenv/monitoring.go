package ccv

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	LokiOnChainStreamURL = "http://localhost:3000/explore?panes=%7B%22UYG%22:%7B%22datasource%22:%22P8E80F9AEF21F6940%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22expr%22:%22%7Bjob%3D%5C%22on-chain%5C%22%7D%22,%22queryType%22:%22range%22,%22datasource%22:%7B%22type%22:%22loki%22,%22uid%22:%22P8E80F9AEF21F6940%22%7D,%22editorMode%22:%22code%22%7D%5D,%22range%22:%7B%22from%22:%22now-30m%22,%22to%22:%22now%22%7D%7D%7D&schemaVersion=1&orgId=1"
	PromMetrics          = "http://localhost:3000/explore?panes=%7B%22UYG%22:%7B%22datasource%22:%22PBFA97CFB590B2093%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22expr%22:%22on_chain_ccip_msg_sent_total%22,%22range%22:true,%22datasource%22:%7B%22type%22:%22prometheus%22,%22uid%22:%22PBFA97CFB590B2093%22%7D,%22editorMode%22:%22code%22,%22legendFormat%22:%22__auto%22%7D%5D,%22range%22:%7B%22from%22:%22now-30m%22,%22to%22:%22now%22%7D%7D%7D&schemaVersion=1&orgId=1"
)

var msgSentTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "msg_sent_total",
	Help: "Total number of CCIP messages sent",
})

var srcDstLatency = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "msg_src_dst_duration_seconds",
	Help:    "Total duration of processing message from src to dst chain",
	Buckets: []float64{1, 2, 5, 10, 15, 20, 30, 45, 60, 90, 120, 180, 240, 300, 400, 500},
})

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
	msgSentEvent, err := FetchAllSentEventsBySelector(c.ProxySrc, c.DstChainDetails.ChainSelector)
	if err != nil {
		return err
	}
	msgsSent := make([]interface{}, 0)
	for _, msg := range msgSentEvent {
		msgsSent = append(msgsSent, msg)
	}
	execEvents, err := FetchAllExecEventsBySelector(c.AggDst, c.SrcChainDetails.ChainSelector)
	if err != nil {
		return err
	}
	msgsExec := make([]interface{}, 0)
	for _, msg := range execEvents {
		msgsExec = append(msgsExec, msg)
	}

	// process Loki streams
	if err := lp.Push(msgsSent, "on-chain-sent"); err != nil {
		return err
	}
	if err := lp.Push(msgsExec, "on-chain-exec"); err != nil {
		return err
	}

	// process Prom metrics
	logTimeByMsgID := make(map[[32]byte]uint64)
	for _, l := range msgSentEvent {
		logTimeByMsgID[l.MessageId] = l.Raw.BlockTimestamp
	}
	for _, l := range execEvents {
		blkTimeStarted, ok := logTimeByMsgID[l.MessageId]
		if !ok {
			continue
		}
		elapsed := l.Raw.BlockTimestamp - blkTimeStarted
		Plog.Debug().
			Any("MsgID", hexutil.Encode(l.MessageId[:])).
			Uint64("Seconds", elapsed).
			Msg("Elapsed time")
		srcDstLatency.Observe(float64(elapsed))
	}
	Plog.Info().Str("LokiStreamURL", LokiOnChainStreamURL).Send()
	Plog.Info().Str("PrometheusMetrics", PromMetrics).Send()
	return nil
}
