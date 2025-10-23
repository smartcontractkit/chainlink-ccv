package logasserter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/metrics"
)

type LogAsserter struct {
	lokiURL      string
	logger       zerolog.Logger
	pollInterval time.Duration

	stream       *LogStream
	logCache     sync.Map
	streamCancel context.CancelFunc
	streamWg     sync.WaitGroup
}

type MessageStageLogs struct {
	mu        sync.RWMutex
	instances map[string][]InstanceLog
}

func New(lokiURL string, logger zerolog.Logger) *LogAsserter {
	return &LogAsserter{
		lokiURL:      lokiURL,
		logger:       logger,
		pollInterval: 100 * time.Millisecond,
	}
}

func (la *LogAsserter) StartStreaming(ctx context.Context, stages []LogStage) error {
	streamCtx, streamCancel := context.WithCancel(ctx)
	la.streamCancel = streamCancel

	stream, err := StartLogStream(streamCtx, la.lokiURL, stages, la.logger)
	if err != nil {
		return fmt.Errorf("failed to start log stream: %w", err)
	}

	la.stream = stream

	la.streamWg.Add(1)
	go la.processStreamedLogs()

	return nil
}

func (la *LogAsserter) StopStreaming() {
	if la.streamCancel != nil {
		la.streamCancel()
	}
	if la.stream != nil {
		la.stream.Stop()
	}
	la.streamWg.Wait()
}

func (la *LogAsserter) processStreamedLogs() {
	defer la.streamWg.Done()

	for {
		select {
		case logEntry, ok := <-la.stream.Logs:
			if !ok {
				return
			}

			msgIDHex := fmt.Sprintf("0x%x", logEntry.MessageID)

			logsInterface, _ := la.logCache.LoadOrStore(msgIDHex, &MessageStageLogs{
				instances: make(map[string][]InstanceLog),
			})
			msgLogs := logsInterface.(*MessageStageLogs)

			instance := InstanceLog{
				InstanceName: logEntry.Instance,
				Timestamp:    logEntry.Timestamp,
				LogLine:      logEntry.RawLog,
				Labels:       map[string]string{"container": logEntry.Instance},
			}

			msgLogs.mu.Lock()
			msgLogs.instances[logEntry.Stage] = append(
				msgLogs.instances[logEntry.Stage],
				instance,
			)
			msgLogs.mu.Unlock()

		case <-la.stream.ctx.Done():
			return
		}
	}
}

func (la *LogAsserter) WaitForStage(ctx context.Context, messageID [32]byte, stage LogStage) (time.Time, error) {
	if la.stream == nil {
		return time.Time{}, fmt.Errorf("streaming not started, call StartStreaming() first")
	}

	msgIDHex := fmt.Sprintf("0x%x", messageID)

	ticker := time.NewTicker(la.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return time.Time{}, fmt.Errorf("timeout waiting for stage %s for message %s", stage.Name, msgIDHex)
		case <-ticker.C:
			if logsInterface, ok := la.logCache.Load(msgIDHex); ok {
				msgLogs := logsInterface.(*MessageStageLogs)
				msgLogs.mu.RLock()
				instances := msgLogs.instances[stage.Name]
				msgLogs.mu.RUnlock()

				if len(instances) > 0 {
					timestamp := instances[0].Timestamp
					return timestamp, nil
				}
			}
		}
	}
}

func (la *LogAsserter) EnrichMetrics(metrics []metrics.MessageMetrics) {
	for i := range metrics {
		metric := &metrics[i]

		item, ok := la.logCache.Load(metric.MessageID)
		if !ok {
			continue
		}
		msgLogs := item.(*MessageStageLogs)

		messageSignedLogs, ok := msgLogs.instances[MessageSigned().Name]
		if !ok {
			continue
		}

		executorLogs, ok := msgLogs.instances[ProcessingInExecutor().Name]
		if !ok {
			continue
		}

		if len(messageSignedLogs) > 0 {
			metric.FirstVerifierSignTime = messageSignedLogs[0].Timestamp
		}

		if len(executorLogs) > 0 {
			metric.ExecutorProcessingTime = executorLogs[0].Timestamp
		}

		if !metric.FirstVerifierSignTime.IsZero() && !metric.ExecutorProcessingTime.IsZero() {
			metric.VerifierToExecutorLatency = metric.ExecutorProcessingTime.Sub(metric.FirstVerifierSignTime)
		}
	}
}
