package logasserter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
)

// LogStream represents an active WebSocket connection to Loki's tail API.
type LogStream struct {
	conn   *websocket.Conn
	Logs   chan StreamedLog
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	stages []LogStage
	err    error
	errMu  sync.RWMutex
}

// StreamedLog represents a log entry received from Loki's streaming API.
type StreamedLog struct {
	Timestamp time.Time
	MessageID [32]byte
	Stage     string
	Instance  string
	RawLog    string
}

// lokiStreamResponse represents the JSON structure from Loki's tail API.
type lokiStreamResponse struct {
	Streams []struct {
		Stream map[string]string `json:"stream"`
		Values [][]string        `json:"values"`
	} `json:"streams"`
}

// StartLogStream initiates a WebSocket connection to Loki and starts streaming logs.
// This is a standalone function that can be used without LogAsserter.
func StartLogStream(ctx context.Context, wsURL string, stages []LogStage, logger zerolog.Logger) (*LogStream, error) {
	if len(stages) == 0 {
		return nil, fmt.Errorf("at least one log stage must be provided")
	}

	// Build LogQL query combining all stages
	query := buildStreamQuery(stages)

	// URL-encode the query and build the tail URL
	encodedQuery := url.QueryEscape(query)
	wsURL = fmt.Sprintf("%s/loki/api/v1/tail?query=%s", wsURL, encodedQuery)

	logger.Info().
		Str("url", wsURL).
		Str("query", query).
		Msg("Connecting to Loki WebSocket")

	// Connect to Loki
	conn, resp, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("failed to connect to Loki WebSocket (status %d): %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("failed to connect to Loki WebSocket: %w", err)
	}

	streamCtx, cancel := context.WithCancel(ctx)
	stream := &LogStream{
		conn:   conn,
		Logs:   make(chan StreamedLog, 1000),
		ctx:    streamCtx,
		cancel: cancel,
		stages: stages,
	}

	// Start reading messages from WebSocket
	stream.wg.Add(1)
	go stream.readLoop()

	return stream, nil
}

// buildStreamQuery creates a LogQL query for streaming multiple log stages.
func buildStreamQuery(stages []LogStage) string {
	// Collect unique services/containers
	servicesMap := make(map[string]bool)
	for _, stage := range stages {
		servicesMap[stage.Service] = true
	}

	// Build container matcher
	services := make([]string, 0, len(servicesMap))
	for service := range servicesMap {
		services = append(services, fmt.Sprintf(".*%s.*", service))
	}

	containerMatcher := fmt.Sprintf(`{container=~"%s"}`, strings.Join(services, "|"))

	// Collect unique log patterns
	patternsMap := make(map[string]bool)
	for _, stage := range stages {
		if stage.LogPattern != "" {
			patternsMap[stage.LogPattern] = true
		}
	}

	// If we have log patterns, add them as filters
	if len(patternsMap) > 0 {
		patterns := make([]string, 0, len(patternsMap))
		for pattern := range patternsMap {
			patterns = append(patterns, pattern)
		}

		// Build pattern matcher - use |= for regex matching multiple patterns
		if len(patterns) == 1 {
			return fmt.Sprintf(`%s |= "%s"`, containerMatcher, patterns[0])
		}
		return fmt.Sprintf(`%s |~ "%s"`, containerMatcher, strings.Join(patterns, "|"))
	}

	return containerMatcher
}

// StartLogStream initiates a WebSocket connection to Loki and starts streaming logs
// that match the provided stages. Logs are delivered to the returned LogStream.Logs channel.
// This method exists for backward compatibility.
func (l *LogAsserter) StartLogStream(ctx context.Context, stages []LogStage) (*LogStream, error) {
	return StartLogStream(ctx, l.lokiURL, stages, l.logger)
}

// readLoop continuously reads messages from the WebSocket connection.
func (s *LogStream) readLoop() {
	defer s.wg.Done()
	defer close(s.Logs)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		_, message, err := s.conn.ReadMessage()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				s.setError(fmt.Errorf("WebSocket read error: %w", err))
			}
			return
		}

		// Parse Loki's streaming response
		var response lokiStreamResponse
		if err := json.Unmarshal(message, &response); err != nil {
			continue // Skip malformed messages
		}

		// Process all streams in the response
		for _, stream := range response.Streams {
			instanceName := stream.Stream["container"]
			if instanceName == "" {
				instanceName = stream.Stream["pod"]
			}

			// Process all log entries in this stream
			for _, values := range stream.Values {
				if len(values) < 2 {
					continue
				}

				// Parse timestamp (nanoseconds)
				timestampNs := values[0]
				timestamp, err := parseTimestamp(timestampNs)
				if err != nil {
					continue
				}

				logLine := values[1]

				// Determine which stage this log belongs to
				stageName := s.identifyStage(logLine)
				if stageName == "" {
					continue
				}

				// Extract message ID from log line (may not exist for system-level logs like finality violations)
				messageID, hasMessageID := extractMessageID(logLine)
				if !hasMessageID {
					// For logs without messageID (e.g., finality violations), use a zero messageID
					messageID = [32]byte{}
				}

				// Send parsed log to channel
				select {
				case s.Logs <- StreamedLog{
					Timestamp: timestamp,
					MessageID: messageID,
					Stage:     stageName,
					Instance:  instanceName,
					RawLog:    logLine,
				}:
				case <-s.ctx.Done():
					return
				}
			}
		}
	}
}

// identifyStage determines which log stage a log line matches.
func (s *LogStream) identifyStage(logLine string) string {
	// Check if log line matches known patterns from log_stages.go
	if strings.Contains(logLine, ProcessingInExecutor().LogPattern) {
		return ProcessingInExecutor().Name
	}
	if strings.Contains(logLine, MessageReachedVerifier().LogPattern) {
		return MessageReachedVerifier().Name
	}
	if strings.Contains(logLine, MessageDroppedInVerifier().LogPattern) {
		return MessageDroppedInVerifier().Name
	}
	if strings.Contains(logLine, MessageSigned().LogPattern) {
		return MessageSigned().Name
	}
	if strings.Contains(logLine, SentToChainInExecutor().LogPattern) {
		return SentToChainInExecutor().Name
	}
	if strings.Contains(logLine, FinalityViolationDetected().LogPattern) {
		return FinalityViolationDetected().Name
	}
	if strings.Contains(logLine, SourceReaderStopped().LogPattern) {
		return SourceReaderStopped().Name
	}

	return ""
} // parseTimestamp converts Loki's nanosecond timestamp string to time.Time
func parseTimestamp(timestampNs string) (time.Time, error) {
	var ns int64
	_, err := fmt.Sscanf(timestampNs, "%d", &ns)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, ns), nil
}

// extractMessageID extracts a message ID from a log line or JSON label.
func extractMessageID(logLine string) ([32]byte, bool) {
	lastBrace := strings.LastIndex(logLine, "{")
	if lastBrace == -1 {
		return [32]byte{}, false
	}

	jsonPart := logLine[lastBrace:]
	var labels map[string]any
	if err := json.Unmarshal([]byte(jsonPart), &labels); err != nil {
		return [32]byte{}, false
	}

	for _, key := range []string{"messageID"} {
		val, ok := labels[key]
		if !ok {
			continue
		}

		strVal, ok := val.(string)
		if !ok {
			continue
		}

		strVal = strings.TrimPrefix(strVal, "0x")
		if len(strVal) < 64 {
			continue
		}

		hash := common.HexToHash(strVal)
		return hash, true
	}

	return [32]byte{}, false
}

// Stop closes the WebSocket connection and waits for the read loop to finish.
func (s *LogStream) Stop() error {
	s.cancel()

	// Close WebSocket connection
	if s.conn != nil {
		s.conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		s.conn.Close()
	}

	// Wait for read loop to finish
	s.wg.Wait()

	return s.getError()
}

// setError stores an error that occurred during streaming.
func (s *LogStream) setError(err error) {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.err == nil {
		s.err = err
	}
}

// getError retrieves any error that occurred during streaming.
func (s *LogStream) getError() error {
	s.errMu.RLock()
	defer s.errMu.RUnlock()
	return s.err
}
