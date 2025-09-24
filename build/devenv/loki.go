package ccv

//
//import (
//	"encoding/json"
//	"fmt"
//	"os"
//	"time"
//
//	"github.com/go-resty/resty/v2"
//)
//
//// LokiPusher handles pushing logs to Loki
//// it does not use Promtail client specifically to avoid dep hell between Prometheus/Loki go deps.
//type LokiPusher struct {
//	lokiURL string
//	client  *resty.Client
//}
//
//// LogEntry represents a single log entry for Loki.
//type LogEntry struct {
//	Timestamp time.Time         `json:"timestamp"`
//	Message   any               `json:"message"`
//	Labels    map[string]string `json:"labels,omitempty"`
//}
//
//// LokiStream represents a stream of log entries with labels.
//type LokiStream struct {
//	Stream map[string]string `json:"stream"`
//	Values [][]string        `json:"values"` // [timestamp, log line]
//}
//
//// LokiPayload represents the payload structure for Loki API.
//type LokiPayload struct {
//	Streams []LokiStream `json:"streams"`
//}
//
//// NewLokiPusher creates a new LokiPusher instance.
//func NewLokiPusher() *LokiPusher {
//	lokiURL := os.Getenv("LOKI_URL")
//	if lokiURL == "" {
//		lokiURL = DefaultLokiURL
//	}
//	return &LokiPusher{
//		lokiURL: lokiURL,
//		client:  resty.New().SetTimeout(10 * time.Second),
//	}
//}
//
//// Push pushes all the messages to a Loki stream
//func (lp *LokiPusher) Push(msgs []any, labels map[string]string) error {
//	if len(msgs) == 0 {
//		return nil
//	}
//	values := make([][]string, 0, len(msgs))
//
//	for i := 0; i < len(msgs); i++ {
//		combinedMessage := map[string]any{
//			"log": msgs[i],
//			"ts":  time.Now().Format(time.RFC3339Nano),
//		}
//		jsonBytes, err := json.Marshal(combinedMessage)
//		if err != nil {
//			return fmt.Errorf("failed to marshal combined message: %w", err)
//		}
//		values = append(values, []string{
//			fmt.Sprintf("%d", time.Now().UnixNano()),
//			string(jsonBytes),
//		})
//	}
//
//	stream := LokiStream{
//		Stream: labels,
//		Values: values,
//	}
//	resp, err := lp.client.R().
//		SetHeader("Content-Type", "application/json").
//		SetBody(LokiPayload{
//			Streams: []LokiStream{stream},
//		}).
//		Post(lp.lokiURL)
//	if err != nil {
//		return fmt.Errorf("failed to send request: %w", err)
//	}
//	if resp.StatusCode() != 200 && resp.StatusCode() != 204 {
//		return fmt.Errorf("loki returned status %d: %s", resp.StatusCode(), resp.String())
//	}
//	return nil
//}
