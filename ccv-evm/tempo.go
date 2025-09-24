package ccv_evm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
)

type TempoPayload struct {
	ResourceSpans []ResourceSpan `json:"resourceSpans"`
}

type ResourceSpan struct {
	Resource   Scope       `json:"resource"`
	ScopeSpans []ScopeSpan `json:"scopeSpans"`
}

type ScopeSpan struct {
	Scope Scope  `json:"scope"`
	Spans []Span `json:"spans"`
}

type Scope struct {
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	Attributes []Attribute `json:"attributes"`
}

type Span struct {
	TraceId           string      `json:"traceId"`
	ParentSpanId      string      `json:"parentSpanId,omitempty"`
	SpanId            string      `json:"spanId"`
	Name              string      `json:"name"`
	StartTimeUnixNano uint64      `json:"startTimeUnixNano"`
	EndTimeUnixNano   uint64      `json:"endTimeUnixNano"`
	Kind              uint8       `json:"kind"`
	Attributes        []Attribute `json:"attributes"`
}

type Attribute struct {
	Key   string         `json:"key"`
	Value map[string]any `json:"value"`
}

// TempoPusher handles pushing traces to Tempo.
type TempoPusher struct {
	tempoURL string
	client   *resty.Client
}

// NewTempoPusher creates a new TempoPusher instance.
func NewTempoPusher() *TempoPusher {
	tempoURL := os.Getenv("TEMPO_URL")
	if tempoURL == "" {
		tempoURL = DefaultTempoURL
	}
	return &TempoPusher{
		tempoURL: tempoURL,
		client:   resty.New().SetTimeout(10 * time.Second),
	}
}

func (tp *TempoPusher) PushTrace(ctx context.Context, spans []Span) error {
	l := zerolog.Ctx(ctx)
	l.Info().Msgf("Pushing spans to %v", tp.tempoURL)
	payload := TempoPayload{
		ResourceSpans: []ResourceSpan{
			{
				Resource: Scope{
					Attributes: []Attribute{
						{
							Key: "service.name",
							Value: map[string]any{
								"stringValue": "on-chain",
							},
						},
					},
				},
				ScopeSpans: []ScopeSpan{
					{
						Scope: Scope{
							Name:    "name",
							Version: "version",
							Attributes: []Attribute{
								{
									Key: "name",
									Value: map[string]any{
										"stringValue": "on-chain",
									},
								},
							},
						},
						Spans: spans,
					},
				},
			},
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	l.Info().Msgf("Payload: %v", string(jsonPayload))
	resp, err := tp.client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		Post(tp.tempoURL)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	if resp.StatusCode() != 200 && resp.StatusCode() != 204 {
		return fmt.Errorf("tempo returned status %d: %s", resp.StatusCode(), resp.String())
	}
	return nil
}
