package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Verdict is a usable answer from the policy endpoint: an HTTP 200 whose body parsed into one
// of the two v1 decisions. Every other outcome reaches the caller as an error.
type Verdict struct {
	// Decision is PASS or FAIL.
	Decision Decision
	// Reason is the endpoint's optional explanation of a FAIL, truncated for logging.
	Reason string
}

// Checker evaluates one message against the operator's policy endpoint.
//
// A returned error means the verdict is unknown — the endpoint was unreachable, slow, returned
// a non-200, or returned a body that is not a v1 response. Callers must retry on an error and
// must never read it as a rejection: an endpoint outage that dropped messages would be
// indistinguishable from a compliance decision, and dropped messages need an operator to replay
// them.
type Checker interface {
	// Evaluate returns the endpoint's verdict for one message, or an error if no verdict was
	// obtained. See the interface doc for why an error is not a rejection.
	Evaluate(ctx context.Context, req EvaluateRequest) (Verdict, error)
}

// HTTPChecker calls a single operator-owned HTTPS endpoint over POST.
//
// It does not reuse verifier/pkg/token/http, which backs the token attestation clients: that
// client is a per-URL singleton with a shared cool-down, and it folds every non-200 into one
// opaque error. The gate needs the opposite — an isolated client whose failure classification is
// explicit, because the difference between "unavailable" and "rejected" is the difference
// between retrying a message and dropping it.
type HTTPChecker struct {
	lggr     logger.Logger
	endpoint string
	client   *http.Client
}

// NewHTTPChecker builds a checker for the configured endpoint. The config must already be valid
// (see Config.Validate); an invalid one is rejected here as well rather than at the first call.
func NewHTTPChecker(lggr logger.Logger, cfg *Config) (*HTTPChecker, error) {
	if cfg == nil {
		return nil, errors.New("policy hook config is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	timeout, err := cfg.RequestTimeoutDuration()
	if err != nil {
		return nil, err
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("unexpected default HTTP transport type")
	}
	transport = transport.Clone()
	transport.MaxIdleConnsPerHost = 32

	return &HTTPChecker{
		lggr:     logger.With(lggr, "component", "PolicyHook", "endpoint", cfg.EndpointURL),
		endpoint: strings.TrimSpace(cfg.EndpointURL),
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// A policy endpoint has no reason to redirect, and following one would either
			// downgrade the transport or turn the POST into a GET on 301/302/303. Surface
			// the redirect as a non-2xx status instead, which retries.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Evaluate posts the request to the policy endpoint and returns its verdict.
func (c *HTTPChecker) Evaluate(ctx context.Context, req EvaluateRequest) (Verdict, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return Verdict{}, fmt.Errorf("failed to encode policy request for message %s: %w", req.MessageID, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return Verdict{}, fmt.Errorf("failed to build policy request for message %s: %w", req.MessageID, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	start := time.Now()
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return Verdict{}, fmt.Errorf("policy endpoint unreachable for message %s after %s: %w", req.MessageID, time.Since(start), classifyTransportError(err))
	}
	defer func() {
		// Drain a bounded amount so the connection can be reused, then close.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("policy endpoint returned status %d for message %s", resp.StatusCode, req.MessageID)
	}

	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return Verdict{}, fmt.Errorf("failed to read policy response for message %s: %w", req.MessageID, err)
	}
	if len(raw) > maxResponseBytes {
		return Verdict{}, fmt.Errorf("policy response for message %s exceeds %d bytes", req.MessageID, maxResponseBytes)
	}

	var parsed EvaluateResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Verdict{}, fmt.Errorf("failed to decode policy response for message %s: %w", req.MessageID, err)
	}
	// An endpoint that echoes message_id lets us refuse a verdict that answers a different
	// message. Signing on a crossed response would attest a message the policy never saw, so a
	// mismatch is an error and the message is retried.
	if parsed.MessageID != "" && !strings.EqualFold(strings.TrimSpace(parsed.MessageID), req.MessageID) {
		return Verdict{}, fmt.Errorf("policy response for message %s echoes message_id %q, so the verdict is for a different message", req.MessageID, parsed.MessageID)
	}
	decision, err := parseDecision(parsed.Decision)
	if err != nil {
		return Verdict{}, fmt.Errorf("invalid policy response for message %s: %w", req.MessageID, err)
	}

	c.lggr.Debugw("Policy endpoint responded",
		"messageID", req.MessageID,
		"decision", string(decision),
		"duration", time.Since(start),
	)

	return Verdict{Decision: decision, Reason: truncateReason(parsed.Reason)}, nil
}

// classifyTransportError makes a timeout say so. net/http wraps a context deadline in a
// *url.Error whose message is dominated by the URL, which reads badly in a per-message log line
// and in the error-class metric.
func classifyTransportError(err error) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("policy endpoint timed out: %w", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("policy endpoint timed out: %w", err)
	}
	return err
}

var _ Checker = (*HTTPChecker)(nil)
