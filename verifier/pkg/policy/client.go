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

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/policy/internal/policyapi"
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
//
// An implementation owns its own per-call deadline and must not rely on the caller for one. The
// ctx it is handed carries cancellation but not necessarily a deadline: GatedVerifier passes the
// batch's context straight through, so a Checker that waited on ctx alone would let one slow
// endpoint hold a verification job past the task queue's lock. HTTPChecker bounds each call with
// Config.RequestTimeout (5s by default, 15s maximum).
type Checker interface {
	// Evaluate returns the endpoint's verdict for one message, or an error if no verdict was
	// obtained. It must return within its own timeout regardless of ctx, and an error is never
	// a rejection; see the interface doc for both.
	Evaluate(ctx context.Context, req EvaluateRequest) (Verdict, error)
}

// HTTPChecker calls a single operator-owned HTTPS endpoint over POST, at the operator's configured
// base_url with the contract's EvaluatePath appended.
//
// It does not reuse verifier/pkg/token/http, which backs the token attestation clients: that
// client is a per-URL singleton with a shared cool-down, and it folds every non-200 into one
// opaque error. The gate needs the opposite — an isolated client whose failure classification is
// explicit, because the difference between "unavailable" and "rejected" is the difference
// between retrying a message and dropping it.
type HTTPChecker struct {
	lggr logger.Logger
	// api is generated from the published contract. It owns building the request: joining
	// base_url with the operation path, and setting the content type. It deliberately does not
	// own reading the response, because the generated *WithResponse helpers read the body
	// unbounded and fold every status into one shape, and the bounded read and the
	// unavailable-versus-rejected split below are the whole reason this package exists.
	api *policyapi.Client
	// endpoint is the URL api will POST, kept for logs and errors.
	endpoint string
	// cred is the optional HMAC credential the endpoint identifies this verifier by. Nil means
	// the operator configured none and the call goes out unauthenticated.
	cred *hmac.ClientConfig
}

// NewHTTPChecker builds a checker for the configured endpoint. The config must already be valid
// (see Config.Validate); an invalid one is rejected here as well rather than at the first call.
//
// cred is optional: nil calls the endpoint with no client credential. It is passed separately
// from cfg because cfg is marshaled into the verifier's job spec and stored in Job Distributor,
// which is not somewhere a secret may go.
func NewHTTPChecker(lggr logger.Logger, cfg *Config, cred *hmac.ClientConfig) (*HTTPChecker, error) {
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

	base, err := cfg.parseBaseURL()
	if err != nil {
		return nil, err
	}
	endpoint, err := cfg.EvaluateURL()
	if err != nil {
		return nil, err
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("unexpected default HTTP transport type")
	}
	transport = transport.Clone()
	transport.MaxIdleConnsPerHost = 32

	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// A policy endpoint has no reason to redirect, and following one would either
		// downgrade the transport or turn the POST into a GET on 301/302/303. Surface
		// the redirect as a non-2xx status instead, which retries.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// The generated client resolves the operation path against the base, so a base carrying a
	// gateway prefix keeps it. That is the same URL Config.EvaluateURL derives, and
	// TestHTTPChecker_PostsTheDerivedEvaluateURL holds the two together.
	//
	// It is built from the parsed base rather than from cfg.BaseURL, because parseBaseURL trims
	// before validating: a base_url with surrounding whitespace is a config the verifier accepts,
	// and url.Parse rejects the untrimmed string outright. Handing the raw value over would turn a
	// working config into an endpoint that fails every call.
	api, err := policyapi.NewClient(base.String(),
		policyapi.WithHTTPClient(httpClient),
		// The generated client sets Content-Type from the body but nothing else. Accept is
		// part of the request shape the contract describes, and an endpoint behind a gateway
		// that content-negotiates needs it.
		policyapi.WithRequestEditorFn(func(_ context.Context, httpReq *http.Request) error {
			httpReq.Header.Set("Accept", "application/json")
			return nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build policy endpoint client: %w", err)
	}

	return &HTTPChecker{
		lggr:     logger.With(lggr, "component", "PolicyHook", "endpoint", endpoint, "authenticated", cred != nil),
		api:      api,
		endpoint: endpoint,
		cred:     cred,
	}, nil
}

// Evaluate posts the request to the policy endpoint and returns its verdict.
func (c *HTTPChecker) Evaluate(ctx context.Context, req EvaluateRequest) (Verdict, error) {
	// Marshaled here rather than handed to the generated client's JSON overload because the
	// signature covers a hash of the exact bytes on the wire, so the signer needs those bytes.
	body, err := json.Marshal(req)
	if err != nil {
		return Verdict{}, fmt.Errorf("failed to encode policy request for message %s: %w", req.MessageId, err)
	}

	// Signed as a request editor, which runs after the generated client has fixed the method,
	// the URL, and the body. The signature covers all three.
	//
	// The editor's error is kept here as well as returned, because the generated client hands it
	// back through the same return as a transport failure and the two are not the same thing: one
	// is this node's credential, the other is the operator's endpoint. Both leave the caller with
	// no verdict, so both retry, but they go to an operator's logs and an error that sent someone
	// to look at a healthy endpoint would be worse than no error at all.
	var signErr error
	editors := make([]policyapi.RequestEditorFn, 0, 1)
	if c.cred != nil {
		editors = append(editors, func(_ context.Context, httpReq *http.Request) error {
			signErr = hmac.SignHTTPRequest(httpReq, c.cred, body, time.Now())
			return signErr
		})
	}

	start := time.Now()
	resp, err := c.api.PolicyEvaluateWithBody(ctx, "application/json", bytes.NewReader(body), editors...)
	if signErr != nil {
		return Verdict{}, fmt.Errorf("failed to sign policy request for message %s: %w", req.MessageId, signErr)
	}
	if err != nil {
		return Verdict{}, fmt.Errorf("policy endpoint unreachable for message %s after %s: %w", req.MessageId, time.Since(start), classifyTransportError(err))
	}
	defer func() {
		// Drain a bounded amount so the connection can be reused, then close.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("policy endpoint returned status %d for message %s", resp.StatusCode, req.MessageId)
	}

	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return Verdict{}, fmt.Errorf("failed to read policy response for message %s: %w", req.MessageId, err)
	}
	if len(raw) > maxResponseBytes {
		return Verdict{}, fmt.Errorf("policy response for message %s exceeds %d bytes", req.MessageId, maxResponseBytes)
	}

	var parsed EvaluateResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Verdict{}, fmt.Errorf("failed to decode policy response for message %s: %w", req.MessageId, err)
	}
	// An endpoint that echoes message_id lets us refuse a verdict that answers a different
	// message. Signing on a crossed response would attest a message the policy never saw, so a
	// mismatch is an error and the message is retried. The field is optional in the contract, so
	// a nil echo is not a mismatch, it is an endpoint that declined the check.
	if parsed.MessageId != nil && !strings.EqualFold(strings.TrimSpace(*parsed.MessageId), req.MessageId) {
		return Verdict{}, fmt.Errorf("policy response for message %s echoes message_id %q, so the verdict is for a different message", req.MessageId, *parsed.MessageId)
	}
	decision, err := parseDecision(parsed.Decision)
	if err != nil {
		return Verdict{}, fmt.Errorf("invalid policy response for message %s: %w", req.MessageId, err)
	}

	c.lggr.Debugw("Policy endpoint responded",
		"messageID", req.MessageId,
		"decision", string(decision),
		"duration", time.Since(start),
	)

	var reason string
	if parsed.Reason != nil {
		reason = truncateReason(*parsed.Reason)
	}
	return Verdict{Decision: decision, Reason: reason}, nil
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
