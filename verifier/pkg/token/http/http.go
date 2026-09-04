package http

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"

	"github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	// maxCoolDownDuration defines the maximum duration we can wait till firing the next request.
	maxCoolDownDuration = 10 * time.Minute
)

var (
	ErrDataMissing     = errors.New("token data missing")
	ErrNotReady        = errors.New("token data not ready")
	ErrRateLimit       = errors.New("token data API is being rate limited")
	ErrTimeout         = errors.New("token data API timed out")
	ErrUnknownResponse = errors.New("unexpected response from attestation API")
)

type Status int

// Client defines the interface for fetching token data via HTTP with either GET or POST methods.
type Client interface {
	// Get calls the token data API with the given path.
	Get(ctx context.Context, path string) (protocol.ByteSlice, Status, error)
	// Post calls the token data API with the given path and request data.
	Post(ctx context.Context, path string, requestData protocol.ByteSlice) (protocol.ByteSlice, Status, error)
}

// httpClient is a client for the attestation API. It encapsulates all the details specific to the HTTP interactions:
// - rate limiting
// - cool down period
// - parsing JSON response and handling errors
// Therefore cctp.Verifier or/and cctp.AttestationService is a higher level abstraction that uses httpClient
// to fetch attestations and can be more oriented around caching/processing the attestation data instead of handling
// the API specifics.
type httpClient struct {
	lggr       logger.Logger
	apiURL     *url.URL
	apiTimeout time.Duration
	rate       *rate.Limiter
	// coolDownDuration defines the time to wait after getting rate limited.
	// this value is only used if the 429 response does not contain the Retry-After header
	coolDownDuration time.Duration
	// coolDownUntil defines whether requests are blocked or not.
	coolDownUntil time.Time
	coolDownMu    *sync.RWMutex

	// observability
	metrics  verifier.MetricLabeler
	provider string
}

var (
	clientInstances = make(map[string]Client)
	mutex           sync.Mutex
)

// GetHTTPClient returns a singleton instance of the httpClient for the given API URL.
// It's critical to reuse existing clients because of the self-rate limiting mechanism. Being rate limited by
// Circle comes with a long cool down period, so we should always self-rate limit before hitting the API rate limit.
// IMPORTANT: In the loop world this might require major rework - e.g. making httpClient a loop plugin to
// enforce the singleton pattern.
func GetHTTPClient(
	lggr logger.Logger,
	metricLabeler verifier.MetricLabeler,
	provider string,
	api string,
	apiInterval time.Duration,
	apiTimeout time.Duration,
	coolDownDuration time.Duration,
) (Client, error) {
	mutex.Lock()
	defer mutex.Unlock()

	if client, exists := clientInstances[api]; exists {
		return client, nil
	}

	client, err := newHTTPClient(lggr, metricLabeler, provider, api, apiInterval, apiTimeout, coolDownDuration)
	if err != nil {
		return nil, err
	}

	clientInstances[api] = client
	return client, nil
}

func newHTTPClient(
	lggr logger.Logger,
	metricLabeler verifier.MetricLabeler,
	provider string,
	api string,
	apiInterval time.Duration,
	apiTimeout time.Duration,
	coolDownDuration time.Duration,
) (Client, error) {
	u, err := url.ParseRequestURI(api)
	if err != nil {
		return nil, err
	}
	return &httpClient{
		lggr:             lggr,
		apiURL:           u,
		apiTimeout:       apiTimeout,
		coolDownDuration: coolDownDuration,
		rate:             rate.NewLimiter(rate.Every(apiInterval), 1),
		coolDownMu:       &sync.RWMutex{},
		metrics:          metricLabeler,
		provider:         provider,
	}, nil
}

func (h *httpClient) Get(ctx context.Context, requestPath string) (protocol.ByteSlice, Status, error) {
	requestURL, err := h.buildRequestURL(requestPath)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	response, httpStatus, err := h.callAPI(ctx, h.lggr, http.MethodGet, requestURL, nil)
	h.lggr.Debugw(
		"Response from attestation API",
		"Method", "GET",
		"requestURL", requestURL.String(),
		"status", httpStatus,
		"err", err,
	)
	return response, httpStatus, err
}

func (h *httpClient) Post(
	ctx context.Context,
	requestPath string,
	requestData protocol.ByteSlice,
) (protocol.ByteSlice, Status, error) {
	requestURL, err := h.buildRequestURL(requestPath)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	response, httpStatus, err := h.callAPI(ctx, h.lggr, http.MethodPost, requestURL, bytes.NewBuffer(requestData))
	h.lggr.Debugw(
		"Response from attestation API",
		"Method", "POST",
		"requestURL", requestURL.String(),
		"requestBody", string(requestData),
		"status", httpStatus,
		"err", err,
	)
	return response, httpStatus, err
}

// buildRequestURL combines the base API URL with the request path, properly handling query parameters.
func (h *httpClient) buildRequestURL(requestPath string) (url.URL, error) {
	requestURL := *h.apiURL

	// Parse the requestPath to separate path and query components
	parsedPath, err := url.Parse(requestPath)
	if err != nil {
		return url.URL{}, err
	}

	// Join the base path with the request path
	requestURL.Path = path.Join(requestURL.Path, parsedPath.Path)

	// Preserve query parameters from the request path
	if parsedPath.RawQuery != "" {
		requestURL.RawQuery = parsedPath.RawQuery
	}

	return requestURL, nil
}

func (h *httpClient) callAPI(
	ctx context.Context,
	lggr logger.Logger,
	method string,
	url url.URL,
	body io.Reader,
) (payload protocol.ByteSlice, status Status, err error) {
	// mCtx is deliberately detached from the request's deadline: metric records
	// must not be silently dropped because the (often short) API timeout fired
	// while we were measuring the request.
	mCtx := context.WithoutCancel(ctx)
	_, span := otel.GetTracerProvider().Tracer("ccv.token.http").Start(ctx, "token_http_request",
		oteltrace.WithAttributes(
			attribute.String(tracing.HTTPMethodKey, method),
		),
	)
	defer span.End()

	start := time.Now()
	h.metrics.IncrementTokenHTTPActiveRequests(mCtx, h.provider)
	defer h.metrics.DecrementTokenHTTPActiveRequests(mCtx, h.provider)
	defer func() {
		outcome := classifyHTTPOutcome(err, status)
		h.metrics.RecordTokenHTTPRequest(mCtx, h.provider, method, outcome, int(status), time.Since(start))
		span.SetAttributes(
			attribute.String(tracing.HTTPOutcomeKey, outcome),
			attribute.String(tracing.HTTPStatusKey, strconv.Itoa(int(status))),
		)
		if err != nil {
			span.RecordError(err)
		}
	}()

	// Terminate immediately when rate limited
	if coolDown, duration := h.inCoolDownPeriod(); coolDown {
		h.metrics.RecordTokenHTTPCooldownSeconds(mCtx, h.provider, duration)
		h.metrics.IncrementTokenHTTPRateLimited(mCtx, h.provider, method)
		lggr.Errorw(
			"Rate limited by API, dropping all requests",
			"coolDownDuration", duration,
		)
		return nil, http.StatusTooManyRequests, ErrRateLimit
	}
	h.metrics.RecordTokenHTTPCooldownSeconds(mCtx, h.provider, 0)

	if h.rate != nil {
		// Wait blocks until it the attestation API can be called or the
		// context is Done.
		if waitErr := h.rate.Wait(ctx); waitErr != nil {
			h.metrics.IncrementTokenHTTPRateLimited(mCtx, h.provider, method)
			lggr.Warnw("Self rate-limited, sending too many requests to the API")
			return nil, http.StatusTooManyRequests, ErrRateLimit
		}
	}

	// Use a timeout to guard against attestation API hanging, causing observation timeout and
	// failing to make any progress.
	timeoutCtx, cancel := context.WithTimeoutCause(ctx, h.apiTimeout, ErrTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(timeoutCtx, method, url.String(), body)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	req.Header.Add("accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, http.StatusRequestTimeout, ErrTimeout
		} else if errors.Is(err, ErrTimeout) {
			return nil, http.StatusRequestTimeout, ErrTimeout
		}
		// On error, res is nil in most cases, do not read res.StatusCode, return BadRequest
		return nil, http.StatusBadRequest, err
	}

	//nolint:errcheck // closing body, error can be ignored here
	defer res.Body.Close()
	status = Status(res.StatusCode)

	// Explicitly signal if the API is being rate limited
	if res.StatusCode == http.StatusTooManyRequests {
		h.metrics.IncrementTokenHTTPRateLimited(mCtx, h.provider, method)
		h.setCoolDownPeriod(lggr, res.Header)
		return nil, status, ErrRateLimit
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, status, ErrNotReady
	}
	if res.StatusCode != http.StatusOK {
		return nil, status, ErrUnknownResponse
	}

	// Limit the maximum response size to prevent unbounded memory usage.
	limit := int64(10 << 20) // 10 MiB
	lr := &io.LimitedReader{R: res.Body, N: limit + 1}
	payloadBytes, err := io.ReadAll(lr)
	if int64(len(payloadBytes)) > limit {
		return nil, http.StatusRequestEntityTooLarge, errors.New("attestation API response too large")
	}
	return payloadBytes, status, err
}

// classifyHTTPOutcome maps an attestation HTTP request result to a bounded outcome label.
func classifyHTTPOutcome(err error, status Status) string {
	switch {
	case errors.Is(err, ErrRateLimit) || status == http.StatusTooManyRequests:
		return "rate_limited"
	case errors.Is(err, ErrNotReady) || status == http.StatusNotFound:
		return "not_ready"
	case errors.Is(err, ErrTimeout) || status == http.StatusRequestTimeout:
		return "timeout"
	case err != nil:
		return "error"
	default:
		return "success"
	}
}

func (h *httpClient) setCoolDownPeriod(lggr logger.Logger, headers http.Header) {
	coolDownDuration := h.coolDownDuration
	if retryAfterHeader, exists := headers["Retry-After"]; exists && len(retryAfterHeader) > 0 {
		retryAfterSec, errParseInt := strconv.ParseInt(retryAfterHeader[0], 10, 64)
		if errParseInt == nil {
			coolDownDuration = time.Duration(retryAfterSec) * time.Second
		} else {
			parsedTime, err := time.Parse(time.RFC1123, retryAfterHeader[0])
			if err == nil {
				coolDownDuration = time.Until(parsedTime)
			}
		}
	}
	coolDownDuration = min(coolDownDuration, maxCoolDownDuration)
	// Logging on the error level, because we should always self-rate limit before hitting the API rate limit
	lggr.Errorw(
		"Rate limited by the Attestation API, setting cool down",
		"coolDownDuration", coolDownDuration,
	)

	h.coolDownMu.Lock()
	defer h.coolDownMu.Unlock()
	h.coolDownUntil = time.Now().Add(coolDownDuration)
}

func (h *httpClient) inCoolDownPeriod() (bool, time.Duration) {
	h.coolDownMu.RLock()
	defer h.coolDownMu.RUnlock()
	return time.Now().Before(h.coolDownUntil), time.Until(h.coolDownUntil)
}
