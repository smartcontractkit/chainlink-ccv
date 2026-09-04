// Package policy implements the operator-configurable policy hook: a binary PASS/FAIL gate
// that a committee verifier consults after finality and the curse and message-disablement
// checks pass, before it validates the message payload and signs.
//
// The gate calls exactly one operator-owned HTTPS endpoint per message. The operator's endpoint
// is their composition layer: it may run any number of internal checks or proxy third-party
// APIs, but it answers the verifier with a single verdict. The endpoint contract is published as
// an OpenAPI 3.0.3 document (verifier/policy_hook_openapi_v1.yaml) and versioned from v1.
//
// Decision semantics, which the rest of this package exists to keep exact:
//
//	HTTP 200 + PASS  -> the message is signed and attested as it would be with no hook at all.
//	HTTP 200 + FAIL  -> the message is dropped. It is never attested and never auto-executed,
//	                    recoverable only by an operator replay: rescheduling the archived job
//	                    or rewinding the verifier checkpoint.
//	anything else    -> retry. A 4xx, a 5xx, a timeout, an unreachable host, or a body the
//	                    verifier cannot parse never drops a message.
//
// The gate does not touch the signed payload: the request is derived from the verification task
// and the response is discarded once the verdict is read, so a signature produced with the hook
// enabled is byte-identical to one produced without it.
package policy

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultRequestTimeout bounds a single call to the policy endpoint. A slow endpoint
	// stalls the verification of that message only; the task is retried, never dropped.
	DefaultRequestTimeout = 5 * time.Second
	// DefaultRetryDelay is how long a message waits before the verifier calls the policy
	// endpoint again after an endpoint error. The task queue keeps retrying for its full
	// retry window (7 days), so a long outage delays messages rather than losing them.
	// The gate jitters this value per message; see GatedVerifier.retryDelayWithJitter.
	DefaultRetryDelay = 10 * time.Second
	// MaxRequestTimeout is the largest per-call timeout an operator may configure. A batch holds
	// up to StorageBatchSize (50) tasks and the gate keeps maxConcurrentEvaluations (8) calls in
	// flight, so a batch is up to seven sequential waves of endpoint calls. The task queue
	// reclaims a job whose lock has been held for longer than taskQueueLockDuration (2 minutes),
	// and a reclaimed job is evaluated again: a second call the operator pays for, and a second
	// trip through the drop path. Seven waves of 15s leave the batch a 15s margin inside that
	// lock for signing and the queue writes around it. An endpoint that needs longer than this
	// has to answer from its own queue rather than hold the call open.
	MaxRequestTimeout = 15 * time.Second
	// maxResponseBytes caps how much of a policy response the verifier reads. The verdict is
	// a few dozen bytes; a larger body is a broken or hostile endpoint and is refused.
	maxResponseBytes = 64 << 10
	// maxReasonLength caps how much of an endpoint-supplied failure reason is logged.
	maxReasonLength = 256
)

// EvaluatePath is where the verifier expects the evaluate operation to be mounted, relative to
// the operator's configured base_url. It is part of the published contract (the operationId in
// verifier/policy_hook_openapi_v1.yaml) rather than something an operator chooses.
//
// The verifier used to POST the configured URL verbatim, which let an operator mount the
// operation anywhere and made a client generated from the spec unusable, since a generated client
// appends the operation path to a base. Splitting the two gives both: the operator still chooses
// the base, including any prefix their gateway imposes, and the path is fixed so the spec
// describes the request that is actually sent.
const EvaluatePath = "/v1/evaluate"

// Config is the [policy_hook] section of the committee verifier config. Its presence enables
// the hook; a verifier with no section runs exactly as it did before the hook existed.
//
// v1 supports exactly one endpoint. That is deliberate: one call yields one verdict, which
// keeps the retry and drop semantics above unambiguous. An operator who needs several checks
// aggregates them behind their own endpoint.
//
// The durations are strings rather than time.Duration because the Chainlink node decodes
// committeeVerifierConfig with github.com/pelletier/go-toml, which does not decode TOML duration
// strings into time.Duration. Standalone decoding uses github.com/BurntSushi/toml, which does.
// Strings keep both deployment modes and changeset marshaling on one representation.
type Config struct {
	// BaseURL is the root the operator serves the policy operation under. The verifier POSTs to
	// base_url + "/v1/evaluate", once per message. Required, and must be https unless
	// insecure_connection is set. A base that already ends in the operation path is rejected at
	// startup rather than turned into a 404 on every message.
	//
	// A path prefix is allowed, so an endpoint behind a gateway that routes on one is configured
	// as "https://acme.example/compliance" and served at "/compliance/v1/evaluate". A query
	// string is not: it would have to survive path concatenation, and no part of the contract
	// needs one.
	BaseURL string `toml:"base_url"`
	// RequestTimeout bounds one call to the endpoint, as a Go duration string (e.g. "5s").
	// Empty uses the 5s default, and 15s is the maximum: a batch of policy calls has to finish
	// inside the task queue's job lock, and a batch that outruns it is reclaimed and evaluated
	// a second time. A timeout is an endpoint error: the message is retried.
	RequestTimeout string `toml:"request_timeout"`
	// RetryDelay is how long a message waits before the endpoint is called again after an
	// endpoint error, as a Go duration string (e.g. "10s"). Empty uses the 10s default. The
	// wait is jittered per message across half to one and a half times this value, so an
	// outage does not send the whole held backlog at the endpoint on the same tick.
	RetryDelay string `toml:"retry_delay"`
	// InsecureConnection allows a plain http:// endpoint. Only for local development and
	// tests: a policy verdict carries compliance weight and must not travel in the clear.
	InsecureConnection bool `toml:"insecure_connection"`
	// RequireAuth makes a missing endpoint credential fatal at startup instead of calling the
	// endpoint unauthenticated. The credential itself is never configured here: it comes from
	// the verifier secrets file, because this section is marshaled into the job spec. Set this
	// on any verifier whose endpoint checks the signature, so a credential that fails to reach
	// the container is a boot failure rather than every message on the lane retrying against a
	// 401 until the queue's deadline.
	RequireAuth bool `toml:"require_auth"`
}

// RequestTimeoutDuration returns the configured per-call timeout, or the default when unset.
func (c *Config) RequestTimeoutDuration() (time.Duration, error) {
	return parseDuration(c.RequestTimeout, "request_timeout", DefaultRequestTimeout)
}

// RetryDelayDuration returns the configured post-error retry delay, or the default when unset.
func (c *Config) RetryDelayDuration() (time.Duration, error) {
	return parseDuration(c.RetryDelay, "retry_delay", DefaultRetryDelay)
}

// Validate reports whether the section describes a usable endpoint. It is called from the
// committee verifier's config validation, so a malformed hook fails the job at load time
// rather than at the first message.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}

	parsed, err := c.parseBaseURL()
	if err != nil {
		return err
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !c.InsecureConnection {
			return fmt.Errorf("invalid policy_hook configuration: base_url %q is http; set insecure_connection to allow it outside production", c.BaseURL)
		}
	default:
		return fmt.Errorf("invalid policy_hook configuration: base_url %q must use http or https, got scheme %q", c.BaseURL, parsed.Scheme)
	}

	timeout, err := c.RequestTimeoutDuration()
	if err != nil {
		return err
	}
	if timeout <= 0 {
		return fmt.Errorf("invalid policy_hook configuration: request_timeout must be positive, got %q", c.RequestTimeout)
	}
	if timeout > MaxRequestTimeout {
		return fmt.Errorf(
			"invalid policy_hook configuration: request_timeout %q exceeds the %s maximum; a batch of policy calls has to finish inside the task queue's job lock, and a slower endpoint would have its messages evaluated twice",
			c.RequestTimeout, MaxRequestTimeout)
	}
	retryDelay, err := c.RetryDelayDuration()
	if err != nil {
		return err
	}
	if retryDelay <= 0 {
		return fmt.Errorf("invalid policy_hook configuration: retry_delay must be positive, got %q", c.RetryDelay)
	}

	return nil
}

// EvaluateURL is the URL the verifier POSTs to: the configured base with the contract's operation
// path appended. It is derived rather than configured so the spec and the request agree.
func (c *Config) EvaluateURL() (string, error) {
	parsed, err := c.parseBaseURL()
	if err != nil {
		return "", err
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + EvaluatePath
	return parsed.String(), nil
}

// parseBaseURL validates base_url and returns it parsed. It rejects the shapes that would make
// appending EvaluatePath produce a URL the operator did not mean: a query or a fragment would end
// up before the path rather than after it.
func (c *Config) parseBaseURL() (*url.URL, error) {
	raw := strings.TrimSpace(c.BaseURL)
	if raw == "" {
		return nil, fmt.Errorf("invalid policy_hook configuration: base_url is required when the section is present")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid policy_hook configuration: base_url %q is not a valid URL: %w", c.BaseURL, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("invalid policy_hook configuration: base_url %q has no host", c.BaseURL)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return nil, fmt.Errorf(
			"invalid policy_hook configuration: base_url %q has a query string; the verifier appends %s to the base, so a query cannot be carried",
			c.BaseURL, EvaluatePath)
	}
	if parsed.Fragment != "" {
		return nil, fmt.Errorf("invalid policy_hook configuration: base_url %q has a fragment", c.BaseURL)
	}
	if strings.HasSuffix(strings.TrimSuffix(parsed.Path, "/"), EvaluatePath) {
		return nil, fmt.Errorf(
			"invalid policy_hook configuration: base_url %q already ends in %s; configure the base the operation is mounted under, which the verifier appends %s to",
			c.BaseURL, EvaluatePath, EvaluatePath)
	}
	return parsed, nil
}

func parseDuration(value, field string, fallback time.Duration) (time.Duration, error) {
	s := strings.TrimSpace(value)
	if s == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid policy_hook configuration: %s %q is not a Go duration: %w", field, value, err)
	}
	return d, nil
}
