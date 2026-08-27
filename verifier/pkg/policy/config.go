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
	DefaultRetryDelay = 10 * time.Second
	// maxResponseBytes caps how much of a policy response the verifier reads. The verdict is
	// a few dozen bytes; a larger body is a broken or hostile endpoint and is refused.
	maxResponseBytes = 64 << 10
	// maxReasonLength caps how much of an endpoint-supplied failure reason is logged.
	maxReasonLength = 256
)

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
	// EndpointURL is the operator's policy endpoint, called once per message with a POST.
	// Required, and must be https unless insecure_connection is set.
	EndpointURL string `toml:"endpoint_url"`
	// RequestTimeout bounds one call to the endpoint, as a Go duration string (e.g. "5s").
	// Empty uses the 5s default. A timeout is an endpoint error: the message is retried.
	RequestTimeout string `toml:"request_timeout"`
	// RetryDelay is how long a message waits before the endpoint is called again after an
	// endpoint error, as a Go duration string (e.g. "10s"). Empty uses the 10s default.
	RetryDelay string `toml:"retry_delay"`
	// InsecureConnection allows a plain http:// endpoint. Only for local development and
	// tests: a policy verdict carries compliance weight and must not travel in the clear.
	InsecureConnection bool `toml:"insecure_connection"`
}

// RequestTimeoutDuration returns the configured per-call timeout, or the default when unset.
func (c *Config) RequestTimeoutDuration() (time.Duration, error) {
	return parseDurationOr(c.RequestTimeout, "request_timeout", DefaultRequestTimeout)
}

// RetryDelayDuration returns the configured post-error retry delay, or the default when unset.
func (c *Config) RetryDelayDuration() (time.Duration, error) {
	return parseDurationOr(c.RetryDelay, "retry_delay", DefaultRetryDelay)
}

// Validate reports whether the section describes a usable endpoint. It is called from the
// committee verifier's config validation, so a malformed hook fails the job at load time
// rather than at the first message.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}

	raw := strings.TrimSpace(c.EndpointURL)
	if raw == "" {
		return fmt.Errorf("invalid policy_hook configuration: endpoint_url is required when the section is present")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid policy_hook configuration: endpoint_url %q is not a valid URL: %w", c.EndpointURL, err)
	}
	if parsed.Host == "" {
		return fmt.Errorf("invalid policy_hook configuration: endpoint_url %q has no host", c.EndpointURL)
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !c.InsecureConnection {
			return fmt.Errorf("invalid policy_hook configuration: endpoint_url %q is http; set insecure_connection to allow it outside production", c.EndpointURL)
		}
	default:
		return fmt.Errorf("invalid policy_hook configuration: endpoint_url %q must use http or https, got scheme %q", c.EndpointURL, parsed.Scheme)
	}

	timeout, err := c.RequestTimeoutDuration()
	if err != nil {
		return err
	}
	if timeout <= 0 {
		return fmt.Errorf("invalid policy_hook configuration: request_timeout must be positive, got %q", c.RequestTimeout)
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

func parseDurationOr(value, field string, fallback time.Duration) (time.Duration, error) {
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
