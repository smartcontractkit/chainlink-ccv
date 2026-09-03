package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// The fake policy endpoint's test-control routes, mirroring build/devenv/fakes/pkg/policy which
// serves them. The endpoint the verifier itself calls, /policy/v1/evaluate, is configured in
// env-policy-hook.toml and is the only route that is part of the published operator contract.
const (
	policyControlPath = "/policy/v1/control"
	policyCallsPath   = "/policy/v1/control/calls"
)

// policyControlRequest drives the fake. ForceStatus is always applied by the fake, so a request
// that omits it clears a previously forced status.
type policyControlRequest struct {
	DefaultDecision string   `json:"default_decision,omitempty"`
	Reason          string   `json:"reason,omitempty"`
	Reject          []string `json:"reject,omitempty"`
	ForceStatus     int      `json:"force_status,omitempty"`
	Reset           bool     `json:"reset,omitempty"`
}

type policyCallsResponse struct {
	PerMessage map[string]int `json:"per_message"`
	Total      int            `json:"total"`
}

// policyFake talks to the fake policy endpoint over its host-side URL. The verifier containers
// reach the same server on the docker network as http://fake:9111 (see env-policy-hook.toml).
type policyFake struct {
	baseURL string
}

func newPolicyFake(t *testing.T, in *ccv.Cfg) *policyFake {
	t.Helper()

	require.NotNil(t, in.Fake, "the policy-hook profile needs the [fake] service")
	require.NotNil(t, in.Fake.Out, "fake service has no output")
	require.NotEmpty(t, in.Fake.Out.ExternalHTTPURL, "fake service has no external URL")

	return &policyFake{baseURL: in.Fake.Out.ExternalHTTPURL}
}

// control applies req to the fake.
func (p *policyFake) control(t *testing.T, ctx context.Context, req policyControlRequest) {
	t.Helper()

	body, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+policyControlPath, bytes.NewReader(body))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	require.NoError(t, err, "fake policy endpoint control call failed")
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "control call rejected: %s", respBody)
}

// reset returns the fake to its default state: PASS for everything, no forced status, empty
// call log.
func (p *policyFake) reset(t *testing.T, ctx context.Context) {
	t.Helper()
	p.control(t, ctx, policyControlRequest{Reset: true})
}

// rejectMessage makes the endpoint answer FAIL for exactly this message.
func (p *policyFake) rejectMessage(t *testing.T, ctx context.Context, messageID protocol.Bytes32, reason string) {
	t.Helper()
	p.control(t, ctx, policyControlRequest{Reject: []string{messageID.String()}, Reason: reason})
}

// forceStatus makes the endpoint answer every call with an HTTP error instead of a verdict,
// which is what an operator endpoint outage looks like to the verifier.
func (p *policyFake) forceStatus(t *testing.T, ctx context.Context, status int) {
	t.Helper()
	p.control(t, ctx, policyControlRequest{ForceStatus: status})
}

// endOutage lifts a forced outage without clearing the call log or the reject set.
func (p *policyFake) endOutage(t *testing.T, ctx context.Context) {
	t.Helper()
	p.control(t, ctx, policyControlRequest{DefaultDecision: "PASS"})
}

func (p *policyFake) calls(t *testing.T, ctx context.Context) policyCallsResponse {
	t.Helper()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+policyCallsPath, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(httpReq)
	require.NoError(t, err, "fake policy endpoint call log request failed")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out policyCallsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// callsFor reports how many times the endpoint was asked about one message. Every committee
// node calls independently, so a two-node committee that evaluated a message once each reports
// two.
func (p *policyFake) callsFor(t *testing.T, ctx context.Context, messageID protocol.Bytes32) int {
	t.Helper()
	return p.calls(t, ctx).PerMessage[messageID.String()]
}
