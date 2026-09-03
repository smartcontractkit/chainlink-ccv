package constructors

import (
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
)

// VerificationCoordinatorOption configures an optional dependency of NewVerificationCoordinator.
//
// These are options rather than parameters because the constructor's only caller is the Chainlink
// node repo. A positional signature that grows breaks that build the moment this lands, and the
// two repos cannot land a change at the same instant, so anything optional goes here and the
// existing call site keeps compiling until it opts in.
type VerificationCoordinatorOption func(*verificationCoordinatorOptions)

// verificationCoordinatorOptions holds the resolved options. The zero value is the behavior of a
// caller that passes none.
type verificationCoordinatorOptions struct {
	// policyHookCredential is nil when the caller supplied none, which calls the operator's
	// policy endpoint unauthenticated (and fails construction if the [policy_hook] section
	// sets require_auth).
	policyHookCredential *hmac.ClientConfig
}

func newVerificationCoordinatorOptions(opts []VerificationCoordinatorOption) verificationCoordinatorOptions {
	var resolved verificationCoordinatorOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&resolved)
		}
	}
	return resolved
}

// WithPolicyHookCredential supplies the HMAC credential the operator's policy endpoint identifies
// this verifier by.
//
// The standalone verifier reads this pair from the [policy_hook] table of its secrets file. A
// verifier running inside a Chainlink node has no such file, so the node resolves the credential
// and passes it here, the same way it passes the aggregator credentials.
//
// Omit it, or pass nil, to call the endpoint unauthenticated. That is the supported shape when the
// endpoint runs inside the verifier's own cluster; an operator who wants a missing credential to
// be fatal instead sets require_auth on the [policy_hook] section, which fails construction here.
func WithPolicyHookCredential(cred *hmac.ClientConfig) VerificationCoordinatorOption {
	return func(o *verificationCoordinatorOptions) { o.policyHookCredential = cred }
}
