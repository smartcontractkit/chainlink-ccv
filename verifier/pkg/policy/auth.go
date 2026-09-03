package policy

import (
	"errors"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

// ResolveCredential reads the credential the verifier presents to the policy endpoint.
//
// The verifier secrets file is the only source. The environment variables that carry the older
// credentials (VERIFIER_AGGREGATOR_*, CL_DATABASE_URL) exist for backwards compatibility with
// deployments that predate the file; a credential introduced after the file has no such history,
// so it does not get an env var and there is only one place an operator has to look.
//
// Authentication is optional, so an entirely absent credential is not an error: it returns a nil
// config and the endpoint is called unauthenticated, which is the supported shape when the
// endpoint runs inside the verifier's own cluster. An operator who wants the absence to be fatal
// instead sets require_auth on the [policy_hook] section.
//
// A half-supplied pair is always an error rather than a silent downgrade to no authentication: an
// operator who set one of the two meant to authenticate.
//
// Errors name the field at fault, never a credential value, so they are safe to log.
func ResolveCredential(fileCred *vsecrets.PolicyHookSecret) (*hmac.ClientConfig, error) {
	if fileCred == nil {
		return nil, nil
	}
	cred, err := buildCredential(fileCred.APIKey, fileCred.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("invalid [policy_hook] credential in the verifier secrets file: %w", err)
	}
	return cred, nil
}

// buildCredential validates one credential pair, naming the half at fault by its key in the
// secrets file's [policy_hook] table.
//
// The parameters are named for what they hold rather than for the credential they belong to: id
// and signer carry values, never a setting name, and nothing here puts either into an error.
func buildCredential(id, signer string) (*hmac.ClientConfig, error) {
	switch {
	case id == "" && signer == "":
		return nil, nil
	case id == "":
		return nil, errors.New("secret_key is set but api_key is missing")
	case signer == "":
		return nil, errors.New("api_key is set but secret_key is missing")
	}
	if err := hmac.ValidateAPIKey(id); err != nil {
		return nil, fmt.Errorf("api_key: %w", err)
	}
	if err := hmac.ValidateSecret(signer); err != nil {
		return nil, fmt.Errorf("secret_key: %w", err)
	}
	return &hmac.ClientConfig{APIKey: id, Secret: signer}, nil
}
