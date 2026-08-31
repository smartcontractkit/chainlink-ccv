package policy

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

// Environment variables holding the policy endpoint credential, used when the verifier secrets
// file does not supply a [policy_hook] table. These are env var names, not secret values.
const (
	APIKeyEnvVar    = "VERIFIER_POLICY_HOOK_API_KEY"    //nolint:gosec // G101: env var name, not a credential
	SecretKeyEnvVar = "VERIFIER_POLICY_HOOK_SECRET_KEY" //nolint:gosec // G101: env var name, not a credential
)

// ResolveCredential reads the credential the verifier presents to the policy endpoint.
//
// Authentication is optional, so an entirely absent credential is not an error: it returns a nil
// config and the endpoint is called unauthenticated, which is the supported shape when the
// endpoint runs inside the verifier's own cluster. An operator who wants the absence to be fatal
// instead sets require_auth on the [policy_hook] section.
//
// The secrets file wins over the environment, matching how aggregator credentials resolve. A
// half-supplied pair is always an error rather than a silent downgrade to no authentication: an
// operator who set one of the two meant to authenticate.
//
// Errors name the source (env var name, or file field name) and never the credential value, so
// they are safe to log.
func ResolveCredential(fileCred *vsecrets.PolicyHookSecret) (*hmac.ClientConfig, error) {
	if fileCred != nil {
		return buildCredential(fileCred.APIKey, fileCred.SecretKey, "api_key", "secret_key")
	}
	return buildCredential(os.Getenv(APIKeyEnvVar), os.Getenv(SecretKeyEnvVar), APIKeyEnvVar, SecretKeyEnvVar)
}

// buildCredential validates an API key / secret pair. apiKeyLabel and secretLabel name where the
// values came from so an error points the operator at the right place.
func buildCredential(apiKey, secret, apiKeyLabel, secretLabel string) (*hmac.ClientConfig, error) {
	if apiKey == "" && secret == "" {
		return nil, nil
	}
	if apiKey == "" {
		return nil, fmt.Errorf("invalid policy_hook credential: %s is set but %s is missing", secretLabel, apiKeyLabel)
	}
	if secret == "" {
		return nil, fmt.Errorf("invalid policy_hook credential: %s is set but %s is missing", apiKeyLabel, secretLabel)
	}
	if err := hmac.ValidateAPIKey(apiKey); err != nil {
		return nil, fmt.Errorf("invalid policy_hook credential: %s: %w", apiKeyLabel, err)
	}
	if err := hmac.ValidateSecret(secret); err != nil {
		return nil, fmt.Errorf("invalid policy_hook credential: %s: %w", secretLabel, err)
	}
	return &hmac.ClientConfig{APIKey: apiKey, Secret: secret}, nil
}

// signRequest adds the HMAC authentication headers to an outgoing policy request.
//
// The scheme is the one the aggregator already uses (protocol/common/hmac), reused rather than
// invented so this repo has one signing scheme for an operator to implement against and one
// implementation to review. The signature covers the method, the request target, a hash of the
// exact body being sent, the API key, and a millisecond timestamp, so an endpoint can reject a
// replayed or altered request rather than only recognizing the caller.
//
// The request target is taken from the URL the verifier actually sends, including any query the
// operator put in endpoint_url, because that is what their server sees and has to reconstruct.
// A URL with no path signs "/", which is the target Go puts on the wire.
func signRequest(httpReq *http.Request, cred *hmac.ClientConfig, body []byte, now time.Time) error {
	timestamp := strconv.FormatInt(now.UnixMilli(), 10)
	stringToSign := hmac.GenerateStringToSign(
		hmac.HTTPMethodPost,
		httpReq.URL.RequestURI(),
		hmac.ComputeBodyHash(body),
		cred.APIKey,
		timestamp,
	)
	signature, err := hmac.ComputeHMAC(cred.Secret, stringToSign)
	if err != nil {
		// Never wrap this with the credential in scope: ComputeHMAC's error is about the
		// secret's encoding, and the caller logs it.
		return fmt.Errorf("failed to sign policy request: %w", err)
	}

	httpReq.Header.Set(hmac.HeaderAuthorization, cred.APIKey)
	httpReq.Header.Set(hmac.HeaderTimestamp, timestamp)
	httpReq.Header.Set(hmac.HeaderSignature, signature)
	return nil
}
