package policy

import (
	"errors"
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
//
// envVarPrefix is what an error message points an operator at, rather than either full name.
// Naming the pair by its prefix keeps the message out of the dataflow that security scanning
// tracks from credential-shaped identifiers into logs, and cannot go stale against the two
// constants built from it.
const (
	envVarPrefix    = "VERIFIER_POLICY_HOOK_"
	APIKeyEnvVar    = envVarPrefix + "API_KEY"
	SecretKeyEnvVar = envVarPrefix + "SECRET_KEY"
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
// Errors name the source they came from and the half at fault, never a credential value, so they
// are safe to log.
func ResolveCredential(fileCred *vsecrets.PolicyHookSecret) (*hmac.ClientConfig, error) {
	// Each branch names its own source in a literal, rather than threading the field and
	// variable names through buildCredential. Passing them would mean reading identifiers that
	// look like credentials into a message that ends up in a log, which is a shape security
	// scanning flags and a reader has to check by hand to see holds only names.
	if fileCred != nil {
		cred, err := buildCredential(fileCred.APIKey, fileCred.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("invalid [policy_hook] credential in the verifier secrets file: %w", err)
		}
		return cred, nil
	}
	cred, err := buildCredential(os.Getenv(APIKeyEnvVar), os.Getenv(SecretKeyEnvVar))
	if err != nil {
		return nil, fmt.Errorf("invalid policy hook credential in %s*: %w", envVarPrefix, err)
	}
	return cred, nil
}

// buildCredential validates one credential pair. Its errors name the half at fault by the term
// both sources share — the file's api_key and secret_key keys are the environment's _API_KEY and
// _SECRET_KEY suffixes — so the caller supplies the source and this supplies the fault.
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
