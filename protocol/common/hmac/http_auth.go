package hmac

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// SignHTTPRequest adds the three HMAC authentication headers to an outgoing HTTP request.
//
// It is the HTTP counterpart of NewClientInterceptor, which does the same for gRPC calls. Keeping
// both in this package means a service this repo calls authenticates the same way whichever
// transport it is on, and there is one implementation to review rather than one per client.
//
// The signed string is the same five fields GenerateStringToSign documents: the method, the
// request target, a hash of the exact body, the API key, and a millisecond timestamp. Covering the
// body and the timestamp is what lets a server reject a replayed or altered request rather than
// only recognize the caller.
//
// req.URL and body must both be final: the request target comes from req.URL.RequestURI(), so a
// query string added after signing is not covered, and body must be the exact bytes the request
// will send. A URL with no path signs "/", which is the target Go puts on the wire.
//
// now is a parameter so a caller can sign against a fixed clock in tests; pass time.Now()
// otherwise.
func SignHTTPRequest(req *http.Request, cfg *ClientConfig, body []byte, now time.Time) error {
	if req == nil || req.URL == nil {
		return errors.New("hmac: request with a URL is required")
	}
	if cfg == nil {
		return errors.New("hmac: client config is required")
	}

	timestamp := strconv.FormatInt(now.UnixMilli(), 10)
	stringToSign := GenerateStringToSign(
		req.Method,
		req.URL.RequestURI(),
		ComputeBodyHash(body),
		cfg.APIKey,
		timestamp,
	)
	signature, err := ComputeHMAC(cfg.Secret, stringToSign)
	if err != nil {
		// Never wrap this with the credential in scope: ComputeHMAC's error is about the
		// secret's encoding, and a caller will log it.
		return fmt.Errorf("hmac: failed to sign request: %w", err)
	}

	req.Header.Set(HeaderAuthorization, cfg.APIKey)
	req.Header.Set(HeaderTimestamp, timestamp)
	req.Header.Set(HeaderSignature, signature)
	return nil
}
