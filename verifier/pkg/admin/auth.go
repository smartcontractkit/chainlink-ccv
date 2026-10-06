package admin

import (
	"errors"
	"net"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

// BasicAuth is the console UI credential from the console secrets file's
// [admin_ui] table. Nil means the console serves without basic auth (the
// loopback personal-tool default).
type BasicAuth struct {
	Username string
	Password string
}

// BasicAuthFromSecrets extracts the [admin_ui] pair. A half-supplied pair is a
// startup error, never a silent downgrade to unauthenticated serving.
func BasicAuthFromSecrets(s *vsecrets.VerifierSecrets) (*BasicAuth, error) {
	if s == nil || s.AdminUIAuth() == nil {
		return nil, nil
	}
	ui := s.AdminUIAuth()
	if ui.Username == "" || ui.Password == "" {
		return nil, errors.New("console secrets file [admin_ui] requires both username and password (remove the table to serve without basic auth)")
	}
	return &BasicAuth{Username: ui.Username, Password: ui.Password}, nil
}

// ValidateAccessPolicy enforces the console's exposure contract: non-loopback
// serving (including a wildcard bind) requires an identity source — the proxy
// actor header or basic auth.
func ValidateAccessPolicy(cfg *Config, auth *BasicAuth) error {
	host, _, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil {
		return err
	}
	if host == "127.0.0.1" || host == "::1" || host == "localhost" {
		return nil
	}
	if cfg.Access.ActorHeader == "" && auth == nil {
		return errors.New("serving a page grants privileged actions: a non-loopback listen_address requires an identity source — access.actor_header (authenticating proxy) or [admin_ui] basic auth in the console secrets file")
	}
	return nil
}
