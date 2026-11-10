package admin

import (
	"errors"
	"net"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

// BasicAuth is the console UI credential from the service secrets file's [admin_ui] table.
type BasicAuth struct {
	Username string
	Password string
}

// NewBasicAuth validates a credential pair from a service secrets file.
func NewBasicAuth(username, password string) (*BasicAuth, error) {
	if username == "" || password == "" {
		return nil, errors.New("console secrets file [admin_ui] requires both username and password (remove the table to serve without basic auth)")
	}
	return &BasicAuth{Username: username, Password: password}, nil
}

// BasicAuthFromSecrets extracts the [admin_ui] pair from the verifier secrets file.
func BasicAuthFromSecrets(s *vsecrets.VerifierSecrets) (*BasicAuth, error) {
	if s == nil || s.AdminUIAuth() == nil {
		return nil, nil
	}
	ui := s.AdminUIAuth()
	return NewBasicAuth(ui.Username, ui.Password)
}

// ValidateAccessPolicy enforces the console's exposure contract: non-loopback
// serving (including a wildcard bind) requires [admin_ui] basic auth.
func ValidateAccessPolicy(cfg *Config, auth *BasicAuth) error {
	host, _, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil {
		return err
	}
	if host == "127.0.0.1" || host == "::1" || host == "localhost" {
		return nil
	}
	if auth == nil {
		return errors.New("serving a page grants privileged access: a non-loopback listen_address requires [admin_ui] basic auth in the service secrets file")
	}
	return nil
}
