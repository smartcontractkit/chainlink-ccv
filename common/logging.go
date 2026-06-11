package common

import "github.com/smartcontractkit/chainlink-common/pkg/logger"

// WithService returns lggr with the "service" field set to name.
func WithService(lggr logger.Logger, name string) logger.Logger {
	// do not use the reserved "service" key.
	return logger.With(lggr, "ccip_service", name)
}
