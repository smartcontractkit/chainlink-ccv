package common

import "github.com/smartcontractkit/chainlink-common/pkg/logger"

// WithService returns lggr with the "service" field set to name.
func WithService(lggr logger.Logger, name string) logger.Logger {
	return logger.With(lggr, "service", name)
}
