package executor

import (
	"github.com/grafana/pyroscope-go"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// StartPyroscope starts the Pyroscope profiler for the executor service.
func StartPyroscope(lggr logger.Logger, pyroscopeAddress, serviceName string) (*pyroscope.Profiler, error) {
	profiler, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: serviceName,
		ServerAddress:   pyroscopeAddress,
		Logger:          nil, // Disable pyroscope logging - so noisy
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileBlockDuration,
			pyroscope.ProfileMutexDuration,
		},
	})
	if err != nil {
		return nil, err
	}
	return profiler, nil
}
