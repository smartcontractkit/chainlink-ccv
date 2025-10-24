package ccv

import (
	"fmt"
	"os"
	"strings"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/tracking"
)

func initDxTracker() tracking.Tracker {
	var trackerErr error
	var dxTracker tracking.Tracker
	dxTracker, trackerErr = tracking.NewDxTracker("API_TOKEN_CCIP", "ccip")
	if trackerErr != nil {
		fmt.Fprintf(os.Stderr, "failed to create getDX tracker: %s\n", trackerErr)
		dxTracker = &tracking.NoOpTracker{}
	}
	return dxTracker
}

func oneLineErrorMessage(errOrPanic any) string {
	if err, ok := errOrPanic.(error); ok {
		return strings.SplitN(err.Error(), "\n", 1)[0]
	}

	return strings.SplitN(fmt.Sprintf("%v", errOrPanic), "\n", 1)[0]
}

func sendStartupMetrics(dxTracker tracking.Tracker, err error, startupDuration float64) {
	metaData := map[string]any{}
	if err != nil {
		metaData["result"] = "failure"
		metaData["error"] = oneLineErrorMessage(err)
	} else {
		metaData["result"] = "success"
	}
	metaData["version"] = "1.7"
	metaData["config_paths"] = os.Getenv(EnvVarTestConfigs)

	resultErr := dxTracker.Track("ccip.startup.result", metaData)
	if resultErr != nil {
		fmt.Fprintf(os.Stderr, "failed to track environment startup result: %s\n", resultErr)
	}

	// send start up duration only if there was no error during startup
	if err == nil {
		metaData["duration_seconds"] = startupDuration
		timeErr := dxTracker.Track("ccip.startup.time", metaData)
		if timeErr != nil {
			fmt.Fprintf(os.Stderr, "failed to track environment startup time: %s\n", timeErr)
		}
	}
}
