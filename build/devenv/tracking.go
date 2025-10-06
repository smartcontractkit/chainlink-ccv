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
