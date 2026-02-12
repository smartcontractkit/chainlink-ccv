package runner

import "errors"

// ErrJobAlreadyRunning is returned by StartJob when a job is already running.
// The caller must call StopJob first before starting a new job.
var ErrJobAlreadyRunning = errors.New("job already running")
