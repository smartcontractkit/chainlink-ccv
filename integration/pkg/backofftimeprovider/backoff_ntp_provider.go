package backofftimeprovider

import (
	"sync"
	"time"

	"github.com/beevik/ntp"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const maxFailedAttempts = 20

var (
	_ common.TimeProvider = &BackoffNTPProvider{}
	// ntpTimeFunc is a variable that can be overridden in tests.
	ntpTimeFunc = ntp.Time
)

type BackoffNTPProvider struct {
	lggr                 logger.Logger
	backoffDuration      time.Duration
	failedAttempts       int
	lastFailureTime      time.Time
	lastSuccessLocalTime time.Time
	lastSuccessNTPTime   time.Time
	mu                   sync.RWMutex
	ntpServer            string
}

func NewBackoffNTPProvider(lggr logger.Logger, backoffDuration time.Duration, ntpServer string) *BackoffNTPProvider {
	return &BackoffNTPProvider{
		lggr:            lggr,
		backoffDuration: backoffDuration,
		failedAttempts:  0,
		ntpServer:       ntpServer,
	}
}

func (b *BackoffNTPProvider) GetTime() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if we're still in backoff period
	if b.failedAttempts > 0 {
		backoffDuration := b.calculateBackoffDuration()
		timeSinceLastFailure := time.Now().UTC().Sub(b.lastFailureTime)

		if timeSinceLastFailure < backoffDuration {
			// Still in backoff, return local time without trying NTP
			b.lggr.Debugw("In backoff period, returning fallback time",
				"failedAttempts", b.failedAttempts,
				"backoffRemaining", backoffDuration-timeSinceLastFailure)
			return b.getFallbackTime()
		}
		// Backoff period expired, will attempt NTP below
		b.lggr.Debugw("Backoff period expired, attempting NTP again",
			"failedAttempts", b.failedAttempts)
	}

	// Attempt to get NTP time
	ntpTime, err := ntpTimeFunc(b.ntpServer)
	if err != nil {
		// NTP failed, increment failure counter and record time
		b.failedAttempts++
		b.lastFailureTime = time.Now().UTC()
		backoffDuration := b.calculateBackoffDuration()

		b.lggr.Warnw("Unable to get NTP time, backing off and returning fallback time",
			"failedAttempts", b.failedAttempts,
			"nextRetryIn", backoffDuration)

		return b.getFallbackTime()
	}

	// Success! Reset failed attempts counter
	b.failedAttempts = 0
	b.lastFailureTime = time.Time{} // zero time
	b.lastSuccessLocalTime = time.Now().UTC()
	b.lastSuccessNTPTime = ntpTime
	b.lggr.Debugw("Successfully retrieved NTP time", "ntpTime", ntpTime)

	return ntpTime
}

func (b *BackoffNTPProvider) getFallbackTime() time.Time {
	now := time.Now().UTC()
	if b.lastSuccessLocalTime.IsZero() {
		return now
	}
	// localtime_now - localtime_then + ntptime_then
	return b.lastSuccessNTPTime.Add(now.Sub(b.lastSuccessLocalTime))
}

// calculateBackoffDuration computes exponential backoff duration based on failed attempts.
// It uses a triangular number sequence to increase the backoff duration more aggressively with each failure.
// A max backoff duration is reached at 20 attempts to avoid unbounded growth.
func (b *BackoffNTPProvider) calculateBackoffDuration() time.Duration {
	attempts := min(b.failedAttempts, maxFailedAttempts)

	// This gives: 1x, 3x, 6x, 10x, etc.
	// Will cap at maxBackoffDuration.
	multiplier := (attempts * (attempts + 1)) / 2
	duration := b.backoffDuration * time.Duration(multiplier)
	return duration
}
