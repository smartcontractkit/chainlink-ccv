package readers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
)

func TestNewResilienceConfig(t *testing.T) {
	def := DefaultResilienceConfig()

	t.Run("zero config returns all defaults", func(t *testing.T) {
		rc := NewResilienceConfig(config.ResilienceConfig{})
		assert.Equal(t, def, rc)
	})

	t.Run("partial overrides keep defaults for unset fields", func(t *testing.T) {
		rc := NewResilienceConfig(config.ResilienceConfig{
			MaxRequestsPerSecond: 100,
			RequestTimeout:       common.Duration(30 * time.Second),
		})
		assert.Equal(t, uint(100), rc.MaxRequestsPerSecond)
		assert.Equal(t, 30*time.Second, rc.RequestTimeout)
		assert.Equal(t, def.MaxConcurrentRequests, rc.MaxConcurrentRequests)
		assert.Equal(t, def.FailureThreshold, rc.FailureThreshold)
		assert.Equal(t, def.SuccessThreshold, rc.SuccessThreshold)
		assert.Equal(t, def.CircuitBreakerDelay, rc.CircuitBreakerDelay)
		assert.Equal(t, def.CircuitBreakerTimeout, rc.CircuitBreakerTimeout)
	})

	t.Run("full overrides", func(t *testing.T) {
		in := config.ResilienceConfig{
			MaxRequestsPerSecond:  50,
			MaxConcurrentRequests: 20,
			FailureThreshold:      10,
			SuccessThreshold:      7,
			CircuitBreakerDelay:   common.Duration(5 * time.Second),
			CircuitBreakerTimeout: common.Duration(2 * time.Second),
			RequestTimeout:        common.Duration(15 * time.Second),
		}
		rc := NewResilienceConfig(in)
		assert.Equal(t, uint(50), rc.MaxRequestsPerSecond)
		assert.Equal(t, uint(20), rc.MaxConcurrentRequests)
		assert.Equal(t, uint32(10), rc.FailureThreshold)
		assert.Equal(t, uint32(7), rc.SuccessThreshold)
		assert.Equal(t, 5*time.Second, rc.CircuitBreakerDelay)
		assert.Equal(t, 2*time.Second, rc.CircuitBreakerTimeout)
		assert.Equal(t, 15*time.Second, rc.RequestTimeout)
	})
}
