package a

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

const shortTimeout = 2 * time.Second

func condition() bool { return true }

func testEventually(t *testing.T) {
	require.Eventually(t, condition, time.Second, time.Millisecond)                                           // want `Eventually timeout 1s is shorter than the 10s minimum`
	assert.Eventually(t, condition, 5*time.Second, time.Millisecond)                                          // want `Eventually timeout 5s is shorter than the 10s minimum`
	require.Eventuallyf(t, condition, shortTimeout, time.Millisecond, "message")                              // want `Eventuallyf timeout 2s is shorter than the 10s minimum`
	assert.EventuallyWithT(t, func(*assert.CollectT) {}, 500*time.Millisecond, time.Millisecond)              // want `EventuallyWithT timeout 500ms is shorter than the 10s minimum`
	require.EventuallyWithTf(t, func(*assert.CollectT) {}, 100*time.Millisecond, time.Millisecond, "message") // want `EventuallyWithTf timeout 100ms is shorter than the 10s minimum`
	assert.New(t).Eventually(condition, 3*time.Second, time.Millisecond)                                      // want `Eventually timeout 3s is shorter than the 10s minimum`

	require.Eventually(t, condition, 10*time.Second, time.Millisecond)
	assert.Eventually(t, condition, time.Minute, time.Millisecond)
	require.Eventually(t, condition, tests.WaitTimeout(t), time.Millisecond)
	require.New(t).Eventually(condition, 30*time.Second, time.Millisecond)
}
