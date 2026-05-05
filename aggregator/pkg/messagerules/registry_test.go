package messagerules

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	shared "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type fakeStore struct {
	mu         sync.Mutex
	rules      []shared.Rule
	err        error
	listCalls  int
	listCallCh chan struct{}
}

func (f *fakeStore) Create(context.Context, shared.RuleData) (shared.Rule, error) {
	return shared.Rule{}, f.err
}

func (f *fakeStore) List(context.Context, *shared.RuleType) ([]shared.Rule, error) {
	f.mu.Lock()
	f.listCalls++
	rules := append([]shared.Rule(nil), f.rules...)
	err := f.err
	listCallCh := f.listCallCh
	f.mu.Unlock()

	if listCallCh != nil {
		select {
		case listCallCh <- struct{}{}:
		default:
		}
	}
	return rules, err
}

func (f *fakeStore) Get(context.Context, string) (*shared.Rule, error) {
	return nil, f.err
}

func (f *fakeStore) Delete(context.Context, string) error {
	return f.err
}

func (f *fakeStore) listCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listCalls
}

type metricEvent struct {
	name   string
	value  int64
	labels []string
}

type fakeMetrics struct {
	mu     sync.Mutex
	events []metricEvent
}

func (f *fakeMetrics) SetMessageDisablementRuleActive(_ context.Context, active int64, keyValues ...string) {
	f.record("active_rule", active, keyValues...)
}

func (f *fakeMetrics) SetMessageDisablementRulesRefreshFailure(_ context.Context, failed int64) {
	f.record("refresh_failure", failed)
}

func (f *fakeMetrics) record(name string, value int64, keyValues ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	labels := append([]string(nil), keyValues...)
	f.events = append(f.events, metricEvent{name: name, value: value, labels: labels})
}

func (f *fakeMetrics) eventsByName(name string) []metricEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	var events []metricEvent
	for _, event := range f.events {
		if event.name == name {
			events = append(events, event)
		}
	}
	return events
}

func labelsToMap(labels []string) map[string]string {
	out := make(map[string]string, len(labels)/2)
	for i := 0; i+1 < len(labels); i += 2 {
		out[labels[i]] = labels[i+1]
	}
	return out
}

func assertMetricEvent(t *testing.T, events []metricEvent, value int64, ruleType, chainSelector string) {
	t.Helper()
	for _, event := range events {
		labels := labelsToMap(event.labels)
		if event.value == value && labels["rule_type"] == ruleType && labels["chain_selector"] == chainSelector {
			return
		}
	}
	require.Failf(t, "metric event not found", "value=%d rule_type=%s chain_selector=%s events=%v", value, ruleType, chainSelector, events)
}

type report struct {
	source uint64
	dest   uint64
	token  *protocol.TokenTransfer
}

func (r report) GetSourceChainSelector() uint64 { return r.source }
func (r report) GetDestinationSelector() uint64 { return r.dest }
func (r report) GetTokenTransfer() *protocol.TokenTransfer {
	return r.token
}

func newRegistry(t *testing.T, rules []shared.Rule) *Registry {
	t.Helper()
	registry := NewRegistry(&fakeStore{rules: rules}, logger.Sugared(logger.Test(t)))
	require.NoError(t, registry.Refresh(context.Background()))
	return registry
}

func makeRule(t *testing.T, data shared.RuleData) shared.Rule {
	t.Helper()
	rule, err := shared.NewRule(shared.NewRuleID(), data, time.Time{}, time.Time{})
	require.NoError(t, err)
	return rule
}

func TestRegistry_ChainRule_DisablesAnythingTouchingSelector(t *testing.T) {
	t.Parallel()

	data, err := shared.NewChainRuleData(10)
	require.NoError(t, err)
	registry := newRegistry(t, []shared.Rule{makeRule(t, data)})

	assert.True(t, registry.IsDisabled(report{source: 10, dest: 20}))
	assert.True(t, registry.IsDisabled(report{source: 20, dest: 10}))
	assert.False(t, registry.IsDisabled(report{source: 20, dest: 30}))
}

func TestRegistry_LaneRule_DisablesUnorderedLane(t *testing.T) {
	t.Parallel()

	data, err := shared.NewLaneRuleData(20, 10)
	require.NoError(t, err)
	registry := newRegistry(t, []shared.Rule{makeRule(t, data)})

	assert.True(t, registry.IsDisabled(report{source: 10, dest: 20}))
	assert.True(t, registry.IsDisabled(report{source: 20, dest: 10}))
	assert.False(t, registry.IsDisabled(report{source: 10, dest: 30}))
}

func TestRegistry_TokenRule_DisablesSourceOrDestinationTokenTouch(t *testing.T) {
	t.Parallel()

	sourceData, err := shared.NewTokenRuleData(10, "0xAA")
	require.NoError(t, err)
	destData, err := shared.NewTokenRuleData(20, "aa")
	require.NoError(t, err)
	registry := newRegistry(t, []shared.Rule{
		makeRule(t, sourceData),
		makeRule(t, destData),
	})

	assert.True(t, registry.IsDisabled(report{
		source: 10,
		dest:   20,
		token:  &protocol.TokenTransfer{SourceTokenAddress: protocol.ByteSlice{0xaa}, DestTokenAddress: protocol.ByteSlice{0xbb}},
	}))
	assert.True(t, registry.IsDisabled(report{
		source: 30,
		dest:   20,
		token:  &protocol.TokenTransfer{SourceTokenAddress: protocol.ByteSlice{0xbb}, DestTokenAddress: protocol.ByteSlice{0xaa}},
	}))
	assert.False(t, registry.IsDisabled(report{
		source: 10,
		dest:   20,
		token:  &protocol.TokenTransfer{SourceTokenAddress: protocol.ByteSlice{0xbb}, DestTokenAddress: protocol.ByteSlice{0xcc}},
	}))
	assert.False(t, registry.IsDisabled(report{
		source: 30,
		dest:   10,
		token:  &protocol.TokenTransfer{SourceTokenAddress: protocol.ByteSlice{0xaa}, DestTokenAddress: protocol.ByteSlice{0xbb}},
	}))
	assert.False(t, registry.IsDisabled(report{
		source: 20,
		dest:   30,
		token:  &protocol.TokenTransfer{SourceTokenAddress: protocol.ByteSlice{0xbb}, DestTokenAddress: protocol.ByteSlice{0xaa}},
	}))
}

func TestRegistry_TokenRule_DoesNotDisableNonTokenMessage(t *testing.T) {
	t.Parallel()

	data, err := shared.NewTokenRuleData(10, "0xAA")
	require.NoError(t, err)
	registry := newRegistry(t, []shared.Rule{makeRule(t, data)})

	assert.False(t, registry.IsDisabled(report{source: 10, dest: 20}))
}

func TestRegistry_RefreshInvalidRuleReturnsError(t *testing.T) {
	t.Parallel()

	registry := NewRegistry(&fakeStore{rules: []shared.Rule{{}}}, logger.Sugared(logger.Test(t)))

	require.Error(t, registry.Refresh(context.Background()))
}

func TestRegistry_RefreshStoreErrorReturnsError(t *testing.T) {
	t.Parallel()

	registry := NewRegistry(&fakeStore{err: errors.New("db down")}, logger.Sugared(logger.Test(t)))

	require.Error(t, registry.Refresh(context.Background()))
}

func TestRegistry_RefreshRecordsMetrics(t *testing.T) {
	t.Parallel()

	data, err := shared.NewChainRuleData(10)
	require.NoError(t, err)
	rule := makeRule(t, data)
	store := &fakeStore{rules: []shared.Rule{rule}}
	metrics := &fakeMetrics{}
	registry := NewRegistry(store, logger.Sugared(logger.Test(t)), WithMetrics(metrics))

	require.NoError(t, registry.Refresh(context.Background()))

	refreshEvents := metrics.eventsByName("refresh_failure")
	require.Len(t, refreshEvents, 1)
	assert.Equal(t, int64(0), refreshEvents[0].value)

	activeEvents := metrics.eventsByName("active_rule")
	require.Len(t, activeEvents, 1)
	assert.Equal(t, int64(1), activeEvents[0].value)
	labels := labelsToMap(activeEvents[0].labels)
	assert.NotContains(t, labels, "rule_id")
	assert.NotContains(t, labels, "rule_data")
	assert.Equal(t, "chain", labels["rule_type"])
	assert.Equal(t, "10", labels["chain_selector"])

	store.rules = nil
	require.NoError(t, registry.Refresh(context.Background()))

	activeEvents = metrics.eventsByName("active_rule")
	require.Len(t, activeEvents, 2)
	assert.Equal(t, int64(0), activeEvents[1].value)
	inactiveLabels := labelsToMap(activeEvents[1].labels)
	assert.Equal(t, "chain", inactiveLabels["rule_type"])
	assert.Equal(t, "10", inactiveLabels["chain_selector"])
	assert.NotContains(t, inactiveLabels, "rule_id")
	assert.NotContains(t, inactiveLabels, "rule_data")
}

func TestRegistry_RefreshRecordsMetricsForSameTypeRules(t *testing.T) {
	t.Parallel()

	chain10Data, err := shared.NewChainRuleData(10)
	require.NoError(t, err)
	chain20Data, err := shared.NewChainRuleData(20)
	require.NoError(t, err)
	chain10Rule := makeRule(t, chain10Data)
	chain20Rule := makeRule(t, chain20Data)
	store := &fakeStore{rules: []shared.Rule{chain10Rule, chain20Rule}}
	metrics := &fakeMetrics{}
	registry := NewRegistry(store, logger.Sugared(logger.Test(t)), WithMetrics(metrics))

	require.NoError(t, registry.Refresh(context.Background()))

	activeEvents := metrics.eventsByName("active_rule")
	require.Len(t, activeEvents, 2)
	assertMetricEvent(t, activeEvents, 1, "chain", "10")
	assertMetricEvent(t, activeEvents, 1, "chain", "20")

	store.rules = []shared.Rule{chain20Rule}
	require.NoError(t, registry.Refresh(context.Background()))

	activeEvents = metrics.eventsByName("active_rule")
	require.Len(t, activeEvents, 4)
	assertMetricEvent(t, activeEvents[2:], 0, "chain", "10")
	assertMetricEvent(t, activeEvents[2:], 1, "chain", "20")
}

func TestRegistry_RefreshFailureRecordsMetricAndKeepsPreviousRules(t *testing.T) {
	t.Parallel()

	data, err := shared.NewChainRuleData(10)
	require.NoError(t, err)
	store := &fakeStore{rules: []shared.Rule{makeRule(t, data)}}
	metrics := &fakeMetrics{}
	registry := NewRegistry(store, logger.Sugared(logger.Test(t)), WithMetrics(metrics))
	require.NoError(t, registry.Refresh(context.Background()))
	require.True(t, registry.IsDisabled(report{source: 10, dest: 20}))

	store.err = errors.New("db down")
	require.Error(t, registry.Refresh(context.Background()))

	refreshEvents := metrics.eventsByName("refresh_failure")
	require.Len(t, refreshEvents, 2)
	assert.Equal(t, int64(0), refreshEvents[0].value)
	assert.Equal(t, int64(1), refreshEvents[1].value)
	assert.True(t, registry.IsDisabled(report{source: 10, dest: 20}))
}

func TestNoopChecker_NeverDisables(t *testing.T) {
	t.Parallel()

	checker := shared.NoopChecker{}

	assert.False(t, checker.IsDisabled(report{source: 1, dest: 2}))
	assert.False(t, checker.IsDisabled(nil))
}

func TestRegistry_StartPeriodicRefresh_CallsRefreshRepeatedly(t *testing.T) {
	t.Parallel()

	store := &fakeStore{listCallCh: make(chan struct{}, 4)}
	registry := NewRegistry(store, logger.Sugared(logger.Nop()))
	ctx := t.Context()

	registry.StartPeriodicRefresh(ctx, 10*time.Millisecond)

	require.Eventually(t, func() bool {
		return store.listCallCount() >= 2
	}, 100*time.Millisecond, 5*time.Millisecond)
}
