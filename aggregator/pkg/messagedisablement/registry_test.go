package messagedisablement_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/messagedisablement"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type fakeStore struct {
	rules []messagedisablement.Rule
	err   error
}

func (f *fakeStore) Create(context.Context, messagedisablement.RuleType, json.RawMessage) (messagedisablement.Rule, error) {
	return messagedisablement.Rule{}, f.err
}

func (f *fakeStore) List(context.Context, *messagedisablement.RuleType) ([]messagedisablement.Rule, error) {
	return f.rules, f.err
}

func (f *fakeStore) Get(context.Context, string) (*messagedisablement.Rule, error) {
	return nil, f.err
}

func (f *fakeStore) Delete(context.Context, string) error {
	return f.err
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

func newRegistry(t *testing.T, rules []messagedisablement.Rule) *messagedisablement.Registry {
	t.Helper()
	registry := messagedisablement.NewRegistry(&fakeStore{rules: rules}, logger.Sugared(logger.Test(t)))
	require.NoError(t, registry.Refresh(context.Background()))
	return registry
}

func makeRule(t *testing.T, ruleType messagedisablement.RuleType, data json.RawMessage) messagedisablement.Rule {
	t.Helper()
	normalized, err := messagedisablement.NormalizeRuleData(ruleType, data)
	require.NoError(t, err)
	return messagedisablement.Rule{
		ID:   messagedisablement.NewRuleID(),
		Type: ruleType,
		Data: normalized,
	}
}

func TestRegistry_ChainRule_DisablesAnythingTouchingSelector(t *testing.T) {
	t.Parallel()

	data, err := messagedisablement.NewChainRuleData(10)
	require.NoError(t, err)
	registry := newRegistry(t, []messagedisablement.Rule{makeRule(t, messagedisablement.RuleTypeChain, data)})

	assert.True(t, registry.IsDisabled(report{source: 10, dest: 20}))
	assert.True(t, registry.IsDisabled(report{source: 20, dest: 10}))
	assert.False(t, registry.IsDisabled(report{source: 20, dest: 30}))
}

func TestRegistry_LaneRule_DisablesUnorderedLane(t *testing.T) {
	t.Parallel()

	data, err := messagedisablement.NewLaneRuleData(20, 10)
	require.NoError(t, err)
	registry := newRegistry(t, []messagedisablement.Rule{makeRule(t, messagedisablement.RuleTypeLane, data)})

	assert.True(t, registry.IsDisabled(report{source: 10, dest: 20}))
	assert.True(t, registry.IsDisabled(report{source: 20, dest: 10}))
	assert.False(t, registry.IsDisabled(report{source: 10, dest: 30}))
}

func TestRegistry_TokenRule_DisablesSourceOrDestinationTokenTouch(t *testing.T) {
	t.Parallel()

	sourceData, err := messagedisablement.NewTokenRuleData(10, "0xAA")
	require.NoError(t, err)
	destData, err := messagedisablement.NewTokenRuleData(20, "aa")
	require.NoError(t, err)
	registry := newRegistry(t, []messagedisablement.Rule{
		makeRule(t, messagedisablement.RuleTypeToken, sourceData),
		makeRule(t, messagedisablement.RuleTypeToken, destData),
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
}

func TestRegistry_TokenRule_DoesNotDisableNonTokenMessage(t *testing.T) {
	t.Parallel()

	data, err := messagedisablement.NewTokenRuleData(10, "0xAA")
	require.NoError(t, err)
	registry := newRegistry(t, []messagedisablement.Rule{makeRule(t, messagedisablement.RuleTypeToken, data)})

	assert.False(t, registry.IsDisabled(report{source: 10, dest: 20}))
}

func TestRegistry_RefreshInvalidDataReturnsError(t *testing.T) {
	t.Parallel()

	registry := messagedisablement.NewRegistry(&fakeStore{rules: []messagedisablement.Rule{
		{ID: messagedisablement.NewRuleID(), Type: messagedisablement.RuleTypeLane, Data: json.RawMessage(`{"selector_a":10,"selector_b":10}`)},
	}}, logger.Sugared(logger.Test(t)))

	require.Error(t, registry.Refresh(context.Background()))
}

func TestRegistry_RefreshStoreErrorReturnsError(t *testing.T) {
	t.Parallel()

	registry := messagedisablement.NewRegistry(&fakeStore{err: errors.New("db down")}, logger.Sugared(logger.Test(t)))

	require.Error(t, registry.Refresh(context.Background()))
}

func TestRegistry_RefreshRecordsMetrics(t *testing.T) {
	t.Parallel()

	data, err := messagedisablement.NewChainRuleData(10)
	require.NoError(t, err)
	rule := makeRule(t, messagedisablement.RuleTypeChain, data)
	store := &fakeStore{rules: []messagedisablement.Rule{rule}}
	metrics := &fakeMetrics{}
	registry := messagedisablement.NewRegistry(store, logger.Sugared(logger.Test(t)), messagedisablement.WithMetrics(metrics))

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
	assert.Equal(t, "Chain", labels["rule_type"])
	assert.Equal(t, "10", labels["chain_selector"])

	store.rules = nil
	require.NoError(t, registry.Refresh(context.Background()))

	activeEvents = metrics.eventsByName("active_rule")
	require.Len(t, activeEvents, 2)
	assert.Equal(t, int64(0), activeEvents[1].value)
	inactiveLabels := labelsToMap(activeEvents[1].labels)
	assert.Equal(t, "Chain", inactiveLabels["rule_type"])
	assert.Equal(t, "10", inactiveLabels["chain_selector"])
	assert.NotContains(t, inactiveLabels, "rule_id")
	assert.NotContains(t, inactiveLabels, "rule_data")
}

func TestRegistry_RefreshFailureRecordsMetricAndKeepsPreviousRules(t *testing.T) {
	t.Parallel()

	data, err := messagedisablement.NewChainRuleData(10)
	require.NoError(t, err)
	store := &fakeStore{rules: []messagedisablement.Rule{makeRule(t, messagedisablement.RuleTypeChain, data)}}
	metrics := &fakeMetrics{}
	registry := messagedisablement.NewRegistry(store, logger.Sugared(logger.Test(t)), messagedisablement.WithMetrics(metrics))
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

	checker := messagedisablement.NoopChecker{}

	assert.False(t, checker.IsDisabled(report{source: 1, dest: 2}))
	assert.False(t, checker.IsDisabled(nil))
}

func TestRegistry_StartPeriodicRefresh_CallsRefreshRepeatedly(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	registry := messagedisablement.NewRegistry(store, logger.Sugared(logger.Test(t)))
	ctx := t.Context()

	registry.StartPeriodicRefresh(ctx, 10*time.Millisecond)

	require.Eventually(t, func() bool {
		return !registry.IsDisabled(report{source: 1, dest: 2})
	}, 100*time.Millisecond, 5*time.Millisecond)
}
