package verifier

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type verificationGuardInner struct {
	calls int
	tasks []VerificationTask
}

func (v *verificationGuardInner) VerifyMessages(_ context.Context, tasks []VerificationTask) []VerificationResult {
	v.calls++
	v.tasks = append(v.tasks, tasks...)
	results := make([]VerificationResult, 0, len(tasks))
	for _, task := range tasks {
		messageID, err := protocol.NewBytes32FromString(task.MessageID)
		if err != nil {
			panic(err)
		}
		results = append(results, VerificationResult{Result: &protocol.VerifierNodeResult{
			MessageID: messageID,
			Message:   task.Message,
		}})
	}
	return results
}

type verificationGuardRules struct {
	check func(protocol.Message) (bool, error)
	calls []protocol.Message
}

func (r *verificationGuardRules) IsMessageDisabled(_ context.Context, message protocol.Message) (bool, error) {
	r.calls = append(r.calls, message)
	if r.check != nil {
		return r.check(message)
	}
	return false, nil
}

type verificationGuardFixture struct {
	guard    *VerificationGuard
	inner    *verificationGuardInner
	statuses *mocks.MockChainStatusManager
	curses   *mocks.MockCurseChecker
	rules    *verificationGuardRules
}

func newVerificationGuardFixture(t *testing.T) *verificationGuardFixture {
	t.Helper()
	inner := &verificationGuardInner{}
	statuses := mocks.NewMockChainStatusManager(t)
	curses := mocks.NewMockCurseChecker(t)
	rules := &verificationGuardRules{}
	return &verificationGuardFixture{
		guard:    NewVerificationGuard(inner, statuses, curses, rules),
		inner:    inner,
		statuses: statuses,
		curses:   curses,
		rules:    rules,
	}
}

func verificationGuardTask(id byte, source, dest protocol.ChainSelector) VerificationTask {
	return VerificationTask{
		MessageID: protocol.Bytes32{31: id}.String(),
		Message: protocol.Message{
			SourceChainSelector: source,
			DestChainSelector:   dest,
			SequenceNumber:      protocol.SequenceNumber(id),
		},
	}
}

func verificationGuardResultForTask(
	t *testing.T,
	results []VerificationResult,
	task VerificationTask,
) VerificationResult {
	t.Helper()
	for _, result := range results {
		if result.Error != nil && result.Error.Task.MessageID == task.MessageID {
			return result
		}
		if result.Result != nil && result.Result.MessageID.String() == task.MessageID {
			return result
		}
	}
	t.Fatalf("no result for task %s", task.MessageID)
	return VerificationResult{}
}

func TestVerificationGuardAllowedForwarding(t *testing.T) {
	f := newVerificationGuardFixture(t)
	const dest = protocol.ChainSelector(99)
	tasks := []VerificationTask{
		verificationGuardTask(1, 1, dest),
		verificationGuardTask(2, 2, dest),
		verificationGuardTask(3, 1, dest),
	}

	f.statuses.EXPECT().ReadChainStatuses(mock.Anything, []protocol.ChainSelector{1, 2}).
		RunAndReturn(func(ctx context.Context, _ []protocol.ChainSelector) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			remaining := time.Until(deadline)
			require.Positive(t, remaining)
			require.LessOrEqual(t, remaining, DefaultJobQueueOperationTimeout)
			return map[protocol.ChainSelector]*protocol.ChainStatusInfo{1: nil}, nil
		}).Once()
	f.curses.EXPECT().IsRemoteChainCursed(mock.Anything, protocol.ChainSelector(1), dest).Return(false, nil).Twice()
	f.curses.EXPECT().IsRemoteChainCursed(mock.Anything, protocol.ChainSelector(2), dest).Return(false, nil).Once()

	results := f.guard.VerifyMessages(t.Context(), tasks)

	require.Len(t, results, len(tasks))
	require.Equal(t, 1, f.inner.calls)
	require.Equal(t, tasks, f.inner.tasks)
	require.Len(t, f.rules.calls, len(tasks))
	for _, task := range tasks {
		result := verificationGuardResultForTask(t, results, task)
		require.Nil(t, result.Error)
		require.NotNil(t, result.Result)
	}
}

func TestVerificationGuardMixedAllowedAndBlockedBatch(t *testing.T) {
	f := newVerificationGuardFixture(t)
	const dest = protocol.ChainSelector(99)
	allowed := verificationGuardTask(1, 1, dest)
	cursed := verificationGuardTask(2, 2, dest)
	disabledSource := verificationGuardTask(3, 3, dest)
	disabledMessage := verificationGuardTask(4, 4, dest)
	tasks := []VerificationTask{allowed, cursed, disabledSource, disabledMessage}

	f.statuses.EXPECT().ReadChainStatuses(mock.Anything, []protocol.ChainSelector{1, 2, 3, 4}).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{
			3: {ChainSelector: 3, Disabled: true},
		}, nil).Once()
	f.curses.EXPECT().IsRemoteChainCursed(mock.Anything, protocol.ChainSelector(1), dest).Return(false, nil).Once()
	f.curses.EXPECT().IsRemoteChainCursed(mock.Anything, protocol.ChainSelector(2), dest).Return(true, nil).Once()
	f.curses.EXPECT().IsRemoteChainCursed(mock.Anything, protocol.ChainSelector(4), dest).Return(false, nil).Once()
	f.rules.check = func(message protocol.Message) (bool, error) {
		return message.SourceChainSelector == disabledMessage.Message.SourceChainSelector, nil
	}

	results := f.guard.VerifyMessages(t.Context(), tasks)

	require.Len(t, results, len(tasks))
	require.Equal(t, 1, f.inner.calls)
	require.Equal(t, []VerificationTask{allowed}, f.inner.tasks)
	require.Nil(t, verificationGuardResultForTask(t, results, allowed).Error)
	for _, task := range []VerificationTask{cursed, disabledSource, disabledMessage} {
		result := verificationGuardResultForTask(t, results, task)
		require.NotNil(t, result.Error)
		require.False(t, result.Error.Retryable)
	}
	require.Len(t, f.rules.calls, 2)
}

func TestVerificationGuardPermanentRejections(t *testing.T) {
	tests := []struct {
		name           string
		statusDisabled bool
		cursed         bool
		ruleDisabled   bool
		wantError      string
	}{
		{name: "disabled source", statusDisabled: true, wantError: "source chain 1 is disabled"},
		{name: "cursed lane", cursed: true, wantError: "is cursed"},
		{name: "message rule disabled", ruleDisabled: true, wantError: "disabled by message rules"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newVerificationGuardFixture(t)
			task := verificationGuardTask(1, 1, 2)
			f.statuses.EXPECT().ReadChainStatuses(mock.Anything, []protocol.ChainSelector{1}).
				Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{
					1: {ChainSelector: 1, Disabled: tc.statusDisabled},
				}, nil).Once()
			if !tc.statusDisabled {
				f.curses.EXPECT().IsRemoteChainCursed(mock.Anything, protocol.ChainSelector(1), protocol.ChainSelector(2)).
					Return(tc.cursed, nil).Once()
			}
			f.rules.check = func(protocol.Message) (bool, error) {
				return tc.ruleDisabled, nil
			}

			results := f.guard.VerifyMessages(t.Context(), []VerificationTask{task})

			require.Len(t, results, 1)
			result := verificationGuardResultForTask(t, results, task)
			require.NotNil(t, result.Error)
			require.False(t, result.Error.Retryable)
			require.ErrorContains(t, result.Error.Error, tc.wantError)
			require.Zero(t, f.inner.calls)
			require.Empty(t, f.inner.tasks)
			if tc.statusDisabled || tc.cursed {
				require.Empty(t, f.rules.calls)
			} else {
				require.Len(t, f.rules.calls, 1)
			}
		})
	}
}

func TestVerificationGuardUnknownStateRetries(t *testing.T) {
	tests := []struct {
		name     string
		curseErr error
		rulesErr error
	}{
		{name: "curse state unknown", curseErr: common.ErrCurseStateUnknown},
		{name: "message rules state unknown", rulesErr: common.ErrMessageRulesStateUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newVerificationGuardFixture(t)
			task := verificationGuardTask(1, 1, 2)
			f.statuses.EXPECT().ReadChainStatuses(mock.Anything, []protocol.ChainSelector{1}).
				Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Once()
			f.curses.EXPECT().IsRemoteChainCursed(mock.Anything, protocol.ChainSelector(1), protocol.ChainSelector(2)).
				Return(tc.curseErr != nil, tc.curseErr).Once()
			f.rules.check = func(protocol.Message) (bool, error) {
				return tc.rulesErr != nil, tc.rulesErr
			}

			results := f.guard.VerifyMessages(t.Context(), []VerificationTask{task})

			require.Len(t, results, 1)
			result := verificationGuardResultForTask(t, results, task)
			require.NotNil(t, result.Error)
			require.True(t, result.Error.Retryable)
			if tc.curseErr != nil {
				require.ErrorIs(t, result.Error.Error, tc.curseErr)
				require.Empty(t, f.rules.calls)
			} else {
				require.ErrorIs(t, result.Error.Error, tc.rulesErr)
				require.Len(t, f.rules.calls, 1)
			}
			require.Zero(t, f.inner.calls)
		})
	}
}

func TestVerificationGuardStatusReadFailureRetries(t *testing.T) {
	f := newVerificationGuardFixture(t)
	readErr := errors.New("database unavailable")
	tasks := []VerificationTask{
		verificationGuardTask(1, 1, 99),
		verificationGuardTask(2, 2, 99),
	}
	f.statuses.EXPECT().ReadChainStatuses(mock.Anything, []protocol.ChainSelector{1, 2}).
		Return(nil, readErr).Once()

	results := f.guard.VerifyMessages(t.Context(), tasks)

	require.Len(t, results, len(tasks))
	for _, task := range tasks {
		result := verificationGuardResultForTask(t, results, task)
		require.NotNil(t, result.Error)
		require.True(t, result.Error.Retryable)
		require.ErrorIs(t, result.Error.Error, readErr)
	}
	require.Zero(t, f.inner.calls)
	require.Empty(t, f.rules.calls)
}
