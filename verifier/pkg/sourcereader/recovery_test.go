package sourcereader

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

type recoveryRules struct {
	disabled bool
	err      error
}

func (r *recoveryRules) IsMessageDisabled(context.Context, protocol.Message) (bool, error) {
	return r.disabled, r.err
}

type auditUnavailable struct{ sqlutil.DataSource }

func (auditUnavailable) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return nil, errors.New("audit unavailable")
}

func recoveryTestService(t *testing.T, cursed bool, rules common.MessageRulesChecker) (*Service, *mocks.MockSourceReader, sqlutil.DataSource) {
	t.Helper()
	db := testutil.NewTestDB(t)
	lggr := logger.Test(t)
	manager := chainstatus.NewPostgresChainStatusManager(chainstatus.NewPostgresChainStatusStore(db, lggr), "owner")
	batcher, err := chainstatus.NewChainStatusBatcher(lggr, manager, time.Hour, 100)
	require.NoError(t, err)
	reader := mocks.NewMockSourceReader(t)
	reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(&protocol.BlockHeader{Number: 1000}, &protocol.BlockHeader{Number: 1000}, nil).Maybe()
	curse := mocks.NewMockCurseCheckerService(t)
	curse.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(cursed, nil).Maybe()
	queue, err := jobqueue.NewPostgresJobQueue[verifier.VerificationTask](db, jobqueue.QueueConfig{Name: verifier.TaskVerifierJobsTableName, OwnerID: "owner", RetryDuration: time.Hour}, lggr)
	require.NoError(t, err)
	r, err := NewService("owner", reader, 42, batcher, lggr, verifier.SourceConfig{DisableFinalityChecker: true, MaxBlockRange: 10}, curse,
		&noopFilter{}, monitoring.NewFakeVerifierMonitoring(), queue, rules)
	require.NoError(t, err)
	require.NoError(t, r.ConfigureRecovery(recovery.NewStore(db), queue, make(chan struct{}, 1)))
	require.NoError(t, r.recovery.store.RegisterReader(t.Context(), "owner", "42", "test-node", false))
	r.lastProcessedFinalizedBlock.Store(big.NewInt(500))
	return r, reader, db
}

func TestRecoveryRereadsAdmissionWithoutChangingNormalProgress(t *testing.T) {
	for _, tc := range []struct {
		name             string
		cursed, disabled bool
		wantReason       string
	}{
		{"admitted", false, false, ""}, {"curse", true, false, "remote_chain_cursed"}, {"disablement", false, true, "message_disablement_rule"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, reader, _ := recoveryTestService(t, tc.cursed, &recoveryRules{disabled: tc.disabled})
			events := createTestMessageSentEvents(t, 1, 42, defaultDestChain, []uint64{100})
			reader.EXPECT().FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(100)).Return(events, nil).Once()
			end := uint64(100)
			o, err := r.recovery.store.Submit(t.Context(), recovery.SubmitRequest{OwnerID: "owner", SourceChain: "42", FromBlock: 100, ToBlock: &end, Mode: "replay", Actor: "operator", Note: "test"})
			require.NoError(t, err)
			head := &protocol.BlockHeader{Number: 1000, Timestamp: time.Now()}
			pending := r.tasksFromEvents(t.Context(), events, head, head)
			r.addToPendingQueueHandleReorg(pending, big.NewInt(100), big.NewInt(100))
			r.recoverRange(t.Context(), head, head, head)
			o, err = r.recovery.store.Get(t.Context(), o.ID)
			require.NoError(t, err)
			require.Equal(t, "completed", o.State)
			require.Equal(t, uint64(101), o.NextBlock)
			require.Equal(t, uint64(500), r.lastProcessedFinalizedBlock.Load().Uint64())
			require.Empty(t, r.pendingTasks)
			require.Empty(t, r.sentTasks)
			page, err := r.recovery.store.ListEvents(t.Context(), recovery.EventFilter{OwnerID: "owner", Limit: 50})
			require.NoError(t, err)
			if tc.wantReason == "" {
				require.Equal(t, int64(1), o.Admitted)
				require.Empty(t, page.Events)
			} else {
				require.Equal(t, int64(1), o.Dropped)
				require.Len(t, page.Events, 1)
				require.Equal(t, tc.wantReason, page.Events[0].Reason)
			}
		})
	}
}

func TestRecoveryUnknownAdmissionDoesNotAdvanceOrAuditDrop(t *testing.T) {
	rules := &recoveryRules{err: errors.New("unknown rules")}
	r, reader, _ := recoveryTestService(t, false, rules)
	events := createTestMessageSentEvents(t, 1, 42, defaultDestChain, []uint64{100})
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(100)).Return(events, nil).Twice()
	end := uint64(100)
	o, err := r.recovery.store.Submit(t.Context(), recovery.SubmitRequest{OwnerID: "owner", SourceChain: "42", FromBlock: 100, ToBlock: &end, Mode: "replay", Actor: "operator", Note: "test"})
	require.NoError(t, err)
	head := &protocol.BlockHeader{Number: 1000, Timestamp: time.Now()}
	r.recoverRange(t.Context(), head, nil, head)
	o, err = r.recovery.store.Get(t.Context(), o.ID)
	require.NoError(t, err)
	require.Equal(t, uint64(100), o.NextBlock)
	require.Contains(t, o.LastError, "rules_state_unknown")
	page, err := r.recovery.store.ListEvents(t.Context(), recovery.EventFilter{Limit: 50})
	require.NoError(t, err)
	require.Empty(t, page.Events)
	rules.err = nil
	r.recoverRange(t.Context(), head, nil, head)
	o, err = r.recovery.store.Get(t.Context(), o.ID)
	require.NoError(t, err)
	require.Equal(t, "completed", o.State)
}

func TestLiveFinalityRecoveryIncludesDisabledStartupReaders(t *testing.T) {
	r, reader, db := recoveryTestService(t, false, common.AllowAllMessagesChecker{})
	ctx := t.Context()
	require.NoError(t, r.chainStatusManager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{{ChainSelector: 42, FinalizedBlockHeight: big.NewInt(0), Disabled: true}}))
	_, err := r.initializeStartBlock(ctx)
	require.NoError(t, err)
	require.True(t, r.disabled.Load())
	end := uint64(100)
	request := recovery.SubmitRequest{OwnerID: "owner", SourceChain: "42", FromBlock: 100, ToBlock: &end, Mode: "replay", Actor: "operator", Note: "investigated boundary 99"}
	ordinary, err := r.recovery.store.Submit(ctx, request)
	require.NoError(t, err)
	r.recoveryControl(ctx)
	ordinary, err = r.recovery.store.Get(ctx, ordinary.ID)
	require.NoError(t, err)
	require.Equal(t, "blocked", ordinary.State)
	require.True(t, r.disabled.Load())
	request.Mode = "reset-reader"
	reset, err := r.recovery.store.Submit(ctx, request)
	require.NoError(t, err)
	r.recoveryControl(ctx)
	require.False(t, r.disabled.Load())
	require.Equal(t, reset.ID, r.recovery.rebuildingID)
	_, err = r.recovery.store.ChangeState(ctx, reset.ID, "cancel")
	require.NoError(t, err)
	active, err := recovery.NewStore(db).ActiveReset(ctx, "owner", "42")
	require.NoError(t, err)
	require.Equal(t, reset.ID, active, "restart and cancellation must not let normal polling skip this range")
	head := &protocol.BlockHeader{Number: 1000, Timestamp: time.Now()}
	r.recoverRange(ctx, head, head, head) // No RPC while canceled.
	_, err = r.recovery.store.ChangeState(ctx, reset.ID, "resume")
	require.NoError(t, err)
	events := createTestMessageSentEvents(t, 1, 42, defaultDestChain, []uint64{100})
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(100)).Return(events, nil).Once()
	r.recoverRange(ctx, head, head, head)
	reset, err = r.recovery.store.Get(ctx, reset.ID)
	require.NoError(t, err)
	require.Equal(t, "completed", reset.State)
	require.True(t, reset.ResetApplied)
	require.Empty(t, r.recovery.rebuildingID)
	statuses, err := r.chainStatusManager.ReadChainStatuses(ctx, []protocol.ChainSelector{42})
	require.NoError(t, err)
	require.False(t, statuses[42].Disabled)
	require.Equal(t, uint64(100), statuses[42].FinalizedBlockHeight.Uint64())
	// A later violation is sticky even though the previous reset remains in history.
	r.pendingTasks[events[0].MessageID.String()] = verifier.VerificationTask{Message: events[0].Message, MessageID: events[0].MessageID.String(), BlockNumber: 100}
	r.handleFinalityViolation(ctx)
	require.True(t, r.disabled.Load())
	page, err := r.recovery.store.ListEvents(ctx, recovery.EventFilter{Reason: "finality_violation", Limit: 50})
	require.NoError(t, err)
	require.Len(t, page.Events, 2, "incident and known pending message are separate records")
	require.Equal(t, page.Events[0].IncidentID, page.Events[1].IncidentID)
	_, err = r.recovery.store.ChangeState(ctx, reset.ID, "resume")
	require.Error(t, err)
}

func TestAuditFailureCannotPreventFinalityBlock(t *testing.T) {
	r, _, db := recoveryTestService(t, false, common.AllowAllMessagesChecker{})
	r.recovery.store = recovery.NewStore(auditUnavailable{db})
	r.handleFinalityViolation(t.Context())
	require.True(t, r.disabled.Load())
	require.True(t, r.finalityBlocked.Load())
	require.Equal(t, int64(1), r.recovery.failedAuditWrites.Load())
}

func TestNormalAdmissionPersistsReaderMetadata(t *testing.T) {
	r, _, _ := recoveryTestService(t, true, common.AllowAllMessagesChecker{})
	head := &protocol.BlockHeader{Number: 1000, Timestamp: time.Now()}
	events := createTestMessageSentEvents(t, 1, 42, defaultDestChain, []uint64{100})
	events[0].TxHash = protocol.ByteSlice{1, 2, 3}
	events[0].BlockHash = protocol.ByteSlice{4, 5, 6}
	tasks := r.tasksFromEvents(t.Context(), events, head, head)
	require.Len(t, tasks, 1)
	r.addToPendingQueueHandleReorg(tasks, big.NewInt(100), big.NewInt(100))
	require.True(t, r.sendReadyMessages(t.Context(), head, head, head))
	require.Empty(t, r.pendingTasks)
	page, err := r.recovery.store.ListEvents(t.Context(), recovery.EventFilter{OwnerID: "owner", Limit: 50})
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	require.Equal(t, "remote_chain_cursed", page.Events[0].Reason)
	require.Equal(t, "admission", page.Events[0].Stage)
	require.Equal(t, events[0].TxHash.String(), *page.Events[0].TxHash)
	require.Equal(t, events[0].BlockHash.String(), *page.Events[0].BlockHash)
}

func TestOverlappingRecoveryCountsActiveConflictsAndReconcilesPending(t *testing.T) {
	r, reader, _ := recoveryTestService(t, false, common.AllowAllMessagesChecker{})
	head := &protocol.BlockHeader{Number: 100, Timestamp: time.Now()}
	events := createTestMessageSentEvents(t, 1, 42, defaultDestChain, []uint64{100})
	tasks := r.tasksFromEvents(t.Context(), events, head, head)
	r.addToPendingQueueHandleReorg(tasks, big.NewInt(100), big.NewInt(100))
	require.NoError(t, r.recovery.queue.Publish(t.Context(), tasks...))
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(100)).Return(events, nil).Twice()
	end := uint64(100)
	for range 2 {
		o, err := r.recovery.store.Submit(t.Context(), recovery.SubmitRequest{
			OwnerID: "owner", SourceChain: "42", FromBlock: 100,
			ToBlock: &end, Mode: "replay", Actor: "operator", Note: "overlapping range",
		})
		require.NoError(t, err)
		r.recoverRange(t.Context(), head, head, head)
		o, err = r.recovery.store.Get(t.Context(), o.ID)
		require.NoError(t, err)
		require.Equal(t, "completed", o.State)
		require.Zero(t, o.Admitted)
		require.Equal(t, int64(1), o.Conflicts)
		require.Empty(t, r.pendingTasks)
		require.Contains(t, r.sentTasks, tasks[0].MessageID)
	}
	r.addToPendingQueueHandleReorg(tasks, big.NewInt(100), big.NewInt(100))
	require.Empty(t, r.pendingTasks, "normal polling must not republish the same in-flight task")
	size, err := r.recovery.queue.Size(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 1, size)
	require.Equal(t, uint64(500), r.lastProcessedFinalizedBlock.Load().Uint64())
}

func TestRecoveryReportsRPCFailureAndBoundsChunks(t *testing.T) {
	r, reader, _ := recoveryTestService(t, false, common.AllowAllMessagesChecker{})
	end := uint64(100)
	request := recovery.SubmitRequest{
		OwnerID: "owner", SourceChain: "42", FromBlock: 100,
		ToBlock: &end, Mode: "replay", Actor: "operator", Note: "bounded range",
	}
	o, err := r.recovery.store.Submit(t.Context(), request)
	require.NoError(t, err)
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(100)).Return(nil, errors.New("RPC unavailable")).Once()
	head := &protocol.BlockHeader{Number: 1000, Timestamp: time.Now()}
	r.recoverRange(t.Context(), head, head, head)
	o, err = r.recovery.store.Get(t.Context(), o.ID)
	require.NoError(t, err)
	require.Equal(t, "failed", o.State)
	require.Equal(t, uint64(100), o.NextBlock)
	require.Equal(t, int64(1), o.Errors)
	require.Contains(t, o.LastError, "RPC unavailable")

	r.maxBlockRange = 500
	end = 500
	o, err = r.recovery.store.Submit(t.Context(), request)
	require.NoError(t, err)
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(199)).Return(nil, nil).Once()
	r.recoverRange(t.Context(), head, head, head)
	o, err = r.recovery.store.Get(t.Context(), o.ID)
	require.NoError(t, err)
	require.Equal(t, "running", o.State)
	require.Equal(t, uint64(200), o.NextBlock, "one poll must scan no more than 100 blocks")
	require.Equal(t, uint64(500), o.ToBlock)
	require.Equal(t, uint64(500), r.lastProcessedFinalizedBlock.Load().Uint64())
}

// A reset whose range ends above the finalized head must not move the in-memory cursor past
// finality. The durable checkpoint is already clamped, so without this the two disagree: a
// process that never restarts resumes above blocks that can still reorg and never sees their
// canonical replacements, while one that does restart re-reads them from the database row.
func TestResetDoesNotAdvanceCursorPastFinality(t *testing.T) {
	r, reader, _ := recoveryTestService(t, false, common.AllowAllMessagesChecker{})
	ctx := t.Context()
	require.NoError(t, r.chainStatusManager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{{ChainSelector: 42, FinalizedBlockHeight: big.NewInt(0), Disabled: true}}))
	_, err := r.initializeStartBlock(ctx)
	require.NoError(t, err)
	require.True(t, r.disabled.Load())

	end := uint64(105)
	reset, err := r.recovery.store.Submit(ctx, recovery.SubmitRequest{
		OwnerID: "owner", SourceChain: "42", FromBlock: 100, ToBlock: &end,
		Mode: "reset-reader", Actor: "operator", Note: "investigated boundary 99",
	})
	require.NoError(t, err)
	r.recoveryControl(ctx)
	require.False(t, r.disabled.Load())

	// The range runs to 105 but only 102 is finalized, so 103-105 are still reorg-able.
	latest := &protocol.BlockHeader{Number: 110, Timestamp: time.Now()}
	finalized := &protocol.BlockHeader{Number: 102, Timestamp: time.Now()}
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(105)).Return(nil, nil).Once()
	r.recoverRange(ctx, latest, latest, finalized)

	reset, err = r.recovery.store.Get(ctx, reset.ID)
	require.NoError(t, err)
	require.Equal(t, "completed", reset.State)

	require.Equal(t, uint64(103), r.lastProcessedFinalizedBlock.Load().Uint64(),
		"the next poll must resume just above the finalized head, not above the recovered range")
	statuses, err := r.chainStatusManager.ReadChainStatuses(ctx, []protocol.ChainSelector{42})
	require.NoError(t, err)
	require.Equal(t, uint64(102), statuses[42].FinalizedBlockHeight.Uint64(),
		"the durable checkpoint is clamped the same way, so the two cursors agree")
}
