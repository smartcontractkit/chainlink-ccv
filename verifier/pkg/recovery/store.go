package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

type Store struct{ ds sqlutil.DataSource }

func NewStore(ds sqlutil.DataSource) *Store { return &Store{ds: ds} }

func (s *Store) DataSource() sqlutil.DataSource { return s.ds }

// RegisterReader marks a process-session boundary; a restarted process cannot claim
// continuous observation during its downtime. Historical coverage starts only at upgrade.
func (s *Store) RegisterReader(ctx context.Context, owner, chain, node string, disabled bool) error {
	_, err := s.ds.ExecContext(ctx, `INSERT INTO ccv_recovery_readers (owner_id, chain_selector, node_id, disabled)
		VALUES ($1,$2,$3,$4) ON CONFLICT (owner_id, chain_selector) DO UPDATE SET
		node_id = EXCLUDED.node_id, session_started_at = NOW(), last_seen_at = NOW(), disabled = EXCLUDED.disabled`, owner, chain, node, disabled)
	return err
}

func (s *Store) Heartbeat(ctx context.Context, owner, chain string, latest *uint64, disabled bool, auditFailures int64) error {
	var height any
	if latest != nil {
		height = fmt.Sprint(*latest)
	}
	_, err := s.ds.ExecContext(ctx, `UPDATE ccv_recovery_readers SET last_seen_at = NOW(),
		latest_block = COALESCE($3::numeric, latest_block),
		head_observed_at = CASE WHEN $3::numeric IS NULL THEN head_observed_at ELSE NOW() END,
		disabled = $4, audit_failures = audit_failures + $5,
		last_audit_failure_at = CASE WHEN $5 > 0 THEN NOW() ELSE last_audit_failure_at END
		WHERE owner_id = $1 AND chain_selector = $2`, owner, chain, height, disabled, auditFailures)
	return err
}

// RecordEvents commits the incident and its known pending messages together.
// Drops deduplicate by owner/node, chain, message, block/hash, transaction, reason and incident.
// Reobservation extends retention from last observation; it does not invent new jobs.
func (s *Store) RecordEvents(ctx context.Context, events ...Event) error {
	return sqlutil.TransactDataSource(ctx, s.ds, nil, func(tx sqlutil.DataSource) error {
		for _, e := range events {
			if e.EventID == "" {
				e.EventID = uuid.NewString()
			}
			if len(e.Details) == 0 {
				e.Details = json.RawMessage(`{}`)
			}
			identity, err := json.Marshal([]any{e.OwnerID, e.NodeID, e.SourceChain, e.MessageID, e.SourceBlock, e.BlockHash, e.TxHash, e.Reason, e.IncidentID})
			if err != nil {
				return err
			}
			if e.Kind != "drop" {
				identity = []byte(e.EventID)
			}
			digest := sha256.Sum256(identity)
			_, err = tx.ExecContext(ctx, `INSERT INTO ccv_recovery_events
				(event_id, dedup_key, owner_id, node_id, chain_selector, dest_chain_selector, message_id,
				source_block, kind, stage, reason, tx_hash, block_hash, incident_id, details)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
				ON CONFLICT (dedup_key) DO UPDATE SET last_observed_at = NOW(),
				observations = ccv_recovery_events.observations + 1, expires_at = NOW() + INTERVAL '30 days'`,
				e.EventID, hex.EncodeToString(digest[:]), e.OwnerID, e.NodeID, e.SourceChain, e.DestChain,
				e.MessageID, e.SourceBlock, e.Kind, e.Stage, e.Reason, e.TxHash, e.BlockHash, e.IncidentID, []byte(e.Details))
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) ListEvents(ctx context.Context, f EventFilter) (EventPage, error) {
	page := EventPage{
		Events: make([]Event, 0), RetainedSince: time.Now().UTC().Add(-HistoryRetention),
		Coverage: "Observed events only. Empty results do not prove no affected traffic. Unobserved disabled intervals, downtime, audit failures and expired history require canonical source-chain investigation.",
	}
	if f.Limit < 1 || f.Limit > MaxPageSize {
		return page, fmt.Errorf("limit must be between 1 and %d", MaxPageSize)
	}
	query := `SELECT id::text, event_id, owner_id, node_id, chain_selector::text, dest_chain_selector::text,
		message_id, source_block::text, kind, stage, reason, tx_hash, block_hash, incident_id,
		details, first_observed_at, last_observed_at, observations::text, expires_at
		FROM ccv_recovery_events WHERE expires_at > NOW()`
	args := []any{}
	add := func(column, operator string, value any) {
		args = append(args, value)
		query += fmt.Sprintf(" AND %s %s $%d", column, operator, len(args))
	}
	for _, filter := range []struct {
		column, value string
	}{
		{"owner_id", f.OwnerID}, {"chain_selector", f.SourceChain}, {"dest_chain_selector", f.DestChain}, {"reason", f.Reason},
	} {
		if filter.value != "" {
			add(filter.column, "=", filter.value)
		}
	}
	if f.Since != nil {
		add("last_observed_at", ">=", *f.Since)
	}
	if f.Until != nil {
		add("first_observed_at", "<=", *f.Until)
	}
	if f.FromBlock != "" {
		add("source_block", ">=", f.FromBlock)
	}
	if f.ToBlock != "" {
		add("source_block", "<=", f.ToBlock)
	}
	if f.BeforeID != "" {
		add("id", "<", f.BeforeID)
	}
	if len(f.MessageIDs) > 0 {
		placeholders := make([]string, len(f.MessageIDs))
		for i, id := range f.MessageIDs {
			args = append(args, id)
			placeholders[i] = fmt.Sprintf("$%d", len(args))
		}
		query += " AND message_id IN (" + strings.Join(placeholders, ",") + ")"
	}
	args = append(args, f.Limit+1)
	query += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args))
	rows, err := s.ds.QueryContext(ctx, query, args...)
	if err != nil {
		return page, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.EventID, &e.OwnerID, &e.NodeID, &e.SourceChain, &e.DestChain,
			&e.MessageID, &e.SourceBlock, &e.Kind, &e.Stage, &e.Reason, &e.TxHash, &e.BlockHash, &e.IncidentID,
			&e.Details, &e.FirstObservedAt, &e.LastObservedAt, &e.Observations, &e.ExpiresAt); err != nil {
			return page, err
		}
		page.Events = append(page.Events, e)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	if err := rows.Close(); err != nil {
		return page, err
	}
	if len(page.Events) > f.Limit {
		page.Events = page.Events[:f.Limit]
		page.NextCursor = page.Events[len(page.Events)-1].ID
	}
	err = s.ds.QueryRowxContext(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_object(
		'owner_id',owner_id,'source_chain_selector',chain_selector::text,'node_id',node_id,
		'history_started_at',history_started_at,'session_started_at',session_started_at,'last_seen_at',last_seen_at,
		'latest_block',latest_block::text,'head_observed_at',head_observed_at,'disabled',disabled,'active_reset_id',active_reset_id,'audit_failures',audit_failures::text,'last_audit_failure_at',last_audit_failure_at)), '[]'::jsonb)
		FROM ccv_recovery_readers WHERE ($1 = '' OR owner_id = $1) AND ($2 = '' OR chain_selector = NULLIF($2, '')::numeric)`,
		f.OwnerID, f.SourceChain).Scan(&page.Readers)
	return page, err
}

// Cleanup is bounded per call. Expired rows never appear in reads even while a
// large expiry backlog is being removed. Active recovery requests are never expired.
func (s *Store) Cleanup(ctx context.Context, owner string) error {
	_, err := s.ds.ExecContext(ctx, `DELETE FROM ccv_recovery_events WHERE id IN
		(SELECT id FROM ccv_recovery_events WHERE owner_id = $1 AND expires_at < NOW() ORDER BY expires_at LIMIT 5000)`, owner)
	if err != nil {
		return err
	}
	_, err = s.ds.ExecContext(ctx, `DELETE FROM ccv_recovery_operations WHERE id IN
		(SELECT id FROM ccv_recovery_operations WHERE owner_id = $1 AND state IN ('completed','cancelled','failed')
		AND id NOT IN (SELECT active_reset_id FROM ccv_recovery_readers WHERE active_reset_id IS NOT NULL)
		AND updated_at < NOW() - INTERVAL '30 days' ORDER BY updated_at LIMIT 5000)`, owner)
	return err
}
