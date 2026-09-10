package recovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

const operationColumns = `id, owner_id, chain_selector::text, from_block::text, to_block::text, next_block::text,
	mode, state, reset_applied, actor, note, admitted, dropped, conflicts, filtered, errors, last_error, created_at, updated_at`

func scanOperation(row interface{ Scan(...any) error }) (Operation, error) {
	var o Operation
	err := row.Scan(&o.ID, &o.OwnerID, &o.SourceChain, &o.FromBlock, &o.ToBlock, &o.NextBlock,
		&o.Mode, &o.State, &o.ResetApplied, &o.Actor, &o.Note, &o.Admitted, &o.Dropped, &o.Conflicts, &o.Filtered, &o.Errors,
		&o.LastError, &o.CreatedAt, &o.UpdatedAt)
	return o, err
}

func (s *Store) Get(ctx context.Context, id string) (Operation, error) {
	return scanOperation(s.ds.QueryRowxContext(ctx, "SELECT "+operationColumns+" FROM ccv_recovery_operations WHERE id = $1", id))
}

// Submit captures an omitted upper bound from the reader's recent advertised head
// in this transaction. The target never follows later head advances.
func (s *Store) Submit(ctx context.Context, r SubmitRequest) (Operation, error) {
	var result Operation
	if strings.TrimSpace(r.OwnerID) == "" || strings.TrimSpace(r.Actor) == "" || strings.TrimSpace(r.Note) == "" {
		return result, fmt.Errorf("verifier owner, actor and recovery note are required")
	}
	chain, err := strconv.ParseUint(r.SourceChain, 10, 64)
	if err != nil {
		return result, fmt.Errorf("invalid source chain: %w", err)
	}
	r.SourceChain = strconv.FormatUint(chain, 10)
	if r.Mode != "replay" && r.Mode != "reset-reader" {
		return result, fmt.Errorf("mode must be replay or reset-reader")
	}
	if r.FromBlock == math.MaxUint64 {
		return result, fmt.Errorf("from-block must be between 0 and 18446744073709551614")
	}
	if r.ToBlock != nil && (*r.ToBlock < r.FromBlock || *r.ToBlock == math.MaxUint64) {
		return result, fmt.Errorf("to-block must be >= from-block and below uint64 maximum")
	}
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	id, err := uuid.Parse(r.ID)
	if err != nil {
		return result, fmt.Errorf("request-id must be a UUID: %w", err)
	}
	r.ID = id.String()
	err = sqlutil.TransactDataSource(ctx, s.ds, nil, func(tx sqlutil.DataSource) error {
		// Serialize repeated submission of the same idempotency key.
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", r.ID); err != nil {
			return err
		}
		store := NewStore(tx)
		existing, err := store.Get(ctx, r.ID)
		if err == nil {
			if existing.OwnerID != r.OwnerID || existing.SourceChain != r.SourceChain || existing.FromBlock != r.FromBlock ||
				existing.Mode != r.Mode || existing.Actor != r.Actor || existing.Note != r.Note || (r.ToBlock != nil && existing.ToBlock != *r.ToBlock) {
				return fmt.Errorf("request-id already belongs to a different request")
			}
			result = existing
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var head sql.NullString
		var fresh bool
		err = tx.QueryRowxContext(ctx, `SELECT latest_block::text,
			COALESCE(head_observed_at > NOW() - INTERVAL '1 minute', FALSE)
			FROM ccv_recovery_readers WHERE owner_id = $1 AND chain_selector = $2`, r.OwnerID, r.SourceChain).Scan(&head, &fresh)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no registered reader for this verifier owner and source chain")
		}
		if err != nil {
			return err
		}
		var to uint64
		if r.ToBlock == nil {
			if !head.Valid || !fresh {
				return fmt.Errorf("reader has no recent head; supply an explicit --to-block")
			}
			to, err = strconv.ParseUint(head.String, 10, 64)
			if err != nil {
				return err
			}
		} else {
			to = *r.ToBlock
		}
		if to < r.FromBlock || to == math.MaxUint64 {
			return fmt.Errorf("captured target is below from-block or outside supported range")
		}
		result, err = scanOperation(tx.QueryRowxContext(ctx, `INSERT INTO ccv_recovery_operations
			(id,owner_id,chain_selector,from_block,to_block,next_block,mode,actor,note)
			VALUES ($1,$2,$3,$4,$5,$4,$6,$7,$8) RETURNING `+operationColumns,
			r.ID, r.OwnerID, r.SourceChain, fmt.Sprint(r.FromBlock), fmt.Sprint(to), r.Mode, r.Actor, r.Note))
		return err
	})
	return result, err
}

func (s *Store) List(ctx context.Context, owner, chain string, limit int) ([]Operation, error) {
	if limit < 1 || limit > MaxPageSize {
		return nil, fmt.Errorf("limit must be between 1 and %d", MaxPageSize)
	}
	rows, err := s.ds.QueryContext(ctx, "SELECT "+operationColumns+` FROM ccv_recovery_operations
		WHERE ($1 = '' OR owner_id = $1) AND ($2 = '' OR chain_selector = NULLIF($2, '')::numeric)
		ORDER BY created_at DESC, id DESC LIMIT $3`, owner, chain, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	result := make([]Operation, 0)
	for rows.Next() {
		o, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, o)
	}
	return result, rows.Err()
}

// ChangeState waits for an in-flight chunk transaction. Cancellation is therefore
// effective when this call returns, and never retracts already-published jobs.
func (s *Store) ChangeState(ctx context.Context, id, action string) (Operation, error) {
	var state, allowed string
	guard := ""
	stateExpression := "$2"
	switch action {
	case "cancel":
		state, allowed = "cancelled", "'accepted','running','blocked','failed','cancelled'"
	case "resume":
		state, allowed = "accepted", "'cancelled','failed','blocked','accepted','running'"
		stateExpression = "CASE WHEN state IN ('accepted','running') THEN state ELSE $2 END"
		guard = " AND (mode <> 'reset-reader' OR NOT reset_applied OR id IN (SELECT active_reset_id FROM ccv_recovery_readers WHERE active_reset_id IS NOT NULL))"
	default:
		return Operation{}, fmt.Errorf("unknown recovery action %q", action)
	}
	o, err := scanOperation(s.ds.QueryRowxContext(ctx, `UPDATE ccv_recovery_operations SET state = `+stateExpression+`,
		last_error = '', updated_at = NOW() WHERE id = $1 AND state IN (`+allowed+`)`+guard+` RETURNING `+operationColumns, id, state))
	if errors.Is(err, sql.ErrNoRows) {
		return o, fmt.Errorf("operation does not exist or cannot %s in its current state", action)
	}
	return o, err
}

func (s *Store) Next(ctx context.Context, owner, chain string) (Operation, error) {
	return scanOperation(s.ds.QueryRowxContext(ctx, "SELECT "+operationColumns+` FROM ccv_recovery_operations
		WHERE owner_id = $1 AND chain_selector = $2 AND state IN ('accepted','running')
		ORDER BY (mode = 'reset-reader' AND NOT reset_applied) DESC,
		(id = COALESCE((SELECT active_reset_id FROM ccv_recovery_readers WHERE owner_id=$1 AND chain_selector=$2), '00000000-0000-0000-0000-000000000000'::uuid)) DESC, created_at, id LIMIT 1`, owner, chain))
}

// Step serializes work per owner/chain and locks the selected operation. Queue
// insertion, drop evidence, counters and block progress share this transaction.
func (s *Store) Step(ctx context.Context, id string, work func(*Store, *Operation) error) error {
	return sqlutil.TransactDataSource(ctx, s.ds, nil, func(tx sqlutil.DataSource) error {
		store := NewStore(tx)
		o, err := store.Get(ctx, id)
		if err != nil {
			return err
		}
		var acquired bool
		err = tx.QueryRowxContext(ctx, "SELECT pg_try_advisory_xact_lock(hashtextextended($1, 1))", o.OwnerID+":"+o.SourceChain).Scan(&acquired)
		if err != nil || !acquired {
			return err
		}
		next, err := store.Next(ctx, o.OwnerID, o.SourceChain)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && next.ID != id) {
			return nil
		}
		if err != nil {
			return err
		}
		o, err = scanOperation(tx.QueryRowxContext(ctx, "SELECT "+operationColumns+" FROM ccv_recovery_operations WHERE id = $1 FOR UPDATE", id))
		if err != nil {
			return err
		}
		if o.State != "accepted" && o.State != "running" {
			return nil
		}
		o.State, o.LastError = "running", ""
		if err := work(store, &o); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE ccv_recovery_operations SET state=$2,next_block=$3,
			admitted=$4,dropped=$5,conflicts=$6,filtered=$7,last_error=$8,reset_applied=$9,errors=$10,updated_at=NOW() WHERE id=$1`,
			o.ID, o.State, fmt.Sprint(o.NextBlock), o.Admitted, o.Dropped, o.Conflicts, o.Filtered, o.LastError, o.ResetApplied, o.Errors)
		return err
	})
}

// Fail records a rolled-back attempt only if no operator action or newer chunk
// has changed the request since that attempt began.
func (s *Store) Fail(ctx context.Context, id string, attemptedVersion time.Time, cause error) error {
	_, err := s.ds.ExecContext(ctx, `UPDATE ccv_recovery_operations SET state='failed',last_error=$2,errors=errors+1,updated_at=NOW()
		WHERE id=$1 AND state IN ('accepted','running') AND updated_at=$3`, id, cause.Error(), attemptedVersion)
	return err
}

// ActiveReset keeps normal polling behind an unfinished investigated reset,
// including canceled/failed operations and across process restarts.
func (s *Store) ActiveReset(ctx context.Context, owner, chain string) (string, error) {
	var id string
	err := s.ds.QueryRowxContext(ctx, "SELECT COALESCE(active_reset_id::text,'') FROM ccv_recovery_readers WHERE owner_id=$1 AND chain_selector=$2", owner, chain).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}
