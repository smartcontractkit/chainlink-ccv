package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/messagedisablement"
)

var _ messagedisablement.Store = (*DatabaseStorage)(nil)

type messageDisablementRuleRow struct {
	ID        string          `db:"id"`
	Type      string          `db:"type"`
	Data      json.RawMessage `db:"data"`
	CreatedAt time.Time       `db:"created_at"`
	UpdatedAt time.Time       `db:"updated_at"`
}

func rowToMessageDisablementRule(r messageDisablementRuleRow) messagedisablement.Rule {
	return messagedisablement.Rule{
		ID:        r.ID,
		Type:      messagedisablement.RuleType(r.Type),
		Data:      r.Data,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}

func (d *DatabaseStorage) Create(ctx context.Context, ruleType messagedisablement.RuleType, data json.RawMessage) (messagedisablement.Rule, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	parsedType, err := messagedisablement.ParseRuleType(string(ruleType))
	if err != nil {
		return messagedisablement.Rule{}, err
	}
	normalized, err := messagedisablement.NormalizeRuleData(parsedType, data)
	if err != nil {
		return messagedisablement.Rule{}, err
	}

	stmt := `INSERT INTO message_disablement_rules (id, type, data)
	         VALUES ($1, $2, $3)
	         RETURNING id::text, type, data, created_at, updated_at`

	var row messageDisablementRuleRow
	if err := d.ds.GetContext(ctx, &row, stmt, messagedisablement.NewRuleID(), string(parsedType), normalized); err != nil {
		return messagedisablement.Rule{}, fmt.Errorf("failed to create message disablement rule: %w", err)
	}

	return rowToMessageDisablementRule(row), nil
}

func (d *DatabaseStorage) List(ctx context.Context, ruleType *messagedisablement.RuleType) ([]messagedisablement.Rule, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	stmt := `SELECT id::text, type, data, created_at, updated_at
	         FROM message_disablement_rules`
	args := []any{}
	if ruleType != nil {
		parsed, err := messagedisablement.ParseRuleType(string(*ruleType))
		if err != nil {
			return nil, err
		}
		stmt += ` WHERE type = $1`
		args = append(args, string(parsed))
	}
	stmt += ` ORDER BY type, data, created_at`

	var rows []messageDisablementRuleRow
	if err := d.ds.SelectContext(ctx, &rows, stmt, args...); err != nil {
		return nil, fmt.Errorf("failed to list message disablement rules: %w", err)
	}

	rules := make([]messagedisablement.Rule, len(rows))
	for i, row := range rows {
		rules[i] = rowToMessageDisablementRule(row)
	}
	return rules, nil
}

func (d *DatabaseStorage) Get(ctx context.Context, id string) (*messagedisablement.Rule, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	if err := messagedisablement.ValidateRuleID(id); err != nil {
		return nil, err
	}

	stmt := `SELECT id::text, type, data, created_at, updated_at
	         FROM message_disablement_rules
	         WHERE id = $1`

	var row messageDisablementRuleRow
	if err := d.ds.GetContext(ctx, &row, stmt, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get message disablement rule %s: %w", id, err)
	}

	rule := rowToMessageDisablementRule(row)
	return &rule, nil
}

func (d *DatabaseStorage) Delete(ctx context.Context, id string) error {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	if err := messagedisablement.ValidateRuleID(id); err != nil {
		return err
	}

	result, err := d.ds.ExecContext(ctx, `DELETE FROM message_disablement_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete message disablement rule %s: %w", id, err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check deleted message disablement rule %s: %w", id, err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("message disablement rule %s not found", id)
	}
	return nil
}
