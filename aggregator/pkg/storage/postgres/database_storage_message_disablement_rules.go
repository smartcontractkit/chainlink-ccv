package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	messagerules "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
)

var _ messagerules.Store = (*DatabaseStorage)(nil)

type messageDisablementRuleRow struct {
	ID        string          `db:"id"`
	Type      string          `db:"type"`
	Data      json.RawMessage `db:"data"`
	CreatedAt time.Time       `db:"created_at"`
	UpdatedAt time.Time       `db:"updated_at"`
}

func rowToMessageDisablementRule(r messageDisablementRuleRow) (messagerules.Rule, error) {
	ruleType, err := messagerules.ParseRuleType(r.Type)
	if err != nil {
		return messagerules.Rule{}, err
	}
	data, err := messagerules.DecodeRuleData(ruleType, r.Data)
	if err != nil {
		return messagerules.Rule{}, err
	}
	return messagerules.NewRule(r.ID, data, r.CreatedAt, r.UpdatedAt)
}

func (d *DatabaseStorage) Create(ctx context.Context, data messagerules.RuleData) (messagerules.Rule, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	ruleType, encoded, err := messagerules.EncodeRuleData(data)
	if err != nil {
		return messagerules.Rule{}, err
	}

	stmt := `INSERT INTO message_disablement_rules (id, type, data)
	         VALUES ($1, $2, $3)
	         RETURNING id::text, type, data, created_at, updated_at`

	var row messageDisablementRuleRow
	if err := d.ds.GetContext(ctx, &row, stmt, messagerules.NewRuleID(), string(ruleType), encoded); err != nil {
		return messagerules.Rule{}, fmt.Errorf("failed to create message disablement rule: %w", err)
	}

	rule, err := rowToMessageDisablementRule(row)
	if err != nil {
		return messagerules.Rule{}, fmt.Errorf("failed to decode created message disablement rule: %w", err)
	}
	return rule, nil
}

func (d *DatabaseStorage) List(ctx context.Context, ruleType *messagerules.RuleType) ([]messagerules.Rule, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	stmt := `SELECT id::text, type, data, created_at, updated_at
	         FROM message_disablement_rules`
	args := []any{}
	if ruleType != nil {
		parsed, err := messagerules.ParseRuleType(string(*ruleType))
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

	rules := make([]messagerules.Rule, len(rows))
	for i, row := range rows {
		rule, err := rowToMessageDisablementRule(row)
		if err != nil {
			return nil, fmt.Errorf("failed to decode message disablement rule %s: %w", row.ID, err)
		}
		rules[i] = rule
	}
	return rules, nil
}

func (d *DatabaseStorage) Get(ctx context.Context, id string) (*messagerules.Rule, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	if err := messagerules.ValidateRuleID(id); err != nil {
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

	rule, err := rowToMessageDisablementRule(row)
	if err != nil {
		return nil, fmt.Errorf("failed to decode message disablement rule %s: %w", id, err)
	}
	return &rule, nil
}

func (d *DatabaseStorage) Delete(ctx context.Context, id string) error {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	if err := messagerules.ValidateRuleID(id); err != nil {
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
