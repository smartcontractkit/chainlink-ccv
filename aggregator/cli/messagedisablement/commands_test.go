package messagedisablement

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	rules "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type memStore struct {
	rows map[string]rules.Rule
}

func newMemStore() *memStore {
	return &memStore{rows: make(map[string]rules.Rule)}
}

func (m *memStore) Create(_ context.Context, data rules.RuleData) (rules.Rule, error) {
	ruleType, encoded, err := rules.EncodeRuleData(data)
	if err != nil {
		return rules.Rule{}, err
	}
	for _, row := range m.rows {
		rowType, rowData, err := rules.EncodeRuleData(row.Data)
		if err != nil {
			return rules.Rule{}, err
		}
		if rowType == ruleType && bytes.Equal(rowData, encoded) {
			return rules.Rule{}, fmt.Errorf("duplicate rule")
		}
	}
	now := time.Now().UTC()
	row, err := rules.NewRule(rules.NewRuleID(), data, now, now)
	if err != nil {
		return rules.Rule{}, err
	}
	m.rows[row.ID] = row
	return row, nil
}

func (m *memStore) List(_ context.Context, ruleType *rules.RuleType) ([]rules.Rule, error) {
	out := make([]rules.Rule, 0, len(m.rows))
	for _, row := range m.rows {
		if ruleType != nil && row.Type != *ruleType {
			continue
		}
		out = append(out, row)
	}
	return out, nil
}

func (m *memStore) Get(_ context.Context, id string) (*rules.Rule, error) {
	if err := rules.ValidateRuleID(id); err != nil {
		return nil, err
	}
	if row, ok := m.rows[id]; ok {
		return &row, nil
	}
	return nil, nil
}

func (m *memStore) Delete(_ context.Context, id string) error {
	if err := rules.ValidateRuleID(id); err != nil {
		return err
	}
	if _, ok := m.rows[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.rows, id)
	return nil
}

func makeDeps(t *testing.T, store rules.Store) Deps {
	t.Helper()
	return Deps{Logger: logger.Test(t), Store: store}
}

func runCLI(t *testing.T, deps Deps, args []string) (string, error) {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	app := cli.NewApp()
	app.Name = "test"
	app.Commands = InitMessageDisablementRulesCommands(deps)
	runErr := app.Run(append([]string{"test"}, args...))

	require.NoError(t, w.Close())
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), runErr
}

func parseRuleID(t *testing.T, out string) string {
	t.Helper()
	match := regexp.MustCompile(`id=([0-9a-f-]{36})`).FindStringSubmatch(out)
	require.Len(t, match, 2, "expected id=<uuid> in output:\n%s", out)
	return match[1]
}

func TestCreateListGetDeleteRule(t *testing.T) {
	store := newMemStore()

	out, err := runCLI(t, makeDeps(t, store), []string{"create", "chain", "--chain", "1001"})
	require.NoError(t, err)
	id := parseRuleID(t, out)
	assert.Contains(t, out, "Chain")
	assert.Contains(t, out, `"chain_selector":1001`)

	out, err = runCLI(t, makeDeps(t, store), []string{"list"})
	require.NoError(t, err)
	assert.Contains(t, out, id)

	out, err = runCLI(t, makeDeps(t, store), []string{"get", "--id", id})
	require.NoError(t, err)
	assert.Contains(t, out, `"chain_selector":1001`)

	out, err = runCLI(t, makeDeps(t, store), []string{"delete", "--id", id})
	require.NoError(t, err)
	assert.Contains(t, out, "Deleted message disablement rule")

	out, err = runCLI(t, makeDeps(t, store), []string{"list"})
	require.NoError(t, err)
	assert.Contains(t, out, "No message disablement rules found.")
}

func TestCreateToken_NormalizesTokenAddressAndListFilter(t *testing.T) {
	store := newMemStore()

	out, err := runCLI(t, makeDeps(t, store), []string{"create", "token", "--token", "2002,ABCDEF"})
	require.NoError(t, err)
	assert.Contains(t, out, `"token_address":"0xabcdef"`)

	_, err = runCLI(t, makeDeps(t, store), []string{"create", "chain", "--chain", "1001"})
	require.NoError(t, err)

	out, err = runCLI(t, makeDeps(t, store), []string{"list", "--type", "Token"})
	require.NoError(t, err)
	assert.Contains(t, out, "Token")
	assert.Contains(t, out, `"token_address":"0xabcdef"`)
	assert.NotContains(t, out, "Chain")
}

func TestCreateSupportsMultipleCompactRuleValues(t *testing.T) {
	store := newMemStore()

	out, err := runCLI(t, makeDeps(t, store), []string{"create", "chain", "--chain", "1001,2002", "--chain", "3003"})
	require.NoError(t, err)
	assert.Len(t, regexp.MustCompile(`id=([0-9a-f-]{36})`).FindAllStringSubmatch(out, -1), 3)
	assert.Contains(t, out, `"chain_selector":1001`)
	assert.Contains(t, out, `"chain_selector":2002`)
	assert.Contains(t, out, `"chain_selector":3003`)

	out, err = runCLI(t, makeDeps(t, store), []string{"create", "lane", "--lane", "4004,5005", "--lane", "7007,6006"})
	require.NoError(t, err)
	assert.Len(t, regexp.MustCompile(`id=([0-9a-f-]{36})`).FindAllStringSubmatch(out, -1), 2)
	assert.Contains(t, out, `"selector_a":4004`)
	assert.Contains(t, out, `"selector_b":5005`)
	assert.Contains(t, out, `"selector_a":6006`)
	assert.Contains(t, out, `"selector_b":7007`)

	out, err = runCLI(t, makeDeps(t, store), []string{"create", "token", "--token", "8008,0xAA", "--token", "9009,BB"})
	require.NoError(t, err)
	assert.Len(t, regexp.MustCompile(`id=([0-9a-f-]{36})`).FindAllStringSubmatch(out, -1), 2)
	assert.Contains(t, out, `"chain_selector":8008`)
	assert.Contains(t, out, `"token_address":"0xaa"`)
	assert.Contains(t, out, `"chain_selector":9009`)
	assert.Contains(t, out, `"token_address":"0xbb"`)
}

func TestValidationErrors(t *testing.T) {
	store := newMemStore()

	_, err := runCLI(t, makeDeps(t, store), []string{"create", "chain", "--chain", "not-a-selector"})
	require.Error(t, err)

	_, err = runCLI(t, makeDeps(t, store), []string{"create", "lane", "--lane", "1001,1001"})
	require.Error(t, err)

	_, err = runCLI(t, makeDeps(t, store), []string{"create", "chain", "--chain", "0"})
	require.Error(t, err)

	_, err = runCLI(t, makeDeps(t, store), []string{"create", "lane", "--lane", "1001,0"})
	require.Error(t, err)

	_, err = runCLI(t, makeDeps(t, store), []string{"create", "token", "--token", "1001,not-hex"})
	require.Error(t, err)

	_, err = runCLI(t, makeDeps(t, store), []string{"delete", "--id", "not-a-uuid"})
	require.Error(t, err)
}
