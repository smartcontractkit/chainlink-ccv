package postgres

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/testutil"
	messagerules "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func setupMessageDisablementRulesTestDB(t *testing.T) (*DatabaseStorage, func()) {
	t.Helper()
	ds, cleanup := testutil.SetupTestPostgresDB(t)
	if err := RunMigrations(ds, "postgres"); err != nil {
		cleanup()
		t.Fatalf("run migrations: %v", err)
	}
	return NewDatabaseStorage(ds, 10, 10*time.Second, logger.Sugared(logger.Test(t))), cleanup
}

func TestDatabaseStorage_MessageDisablementRules_CreateGetDelete(t *testing.T) {
	t.Parallel()

	storage, cleanup := setupMessageDisablementRulesTestDB(t)
	defer cleanup()
	ctx := context.Background()

	chainData, err := messagerules.NewChainRuleData(1001)
	require.NoError(t, err)
	created, err := storage.Create(ctx, chainData)
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)
	assert.Equal(t, messagerules.RuleTypeChain, created.Type)
	_, raw, err := messagerules.EncodeRuleData(created.Data)
	require.NoError(t, err)
	assert.JSONEq(t, `{"chain_selector":1001}`, string(raw))
	assert.False(t, created.CreatedAt.IsZero())
	assert.False(t, created.UpdatedAt.IsZero())

	got, err := storage.Get(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, created.ID, got.ID)

	require.NoError(t, storage.Delete(ctx, created.ID))
	got, err = storage.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestDatabaseStorage_MessageDisablementRules_ListWithTypeFilter(t *testing.T) {
	t.Parallel()

	storage, cleanup := setupMessageDisablementRulesTestDB(t)
	defer cleanup()
	ctx := context.Background()

	chainData, err := messagerules.NewChainRuleData(1001)
	require.NoError(t, err)
	tokenData, err := messagerules.NewTokenRuleData(2002, "0xABCDEF")
	require.NoError(t, err)
	_, err = storage.Create(ctx, chainData)
	require.NoError(t, err)
	_, err = storage.Create(ctx, tokenData)
	require.NoError(t, err)

	allRules, err := storage.List(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, allRules, 2)

	ruleType := messagerules.RuleTypeToken
	tokenRules, err := storage.List(ctx, &ruleType)
	require.NoError(t, err)
	require.Len(t, tokenRules, 1)
	assert.Equal(t, messagerules.RuleTypeToken, tokenRules[0].Type)
	_, raw, err := messagerules.EncodeRuleData(tokenRules[0].Data)
	require.NoError(t, err)
	assert.JSONEq(t, `{"chain_selector":2002,"token_address":"0xabcdef"}`, string(raw))
}

func TestDatabaseStorage_MessageDisablementRules_DuplicatePrevention(t *testing.T) {
	t.Parallel()

	storage, cleanup := setupMessageDisablementRulesTestDB(t)
	defer cleanup()
	ctx := context.Background()

	laneData, err := messagerules.NewLaneRuleData(1001, 2002)
	require.NoError(t, err)
	_, err = storage.Create(ctx, laneData)
	require.NoError(t, err)

	reversedLaneData, err := messagerules.NewLaneRuleData(2002, 1001)
	require.NoError(t, err)
	_, err = storage.Create(ctx, reversedLaneData)
	require.Error(t, err)

	chainData, err := messagerules.NewChainRuleData(3003)
	require.NoError(t, err)
	_, err = storage.Create(ctx, chainData)
	require.NoError(t, err)
	_, err = storage.Create(ctx, chainData)
	require.Error(t, err)
}

func TestDatabaseStorage_MessageDisablementRules_LargeChainSelector(t *testing.T) {
	t.Parallel()

	storage, cleanup := setupMessageDisablementRulesTestDB(t)
	defer cleanup()
	ctx := context.Background()

	data, err := messagerules.NewChainRuleData(math.MaxUint64)
	require.NoError(t, err)
	created, err := storage.Create(ctx, data)
	require.NoError(t, err)

	got, err := storage.Get(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	_, raw, err := messagerules.EncodeRuleData(got.Data)
	require.NoError(t, err)
	assert.JSONEq(t, `{"chain_selector":18446744073709551615}`, string(raw))
}

func TestDatabaseStorage_MessageDisablementRules_NotFoundAndValidation(t *testing.T) {
	t.Parallel()

	storage, cleanup := setupMessageDisablementRulesTestDB(t)
	defer cleanup()
	ctx := context.Background()

	got, err := storage.Get(ctx, "not-a-uuid")
	require.Error(t, err)
	assert.Nil(t, got)

	err = storage.Delete(ctx, messagerules.NewRuleID())
	require.Error(t, err)

	_, err = messagerules.NewChainRuleData(0)
	require.Error(t, err)
}
