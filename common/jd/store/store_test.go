package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileStore_SaveAndLoadJob(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "job.json")
	ctx := context.Background()

	s := NewFileStore(path)

	// No file yet
	_, err := s.LoadJob(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoJob)

	// Save a job
	err = s.SaveJob(ctx, "proposal-1", 1, `{"type":"ccv"}`)
	require.NoError(t, err)

	job, err := s.LoadJob(ctx)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, "proposal-1", job.ProposalID)
	assert.Equal(t, int64(1), job.Version)
	assert.Equal(t, `{"type":"ccv"}`, job.Spec)
}

func TestFileStore_SaveReplacesExistingJob(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "job.json")
	ctx := context.Background()

	s := NewFileStore(path)
	require.NoError(t, s.SaveJob(ctx, "proposal-1", 1, `{"v":1}`))
	require.NoError(t, s.SaveJob(ctx, "proposal-2", 2, `{"v":2}`))

	job, err := s.LoadJob(ctx)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, "proposal-2", job.ProposalID)
	assert.Equal(t, int64(2), job.Version)
}

func TestFileStore_DeleteJob(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "job.json")
	ctx := context.Background()

	s := NewFileStore(path)
	require.NoError(t, s.SaveJob(ctx, "proposal-1", 1, `{}`))
	require.NoError(t, s.DeleteJob(ctx))

	_, err := s.LoadJob(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoJob)

	// Idempotent
	require.NoError(t, s.DeleteJob(ctx))
}

func TestFileStore_DeleteJob_WhenEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "job.json")
	ctx := context.Background()

	s := NewFileStore(path)
	require.NoError(t, s.DeleteJob(ctx))
}

func TestFileStore_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "job.json")
	ctx := context.Background()

	s := NewFileStore(path)
	require.NoError(t, s.SaveJob(ctx, "id", 1, "spec"))

	// Should be valid JSON; read raw and assert file exists and is valid
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotEmpty(t, data)
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, "id", m["proposal_id"])
}
