// Package store provides persistence for job specs received from the Job Distributor.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrNoJob is returned when no job is found in the store.
var ErrNoJob = errors.New("no job found in store")

// StoreInterface defines the interface for persisting job specs.
// It can, in theory, be implemented using any storage backend.
//
//revive:disable-next-line:exported
type StoreInterface interface {
	// SaveJob persists a job spec to the persistent store.
	SaveJob(ctx context.Context, proposalID string, version int64, spec string) error
	// LoadJob loads the most recent job spec from the persistent store.
	LoadJob(ctx context.Context) (*Job, error)
	// DeleteJob deletes all job specs from the persistent store.
	DeleteJob(ctx context.Context) error
}

// Ensure FileStore implements StoreInterface.
var _ StoreInterface = (*FileStore)(nil)

// Job represents a persisted job spec from the Job Distributor.
// File timestamps (e.g. os.Stat ModTime) can be used when creation/update time is needed.
type Job struct {
	ProposalID string
	Version    int64
	Spec       string
}

// fileJob is the JSON shape on disk (snake_case for proposal_id).
type fileJob struct {
	ProposalID string `json:"proposal_id"`
	Version    int64  `json:"version"`
	Spec       string `json:"spec"`
}

// FileStore persists a single job spec to a JSON file with atomic updates.
type FileStore struct {
	path string
	mu   sync.Mutex
}

// NewFileStore creates a new file-based job store. path is the path to the JSON file.
// The file is created on first SaveJob. All operations are thread-safe and atomic
// (writes go to a temp file then rename).
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// SaveJob persists the job by writing JSON to the file atomically.
func (f *FileStore) SaveJob(ctx context.Context, proposalID string, version int64, spec string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	job := fileJob{
		ProposalID: proposalID,
		Version:    version,
		Spec:       spec,
	}
	data, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal job: %w", err)
	}

	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create store directory: %w", err)
	}

	tmpPath := f.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write job file: %w", err)
	}
	// Ensure data is on disk before renaming
	file, err := os.Open(tmpPath) //nolint:gosec // G304: tmpPath is f.path+".tmp", both set at store init
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("open temp file for sync: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sync job file: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, f.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename job file: %w", err)
	}
	return nil
}

// LoadJob reads the job from the JSON file. Returns ErrNoJob if the file does not exist or is empty.
func (f *FileStore) LoadJob(ctx context.Context) (*Job, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loadLocked()
}

func (f *FileStore) loadLocked() (*Job, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoJob
		}
		return nil, fmt.Errorf("read job file: %w", err)
	}
	var fj fileJob
	if err := json.Unmarshal(data, &fj); err != nil {
		return nil, fmt.Errorf("decode job file: %w", err)
	}
	return &Job{
		ProposalID: fj.ProposalID,
		Version:    fj.Version,
		Spec:       fj.Spec,
	}, nil
}

// DeleteJob removes the job file. Idempotent if the file does not exist.
func (f *FileStore) DeleteJob(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.Remove(f.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete job file: %w", err)
	}
	return nil
}
