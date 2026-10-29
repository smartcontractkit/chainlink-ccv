package admin

import (
	"sync"
	"sync/atomic"
	"time"
)

// Action is one console mutation record. OperationID carries the recovery
// operation ID when the action produced one; Detail holds per-target outcomes.
type Action struct {
	ID          int64
	Actor       string
	Action      string
	Target      string
	OperationID string
	Outcome     string
	Detail      string
	CreatedAt   time.Time
}

// ActionLog is the console's audit of its own mutations. It is deliberately
// in-memory and session-scoped: it survives only as long as the console does,
// and a verifier restart or job replacement starts a fresh page. Persisting
// it is a follow-up if session history proves insufficient.
type ActionLog struct {
	mu      sync.Mutex
	seq     atomic.Int64
	actions []Action
}

func NewActionLog() *ActionLog { return &ActionLog{} }

// Record appends one action; the console is the only writer.
func (l *ActionLog) Record(a Action) {
	a.ID = l.seq.Add(1)
	a.CreatedAt = time.Now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.actions = append(l.actions, a)
}

// List returns newest-first actions; beforeID=0 starts at the latest.
func (l *ActionLog) List(limit int, beforeID int64) []Action {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Action
	for i := len(l.actions) - 1; i >= 0 && len(out) < limit; i-- {
		if beforeID == 0 || l.actions[i].ID < beforeID {
			out = append(out, l.actions[i])
		}
	}
	return out
}
