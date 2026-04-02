package replay

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Type distinguishes between the two replay modes.
type Type string

const (
	TypeDiscovery Type = "discovery"
	TypeMessages  Type = "messages"
)

func ParseType(s string) (Type, error) {
	switch Type(s) {
	case TypeDiscovery, TypeMessages:
		return Type(s), nil
	default:
		return "", errors.New("unknown replay type: " + s)
	}
}

// Status tracks the lifecycle of a replay job.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

func ParseStatus(s string) (Status, error) {
	switch Status(s) {
	case StatusPending, StatusRunning, StatusCompleted, StatusFailed:
		return Status(s), nil
	default:
		return "", errors.New("unknown replay status: " + s)
	}
}

// Job represents a persisted replay job stored in the replay_jobs table.
type Job struct {
	ID             string `json:"id"`
	Type           Type   `json:"type"`
	Status         Status `json:"status"`
	ForceOverwrite bool   `json:"forceOverwrite"`
	RequestHash    string `json:"requestHash"`

	// Discovery replay params
	SinceSequenceNumber *int64 `json:"sinceSequenceNumber,omitempty"`

	// Message replay params
	MessageIDs []string `json:"messageIds,omitempty"`

	// Progress tracking
	ProgressCursor int64 `json:"progressCursor"`
	TotalItems     int   `json:"totalItems"`
	ProcessedItems int   `json:"processedItems"`

	// Heartbeat for stale-job detection
	LastHeartbeat time.Time `json:"lastHeartbeat"`

	ErrorMessage *string    `json:"errorMessage,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
	CompletedAt  *time.Time `json:"completedAt,omitempty"`
}

// Request is the input to start a new replay.
type Request struct {
	Type       Type
	Since      int64
	MessageIDs []string
	Force      bool
}

// Hash returns a deterministic SHA-256 hex digest that uniquely identifies the
// request parameters (type, force flag, and the type-specific fields). Two
// requests with the same arguments always produce the same hash, which is used
// by FindResumable to match a crashed job to the incoming retry.
func (r Request) Hash() string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "type=%s\n", r.Type)
	_, _ = fmt.Fprintf(h, "force=%v\n", r.Force)

	switch r.Type {
	case TypeDiscovery:
		_, _ = fmt.Fprintf(h, "since=%d\n", r.Since)
	case TypeMessages:
		sorted := make([]string, len(r.MessageIDs))
		copy(sorted, r.MessageIDs)
		sort.Strings(sorted)
		_, _ = fmt.Fprintf(h, "ids=%s\n", strings.Join(sorted, ","))
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}
