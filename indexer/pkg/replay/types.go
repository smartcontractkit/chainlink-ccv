package replay

import (
	"errors"
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

	// Discovery replay params
	SinceTimestamp *int64 `json:"sinceTimestamp,omitempty"`

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
	Since      time.Time
	MessageIDs []string
	Force      bool
}
