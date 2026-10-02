// Package recovery stores operator requests and source-reader evidence. It has no
// chain-family dependencies and never bypasses verifier or policy processing.
package recovery

import (
	"encoding/json"
	"time"
)

const (
	HistoryRetention = 30 * 24 * time.Hour
	MaxPageSize      = 500
	MaxChunkBlocks   = 100
	MaxChunkMessages = 1000
	MaxActiveJobs    = 10000
)

// Numeric selectors, heights, counters and cursors are strings in CLI JSON to
// preserve uint64 precision in browser clients. Absent evidence is JSON null.
type Event struct {
	ID              string          `json:"id"`
	EventID         string          `json:"event_id"`
	OwnerID         string          `json:"owner_id"`
	NodeID          string          `json:"node_id"`
	SourceChain     string          `json:"source_chain_selector"`
	DestChain       *string         `json:"dest_chain_selector"`
	MessageID       *string         `json:"message_id"`
	SourceBlock     *string         `json:"source_block"`
	Kind            string          `json:"kind"`
	Stage           string          `json:"stage"`
	Reason          string          `json:"reason"`
	TxHash          *string         `json:"tx_hash"`
	BlockHash       *string         `json:"block_hash"`
	IncidentID      *string         `json:"incident_id"`
	Details         json.RawMessage `json:"details"`
	FirstObservedAt time.Time       `json:"first_observed_at"`
	LastObservedAt  time.Time       `json:"last_observed_at"`
	Observations    string          `json:"observations"`
	ExpiresAt       time.Time       `json:"expires_at"`
}

type EventFilter struct {
	OwnerID, SourceChain, DestChain, Reason string
	MessageIDs                              []string
	Since, Until                            *time.Time
	FromBlock, ToBlock, BeforeID            string
	Limit                                   int
}

type EventPage struct {
	Events        []Event         `json:"events"`
	NextCursor    string          `json:"next_cursor,omitempty"`
	RetainedSince time.Time       `json:"retained_since"`
	Coverage      string          `json:"coverage"`
	Readers       json.RawMessage `json:"readers"`
}

type Operation struct {
	ID           string    `json:"id"`
	OwnerID      string    `json:"owner_id"`
	SourceChain  string    `json:"source_chain_selector"`
	FromBlock    uint64    `json:"from_block,string"`
	ToBlock      uint64    `json:"to_block,string"`
	NextBlock    uint64    `json:"next_block,string"`
	Mode         string    `json:"mode"`
	State        string    `json:"state"`
	ResetApplied bool      `json:"reset_applied"`
	Actor        string    `json:"actor"`
	Note         string    `json:"note"`
	Admitted     int64     `json:"admitted,string"`
	Dropped      int64     `json:"dropped,string"`
	Conflicts    int64     `json:"conflicts,string"`
	Filtered     int64     `json:"filtered,string"`
	Errors       int64     `json:"errors,string"`
	LastError    string    `json:"last_error"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type SubmitRequest struct {
	ID, OwnerID, SourceChain, Mode, Actor, Note string
	FromBlock                                   uint64
	ToBlock                                     *uint64
}
