package model

// CommitteeID is a type alias for string representing a committee identifier.
type CommitteeID = string

const (
	// DefaultCommitteeID is the default committee ID used when none is specified.
	DefaultCommitteeID CommitteeID = "default"

	CommitteeIDHeader = "committee"
)
