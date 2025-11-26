package verifier

const (
	DefaultConfigFile = "/etc/config.toml"
	// ConfirmationDepth is the number of blocks to wait before considering a block finalized.
	// This is used for calculating finalized blocks as: (latest - ConfirmationDepth)
	// when running standalone mode. In CL node it's HeadTracker configuration.
	ConfirmationDepth = 15
)
