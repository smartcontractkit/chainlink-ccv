package token

// JobSpec is the specification for a commit verifier job, pushed by JD.
type JobSpec struct {
	ExternalJobID       string `toml:"externalJobID"`
	SchemaVersion       int    `toml:"schemaVersion"`
	Type                string `toml:"type"`
	TokenVerifierConfig string `toml:"tokenVerifierConfig"`
}
