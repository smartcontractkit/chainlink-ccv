package executor

// JobSpec is the specification for an executor job, pushed by JD.
type JobSpec struct {
	ExternalJobID  string `toml:"externalJobID"`
	SchemaVersion  int    `toml:"schemaVersion"`
	Type           string `toml:"type"`
	ExecutorConfig string `toml:"executorConfig"`
}
