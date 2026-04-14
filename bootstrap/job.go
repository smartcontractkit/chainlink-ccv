package bootstrap

// JobSpec is the specification for a bootstrap service job, pushed by JD.
type JobSpec struct {
	Name          string `toml:"name"`
	ExternalJobID string `toml:"externalJobID"`
	SchemaVersion int    `toml:"schemaVersion"`
	Type          string `toml:"type"`
	AppConfig     string `toml:"appConfig"`
}
