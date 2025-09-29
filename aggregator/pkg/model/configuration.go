package model

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// Signer represents a participant in the commit verification process.
type Signer struct {
	ParticipantID string   `toml:"participantID"`
	Addresses     []string `toml:"addresses"`
}

type IdentifierSigner struct {
	Signer
	Address     []byte
	SignatureR  [32]byte
	SignatureS  [32]byte
	CommitteeID CommitteeID
}

// Committee represents a group of signers participating in the commit verification process.
type Committee struct {
	// QuorumConfigs stores a QuorumConfig for each chain selector
	// there is a commit verifier for.
	// The aggregator uses this to verify signatures from each chain's
	// commit verifier set.
	QuorumConfigs           map[string]*QuorumConfig `toml:"quorumConfigs"`
	SourceVerifierAddresses map[string]string        `toml:"sourceVerifierAddresses"`
}

func (c *Committee) GetSourceVerifierAddress(sourceSelector uint64) (string, bool) {
	address, exists := c.SourceVerifierAddresses[fmt.Sprintf("%d", sourceSelector)]
	return address, exists
}

func (c *Committee) GetQuorumConfig(chainSelector uint64) (*QuorumConfig, bool) {
	selectorStr := new(big.Int).SetUint64(chainSelector).String()
	qc, exists := c.QuorumConfigs[selectorStr]
	return qc, exists
}

func FindQuorumConfigFromSelectorAndSourceVerifierAddress(committees map[CommitteeID]*Committee, sourceSelector, destSelector uint64, sourceVerifierAddress []byte) *QuorumConfig {
	for _, committee := range committees {
		sourceAddress, ok := committee.SourceVerifierAddresses[fmt.Sprintf("%d", sourceSelector)]
		if !ok {
			continue
		}
		if !bytes.Equal(common.HexToAddress(sourceAddress).Bytes(), sourceVerifierAddress) {
			continue
		}

		quorumConfig, exists := committee.GetQuorumConfig(destSelector)
		if !exists {
			continue
		}
		return quorumConfig
	}
	return nil
}

// QuorumConfig represents the configuration for a quorum of signers.
type QuorumConfig struct {
	CommitteeVerifierAddress string   `toml:"committeeVerifierAddress"`
	Signers                  []Signer `toml:"signers"`
	Threshold                uint8    `toml:"threshold"`
}

func (q *QuorumConfig) GetParticipantFromAddress(address []byte) *Signer {
	for _, signer := range q.Signers {
		for _, addr := range signer.Addresses {
			// TODO: Do not use go ethereum common package here
			addrBytes := common.HexToAddress(addr).Bytes()
			if bytes.Equal(addrBytes, address) {
				return &signer
			}
		}
	}
	return nil
}

func (q *QuorumConfig) GetDestVerifierAddressBytes() []byte {
	return common.HexToAddress(q.CommitteeVerifierAddress).Bytes()
}

// StorageType represents the type of storage backend to use.
type StorageType string

const (
	StorageTypeMemory     StorageType = "memory"
	StorageTypePostgreSQL StorageType = "postgres"
)

// StorageConfig represents the configuration for the storage backend.
type StorageConfig struct {
	StorageType   StorageType `toml:"type"`
	ConnectionURL string      `toml:"connectionURL,omitempty"`
}

// ServerConfig represents the configuration for the server.
type ServerConfig struct {
	Address string `toml:"address"`
}

// APIClient represents a configured client for API access.
type APIClient struct {
	ClientID    string `toml:"clientId"`
	Description string `toml:"description,omitempty"`
	Enabled     bool   `toml:"enabled"`
}

// APIKeyConfig represents the configuration for API key management.
type APIKeyConfig struct {
	// Clients maps API keys to client configurations
	Clients map[string]*APIClient `toml:"clients"`
	// MaxAPIKeyLength limits the length of API keys
	MaxAPIKeyLength int `toml:"maxApiKeyLength"`
}

// CheckpointConfig represents the configuration for the checkpoint API.
type CheckpointConfig struct {
	// MaxCheckpointsPerRequest limits the number of checkpoints per write request
	MaxCheckpointsPerRequest int `toml:"maxCheckpointsPerRequest"`
}

// PaginationConfig represents the configuration for pagination in GetMessagesSince API.
type PaginationConfig struct {
	// PageLimit is the maximum number of records returned per page (server-controlled)
	PageLimit int `toml:"pageLimit"`
	// TokenSecret is the secret key used for HMAC signing of pagination tokens
	TokenSecret string `toml:"tokenSecret"`
}

// BeholderConfig wraps the beholder configuration to expose a minimal config for the aggregator.
type BeholderConfig struct {
	// InsecureConnection disables TLS for the beholder client.
	InsecureConnection bool `toml:"insecureConnection"`
	// CACertFile is the path to the CA certificate file for the beholder client.
	CACertFile string `toml:"caCertFile"`
	// OtelExporterGRPCEndpoint is the endpoint for the beholder client to export to the collector.
	OtelExporterGRPCEndpoint string `toml:"otelExporterGRPCEndpoint"`
	// OtelExporterHTTPEndpoint is the endpoint for the beholder client to export to the collector.
	OtelExporterHTTPEndpoint string `toml:"otelExporterHTTPEndpoint"`
	// LogStreamingEnabled enables log streaming to the collector.
	LogStreamingEnabled bool `toml:"logStreamingEnabled"`
	// MetricReaderInterval is the interval to scrape metrics (in seconds).
	MetricReaderInterval int64 `toml:"metricReaderInterval"`
	// TraceSampleRatio is the ratio of traces to sample.
	TraceSampleRatio float64 `toml:"traceSampleRatio"`
	// TraceBatchTimeout is the timeout for a batch of traces.
	TraceBatchTimeout int64 `toml:"traceBatchTimeout"`
}

// MonitoringConfig provides all configuration for the monitoring system inside the aggregator.
type MonitoringConfig struct {
	// Enabled enables the monitoring system.
	Enabled bool `toml:"enabled"`
	// Type is the type of monitoring system to use (beholder, noop).
	Type string `toml:"type"`
	// Beholder is the configuration for the beholder client (Not required if type is noop).
	Beholder BeholderConfig `toml:"beholder"`
}

// GetClientByAPIKey returns the client configuration for a given API key.
func (c *APIKeyConfig) GetClientByAPIKey(apiKey string) (*APIClient, bool) {
	client, exists := c.Clients[apiKey]
	if !exists || !client.Enabled {
		return nil, false
	}
	return client, true
}

// ValidateAPIKey validates an API key against the configuration.
func (c *APIKeyConfig) ValidateAPIKey(apiKey string) error {
	if strings.TrimSpace(apiKey) == "" {
		return errors.New("api key cannot be empty")
	}

	if len(apiKey) > c.MaxAPIKeyLength {
		return fmt.Errorf("api key too long (max %d characters)", c.MaxAPIKeyLength)
	}

	client, exists := c.GetClientByAPIKey(apiKey)
	if !exists {
		return errors.New("invalid or disabled api key")
	}

	if client.ClientID == "" {
		return errors.New("client id cannot be empty")
	}

	return nil
}

// AggregatorConfig is the root configuration for the pb.
type AggregatorConfig struct {
	// CommitteeID are just arbitrary names for different committees this is a concept internal to the aggregator
	Committees        map[CommitteeID]*Committee `toml:"committees"`
	Server            ServerConfig               `toml:"server"`
	Storage           StorageConfig              `toml:"storage"`
	APIKeys           APIKeyConfig               `toml:"apiKeys"`
	Checkpoints       CheckpointConfig           `toml:"checkpoints"`
	Pagination        PaginationConfig           `toml:"pagination"`
	DisableValidation bool                       `toml:"disableValidation"`
	StubMode          bool                       `toml:"stubQuorumValidation"`
	Monitoring        MonitoringConfig           `toml:"monitoring"`
	PyroscopeURL      string                     `toml:"pyroscope_url"`
}

// SetDefaults sets default values for the configuration.
func (c *AggregatorConfig) SetDefaults() {
	if c.Checkpoints.MaxCheckpointsPerRequest == 0 {
		c.Checkpoints.MaxCheckpointsPerRequest = 1000
	}
	if c.APIKeys.MaxAPIKeyLength == 0 {
		c.APIKeys.MaxAPIKeyLength = 1000
	}
	if c.APIKeys.Clients == nil {
		c.APIKeys.Clients = make(map[string]*APIClient)
	}
	if c.Pagination.PageLimit == 0 {
		c.Pagination.PageLimit = 100
	}
}

// ValidateAPIKeyConfig validates the API key configuration.
func (c *AggregatorConfig) ValidateAPIKeyConfig() error {
	if c.APIKeys.MaxAPIKeyLength <= 0 {
		return errors.New("apiKeys.maxApiKeyLength must be greater than 0")
	}

	// Validate each API key configuration
	for apiKey, client := range c.APIKeys.Clients {
		if strings.TrimSpace(apiKey) == "" {
			return errors.New("api key cannot be empty")
		}
		if len(apiKey) > c.APIKeys.MaxAPIKeyLength {
			return fmt.Errorf("api key '%s' exceeds maximum length of %d", apiKey, c.APIKeys.MaxAPIKeyLength)
		}
		if client == nil {
			return fmt.Errorf("client configuration for api key '%s' cannot be nil", apiKey)
		}
		if strings.TrimSpace(client.ClientID) == "" {
			return fmt.Errorf("client id for api key '%s' cannot be empty", apiKey)
		}
	}

	return nil
}

// ValidateCheckpointConfig validates the checkpoint configuration.
func (c *AggregatorConfig) ValidateCheckpointConfig() error {
	if c.Checkpoints.MaxCheckpointsPerRequest <= 0 {
		return errors.New("checkpoints.maxCheckpointsPerRequest must be greater than 0")
	}

	return nil
}

// ValidatePaginationConfig validates the pagination configuration.
func (c *AggregatorConfig) ValidatePaginationConfig() error {
	if c.Pagination.PageLimit <= 0 {
		return errors.New("pagination.pageLimit must be greater than 0")
	}

	if c.Pagination.PageLimit > 10000 {
		return errors.New("pagination.pageLimit must not exceed 10000")
	}

	if strings.TrimSpace(c.Pagination.TokenSecret) == "" {
		return errors.New("pagination.tokenSecret cannot be empty")
	}

	if len(c.Pagination.TokenSecret) < 32 {
		return errors.New("pagination.tokenSecret must be at least 32 bytes long")
	}

	return nil
}

// Validate validates the aggregator configuration for integrity and correctness.
func (c *AggregatorConfig) Validate() error {
	// Set defaults first
	c.SetDefaults()

	// Validate API key configuration
	if err := c.ValidateAPIKeyConfig(); err != nil {
		return fmt.Errorf("api key configuration error: %w", err)
	}

	// Validate checkpoint configuration
	if err := c.ValidateCheckpointConfig(); err != nil {
		return fmt.Errorf("checkpoint configuration error: %w", err)
	}

	// Validate pagination configuration
	if err := c.ValidatePaginationConfig(); err != nil {
		return fmt.Errorf("pagination configuration error: %w", err)
	}

	// TODO: Add other validation logic
	// Should validate:
	// - No duplicate signers within the same QuorumConfig
	// - StorageType is supported (memory, etc.)
	// - AggregationStrategy is supported (stub, etc.)
	// - F value follows N = 3F + 1 rule, so F = (N-1) // 3
	// - Committee names are valid
	// - QuorumConfig chain selectors are valid
	// - Server address format is correct
	// - Offramp address cannot be shared across same chain on different committees
	return nil
}
