package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// Signer represents a participant in the commit verification process.
type Signer struct {
	Address string `toml:"address"`
}

type IdentifierSigner struct {
	Address    []byte
	SignatureR [32]byte
	SignatureS [32]byte
}

// DestinationSelector represents a destination chain selector as a string.
type DestinationSelector = string

// SourceSelector represents a source chain selector as a string.
type SourceSelector = string

// Committee represents a group of signers participating in the commit verification process.
type Committee struct {
	// QuorumConfigs stores a QuorumConfig for each destination-source chain selector pair.
	// The aggregator uses this to verify signatures from each chain's
	// commit verifier set.
	// Map structure: destination selector -> source selector -> QuorumConfig
	QuorumConfigs map[DestinationSelector]map[SourceSelector]*QuorumConfig `toml:"quorumConfigs"`
}

func (c *Committee) GetQuorumConfig(destChainSelector, sourceChainSelector uint64) (*QuorumConfig, bool) {
	destSelectorStr := new(big.Int).SetUint64(destChainSelector).String()
	sourceSelectorStr := new(big.Int).SetUint64(sourceChainSelector).String()

	sourceConfigs, destExists := c.QuorumConfigs[destSelectorStr]
	if !destExists {
		return nil, false
	}

	qc, sourceExists := sourceConfigs[sourceSelectorStr]
	return qc, sourceExists
}

// QuorumConfig represents the configuration for a quorum of signers.
type QuorumConfig struct {
	DestinationVerifierAddress string   `toml:"destinationVerifierAddress"`
	SourceVerifierAddress      string   `toml:"sourceVerifierAddress"`
	Signers                    []Signer `toml:"signers"`
	Threshold                  uint8    `toml:"threshold"`
}

func (q *QuorumConfig) GetDestVerifierAddressBytes() []byte {
	return common.HexToAddress(q.DestinationVerifierAddress).Bytes()
}

func (q *QuorumConfig) GetSourceVerifierAddressBytes() []byte {
	return common.HexToAddress(q.SourceVerifierAddress).Bytes()
}

// StorageType represents the type of storage backend to use.
type StorageType string

const (
	StorageTypeMemory     StorageType = "memory"
	StorageTypePostgreSQL StorageType = "postgres"
)

// StorageConfig represents the configuration for the storage backend.
type StorageConfig struct {
	StorageType     StorageType `toml:"type"`
	ConnectionURL   string      `toml:"-"`
	PageSize        int         `toml:"pageSize"`
	MaxOpenConns    int         `toml:"maxOpenConns"`
	MaxIdleConns    int         `toml:"maxIdleConns"`
	ConnMaxLifetime int         `toml:"connMaxLifetime"` // in seconds
	ConnMaxIdleTime int         `toml:"connMaxIdleTime"` // in seconds
}

// ServerConfig represents the configuration for the server.
type ServerConfig struct {
	Address string `toml:"address"`
}

// APIClient represents a configured client for API access.
type APIClient struct {
	ClientID    string            `toml:"clientId"`
	Description string            `toml:"description,omitempty"`
	Enabled     bool              `toml:"enabled"`
	IsAdmin     bool              `toml:"isAdmin,omitempty"`
	Secrets     map[string]string `toml:"secrets,omitempty"`
	Groups      []string          `toml:"groups,omitempty"`
}

// APIKeyConfig represents the configuration for API key management.
type APIKeyConfig struct {
	// Clients maps API keys to client configurations
	Clients map[string]*APIClient `toml:"clients"`
}

// ChainStatusConfig represents the configuration for the chain status API.
type ChainStatusConfig struct {
	// MaxChainStatusesPerRequest limits the number of chain statuses per write request
	MaxChainStatusesPerRequest int `toml:"maxChainStatusesPerRequest"`
}

// AggregationConfig represents the configuration for the aggregation system.
type AggregationConfig struct {
	// ChannelBufferSize controls the size of the aggregation request channel buffer
	ChannelBufferSize int `toml:"channelBufferSize"`
	// BackgroundWorkerCount controls the number of background workers processing aggregation requests
	BackgroundWorkerCount int `toml:"backgroundWorkerCount"`
}

type OrphanRecoveryConfig struct {
	// Enabled controls whether orphan recovery is enabled
	Enabled bool `toml:"enabled"`
	// IntervalSeconds controls how often orphan recovery runs (in seconds)
	IntervalSeconds int `toml:"intervalSeconds"`
}

type HealthCheckConfig struct {
	Enabled bool   `toml:"enabled"`
	Port    string `toml:"port"`
}

// RateLimitConfig defines the rate limit for a specific method.
type RateLimitConfig struct {
	// LimitPerMinute is the number of requests allowed per minute
	LimitPerMinute int `toml:"limit_per_minute"`
}

// RateLimiterStoreType defines the supported storage types for rate limiting.
type RateLimiterStoreType string

const (
	RateLimiterStoreTypeMemory RateLimiterStoreType = "memory"
	RateLimiterStoreTypeRedis  RateLimiterStoreType = "redis"
)

const (
	DefaultRateLimiterRedisKeyPrefix = "ratelimit"
)

// IsValid returns true if the RateLimiterStoreType is a valid enum value.
func (t RateLimiterStoreType) IsValid() bool {
	switch t {
	case RateLimiterStoreTypeMemory, RateLimiterStoreTypeRedis:
		return true
	default:
		return false
	}
}

// RateLimiterRedisConfig defines Redis-specific configuration for rate limiting.
type RateLimiterRedisConfig struct {
	Address  string `toml:"-"`
	Password string `toml:"-"`
	DB       int    `toml:"-"`
	// Prefix for Redis keys (default: "ratelimit")
	KeyPrefix string `toml:"key_prefix"`
}

// RateLimiterMemoryConfig defines memory-specific configuration for rate limiting.
// Currently empty but can be extended in the future.
type RateLimiterMemoryConfig struct {
	// Future memory-specific configurations can go here
}

// RateLimiterStoreConfig defines the configuration for rate limiter storage.
type RateLimiterStoreConfig struct {
	// Type of storage: "memory" or "redis"
	Type RateLimiterStoreType `toml:"type"`

	// Redis configuration (only used when Type is "redis")
	Redis *RateLimiterRedisConfig `toml:"redis,omitempty"`
}

// RateLimitingConfig is the top-level configuration for rate limiting.
type RateLimitingConfig struct {
	// Enabled controls whether rate limiting is active
	Enabled bool `toml:"enabled"`

	// Storage configuration
	Storage RateLimiterStoreConfig `toml:"storage"`

	// Limits defines per-caller, per-method rate limits
	// Map structure: callerID -> method -> RateLimitConfig
	Limits map[string]map[string]RateLimitConfig `toml:"limits"`

	// GroupLimits defines per-group, per-method rate limits
	// Map structure: groupName -> method -> RateLimitConfig
	GroupLimits map[string]map[string]RateLimitConfig `toml:"groupLimits"`

	// DefaultLimits defines fallback rate limits when no specific caller or group limits exist
	// Map structure: method -> RateLimitConfig
	DefaultLimits map[string]RateLimitConfig `toml:"defaultLimits"`
}

// GetEffectiveLimit resolves the effective rate limit for a given caller and method.
// Priority order: 1) Specific caller limit, 2) Group limits (most restrictive), 3) Default limit.
func (c *RateLimitingConfig) GetEffectiveLimit(callerID, method string, apiClient *APIClient) *RateLimitConfig {
	// 1. Check specific caller limit (highest priority)
	if callerLimits, exists := c.Limits[callerID]; exists {
		if limit, exists := callerLimits[method]; exists {
			return &limit
		}
	}

	// 2. Check group limits (most restrictive wins if multiple groups)
	if mostRestrictive := c.getMostRestrictiveGroupLimit(apiClient, method); mostRestrictive != nil {
		return mostRestrictive
	}

	// 3. Fall back to default limit
	if limit, exists := c.DefaultLimits[method]; exists {
		return &limit
	}

	return nil // No limit configured
}

// getMostRestrictiveGroupLimit finds the most restrictive rate limit from all groups the API client belongs to.
func (c *RateLimitingConfig) getMostRestrictiveGroupLimit(apiClient *APIClient, method string) *RateLimitConfig {
	if apiClient == nil {
		return nil
	}

	var mostRestrictive *RateLimitConfig
	for _, group := range apiClient.Groups {
		if groupLimits, exists := c.GroupLimits[group]; exists {
			if limit, exists := groupLimits[method]; exists {
				if mostRestrictive == nil || limit.LimitPerMinute < mostRestrictive.LimitPerMinute {
					mostRestrictive = &limit
				}
			}
		}
	}
	return mostRestrictive
}

// MonitoringConfig provides monitoring configuration for aggregator.
type MonitoringConfig struct {
	// Enabled enables the monitoring system.
	Enabled bool `toml:"Enabled"`
	// Type is the type of monitoring system to use (beholder, noop).
	Type string `toml:"Type"`
	// Beholder is the configuration for the beholder client (Not required if type is noop).
	Beholder BeholderConfig `toml:"Beholder"`
}

// BeholderConfig wraps OpenTelemetry configuration for the beholder client.
type BeholderConfig struct {
	// InsecureConnection disables TLS for the beholder client.
	InsecureConnection bool `toml:"InsecureConnection"`
	// CACertFile is the path to the CA certificate file for the beholder client.
	CACertFile string `toml:"CACertFile"`
	// OtelExporterGRPCEndpoint is the endpoint for the beholder client to export to the collector.
	OtelExporterGRPCEndpoint string `toml:"OtelExporterGRPCEndpoint"`
	// OtelExporterHTTPEndpoint is the endpoint for the beholder client to export to the collector.
	OtelExporterHTTPEndpoint string `toml:"OtelExporterHTTPEndpoint"`
	// LogStreamingEnabled enables log streaming to the collector.
	LogStreamingEnabled bool `toml:"LogStreamingEnabled"`
	// MetricReaderInterval is the interval to scrape metrics (in seconds).
	MetricReaderInterval int64 `toml:"MetricReaderInterval"`
	// TraceSampleRatio is the ratio of traces to sample.
	TraceSampleRatio float64 `toml:"TraceSampleRatio"`
	// TraceBatchTimeout is the timeout for a batch of traces.
	TraceBatchTimeout int64 `toml:"TraceBatchTimeout"`
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
	Committee             *Committee           `toml:"committee"`
	Server                ServerConfig         `toml:"server"`
	Storage               *StorageConfig       `toml:"storage"`
	APIKeys               APIKeyConfig         `toml:"-"`
	ChainStatuses         ChainStatusConfig    `toml:"chainStatuses"`
	Aggregation           AggregationConfig    `toml:"aggregation"`
	OrphanRecovery        OrphanRecoveryConfig `toml:"orphanRecovery"`
	RateLimiting          RateLimitingConfig   `toml:"rateLimiting"`
	HealthCheck           HealthCheckConfig    `toml:"healthCheck"`
	StubMode              bool                 `toml:"stubQuorumValidation"`
	Monitoring            MonitoringConfig     `toml:"monitoring"`
	PyroscopeURL          string               `toml:"pyroscope_url"`
	MaxMessageIDsPerBatch int                  `toml:"maxMessageIDsPerBatch"`
}

// SetDefaults sets default values for the configuration.
func (c *AggregatorConfig) SetDefaults() {
	if c.ChainStatuses.MaxChainStatusesPerRequest == 0 {
		c.ChainStatuses.MaxChainStatusesPerRequest = 1000
	}
	// Batch verifier result defaults
	if c.MaxMessageIDsPerBatch == 0 {
		c.MaxMessageIDsPerBatch = 100
	}
	// Aggregation defaults
	if c.Aggregation.ChannelBufferSize == 0 {
		// Set to 10 by default matching the number of background workers
		c.Aggregation.ChannelBufferSize = 10
	}
	if c.Aggregation.BackgroundWorkerCount == 0 {
		c.Aggregation.BackgroundWorkerCount = 10
	}
	// Initialize Storage config if nil
	if c.Storage == nil {
		c.Storage = &StorageConfig{}
	}
	if c.Storage.PageSize == 0 {
		c.Storage.PageSize = 100
	}
	if c.APIKeys.Clients == nil {
		c.APIKeys.Clients = make(map[string]*APIClient)
	}
	// Default orphan recovery: enabled with 5 minute interval
	if c.OrphanRecovery.IntervalSeconds == 0 {
		c.OrphanRecovery.IntervalSeconds = 300 // 5 minutes
	}
	// Default orphan recovery enabled unless explicitly disabled
	if !c.OrphanRecovery.Enabled && c.OrphanRecovery.IntervalSeconds > 0 {
		c.OrphanRecovery.Enabled = true
	}
	// Health check defaults
	if c.HealthCheck.Port == "" {
		c.HealthCheck.Port = "8080"
	}
}

// ValidateAPIKeyConfig validates the API key configuration.
func (c *AggregatorConfig) ValidateAPIKeyConfig() error {
	// Validate each API key configuration
	for apiKey, client := range c.APIKeys.Clients {
		if strings.TrimSpace(apiKey) == "" {
			return errors.New("api key cannot be empty")
		}
		if client == nil {
			return fmt.Errorf("client configuration for api key '%s' cannot be nil", apiKey)
		}
		if strings.TrimSpace(client.ClientID) == "" {
			return fmt.Errorf("client id for api key '%s' cannot be empty", apiKey)
		}

		// Validate group references
		for _, group := range client.Groups {
			if strings.TrimSpace(group) == "" {
				return fmt.Errorf("empty group name for client '%s'", client.ClientID)
			}
			if _, exists := c.RateLimiting.GroupLimits[group]; !exists {
				return fmt.Errorf("client '%s' references undefined group '%s'", client.ClientID, group)
			}
		}
	}

	return nil
}

// ValidateChainStatusConfig validates the chain status configuration.
func (c *AggregatorConfig) ValidateChainStatusConfig() error {
	if c.ChainStatuses.MaxChainStatusesPerRequest <= 0 {
		return errors.New("chainStatuses.maxChainStatusesPerRequest must be greater than 0")
	}

	return nil
}

// ValidateBatchConfig validates the batch verifier result configuration.
func (c *AggregatorConfig) ValidateBatchConfig() error {
	if c.MaxMessageIDsPerBatch <= 0 {
		return errors.New("maxMessageIDsPerBatch must be greater than 0")
	}
	if c.MaxMessageIDsPerBatch > 1000 {
		return errors.New("maxMessageIDsPerBatch cannot exceed 1000")
	}

	return nil
}

// ValidateAggregationConfig validates the aggregation configuration.
func (c *AggregatorConfig) ValidateAggregationConfig() error {
	if c.Aggregation.ChannelBufferSize <= 0 {
		return errors.New("aggregation.channelBufferSize must be greater than 0")
	}
	if c.Aggregation.ChannelBufferSize > 100000 {
		return errors.New("aggregation.channelBufferSize cannot exceed 100000")
	}
	if c.Aggregation.BackgroundWorkerCount <= 0 {
		return errors.New("aggregation.backgroundWorkerCount must be greater than 0")
	}
	if c.Aggregation.BackgroundWorkerCount > 100 {
		return errors.New("aggregation.backgroundWorkerCount cannot exceed 100")
	}

	return nil
}

// ValidateStorageConfig validates the storage configuration.
func (c *AggregatorConfig) ValidateStorageConfig() error {
	if c.Storage.PageSize <= 0 {
		return errors.New("storage.pageSize must be greater than 0")
	}
	if c.Storage.PageSize > 1000 {
		return errors.New("storage.pageSize cannot exceed 1000")
	}

	return nil
}

// ValidateCommitteeConfig validates the committee configuration.
func (c *AggregatorConfig) ValidateCommitteeConfig() error {
	if c.Committee == nil {
		return errors.New("committee configuration cannot be nil")
	}

	if len(c.Committee.QuorumConfigs) == 0 {
		return errors.New("committee must have at least one quorum configuration")
	}

	// Validate each destination's source configurations
	for destSelector, sourceConfigs := range c.Committee.QuorumConfigs {
		if strings.TrimSpace(destSelector) == "" {
			return errors.New("destination selector cannot be empty")
		}

		// Validate destination selector is a valid uint64 string
		if _, err := strconv.ParseUint(destSelector, 10, 64); err != nil {
			return fmt.Errorf("invalid destination selector '%s': must be a valid uint64 decimal string", destSelector)
		}

		if len(sourceConfigs) == 0 {
			return fmt.Errorf("destination selector '%s' has no source configurations", destSelector)
		}

		// Validate each source configuration
		for sourceSelector, quorumConfig := range sourceConfigs {
			if strings.TrimSpace(sourceSelector) == "" {
				return fmt.Errorf("source selector cannot be empty for destination '%s'", destSelector)
			}

			// Validate source selector is a valid uint64 string
			if _, err := strconv.ParseUint(sourceSelector, 10, 64); err != nil {
				return fmt.Errorf("invalid source selector '%s' for destination '%s': must be a valid uint64 decimal string", sourceSelector, destSelector)
			}

			// Validate that source and destination selectors are not the same
			if sourceSelector == destSelector {
				return fmt.Errorf("source selector and destination selector cannot be the same: '%s'", sourceSelector)
			}

			if quorumConfig == nil {
				return fmt.Errorf("quorum config cannot be nil for destination '%s', source '%s'", destSelector, sourceSelector)
			}

			// Validate quorum config
			if quorumConfig.Threshold == 0 {
				return fmt.Errorf("threshold must be greater than 0 for destination '%s', source '%s'", destSelector, sourceSelector)
			}

			if len(quorumConfig.Signers) == 0 {
				return fmt.Errorf("must have at least one signer for destination '%s', source '%s'", destSelector, sourceSelector)
			}

			if int(quorumConfig.Threshold) > len(quorumConfig.Signers) {
				return fmt.Errorf("threshold (%d) cannot exceed number of signers (%d) for destination '%s', source '%s'",
					quorumConfig.Threshold, len(quorumConfig.Signers), destSelector, sourceSelector)
			}

			// Validate CommitteeVerifierAddress is a valid hex address
			if strings.TrimSpace(quorumConfig.DestinationVerifierAddress) == "" {
				return fmt.Errorf("committee verifier address cannot be empty for destination '%s', source '%s'", destSelector, sourceSelector)
			}

			// Validate no duplicate signers within this quorum
			seenSigners := make(map[string]bool)
			for i, signer := range quorumConfig.Signers {
				if strings.TrimSpace(signer.Address) == "" {
					return fmt.Errorf("signer address cannot be empty at index %d for destination '%s', source '%s'", i, destSelector, sourceSelector)
				}

				normalizedAddr := strings.ToLower(signer.Address)
				if seenSigners[normalizedAddr] {
					return fmt.Errorf("duplicate signer address '%s' for destination '%s', source '%s'", signer.Address, destSelector, sourceSelector)
				}
				seenSigners[normalizedAddr] = true
			}
		}
	}

	return nil
}

// Validate validates the aggregator configuration for integrity and correctness.
func (c *AggregatorConfig) Validate() error {
	// Set defaults first
	c.SetDefaults()

	// Validate committee configuration
	if err := c.ValidateCommitteeConfig(); err != nil {
		return fmt.Errorf("committee configuration error: %w", err)
	}

	// Validate API key configuration
	if err := c.ValidateAPIKeyConfig(); err != nil {
		return fmt.Errorf("api key configuration error: %w", err)
	}

	// Validate chain status configuration
	if err := c.ValidateChainStatusConfig(); err != nil {
		return fmt.Errorf("chain status configuration error: %w", err)
	}

	// Validate batch configuration
	if err := c.ValidateBatchConfig(); err != nil {
		return fmt.Errorf("batch configuration error: %w", err)
	}

	// Validate aggregation configuration
	if err := c.ValidateAggregationConfig(); err != nil {
		return fmt.Errorf("aggregation configuration error: %w", err)
	}

	// Validate storage configuration
	if err := c.ValidateStorageConfig(); err != nil {
		return fmt.Errorf("storage configuration error: %w", err)
	}

	return nil
}

func (c *AggregatorConfig) LoadFromEnvironment() error {
	if c.Storage.StorageType == StorageTypePostgreSQL {
		storageURL := os.Getenv("AGGREGATOR_STORAGE_CONNECTION_URL")
		if storageURL == "" {
			return errors.New("AGGREGATOR_STORAGE_CONNECTION_URL environment variable is required")
		}
		c.Storage.ConnectionURL = storageURL
	}

	apiKeysJSON := os.Getenv("AGGREGATOR_API_KEYS_JSON")
	if apiKeysJSON == "" {
		return errors.New("AGGREGATOR_API_KEYS_JSON environment variable is required")
	}

	var apiKeyConfig APIKeyConfig
	if err := json.Unmarshal([]byte(apiKeysJSON), &apiKeyConfig); err != nil {
		return fmt.Errorf("failed to parse AGGREGATOR_API_KEYS_JSON: %w", err)
	}
	c.APIKeys = apiKeyConfig

	if c.RateLimiting.Storage.Type == RateLimiterStoreTypeRedis {
		if err := c.loadRateLimiterRedisConfigFromEnvironment(); err != nil {
			return fmt.Errorf("failed to load rate limiter redis config from environment: %w", err)
		}
	}

	return nil
}

func (c *AggregatorConfig) loadRateLimiterRedisConfigFromEnvironment() error {
	redisAddress := os.Getenv("AGGREGATOR_REDIS_ADDRESS")
	if redisAddress == "" {
		return errors.New("AGGREGATOR_REDIS_ADDRESS environment variable is required")
	}
	if c.RateLimiting.Storage.Redis == nil {
		c.RateLimiting.Storage.Redis = &RateLimiterRedisConfig{}
	}
	c.RateLimiting.Storage.Redis.Address = redisAddress

	redisPassword := os.Getenv("AGGREGATOR_REDIS_PASSWORD")
	c.RateLimiting.Storage.Redis.Password = redisPassword

	redisDBStr := os.Getenv("AGGREGATOR_REDIS_DB")
	if redisDBStr != "" {
		redisDB, err := strconv.Atoi(redisDBStr)
		if err != nil {
			return fmt.Errorf("invalid AGGREGATOR_REDIS_DB value: %w", err)
		}
		c.RateLimiting.Storage.Redis.DB = redisDB
	}
	return nil
}
