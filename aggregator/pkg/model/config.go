package model

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
)

// Signer represents a participant in the commit verification process.
type Signer struct {
	Address string `toml:"address"`
}

// SignerIdentifier holds the chain-native signer identifier.
type SignerIdentifier struct {
	Identifier protocol.ByteSlice
}

// DestinationSelector represents a destination chain selector as a string.
type DestinationSelector = string

// SourceSelector represents a source chain selector as a string.
type SourceSelector = string

// ChannelKey identifies a client's aggregation channel for fair scheduling.
type ChannelKey string

// OrphanRecoveryChannelKey is the channel key used for orphan recovery operations.
const OrphanRecoveryChannelKey ChannelKey = "orphan_recovery"

// Committee represents a group of signers participating in the commit verification process.
type Committee struct {
	// QuorumConfigs stores a QuorumConfig for each source chain selector.
	// The aggregator uses this to verify signatures from each chain's
	// commit verifier set.
	// Map structure: source selector -> QuorumConfig
	QuorumConfigs map[SourceSelector]*QuorumConfig `toml:"quorumConfigs"`
	// DestinationVerifiers maps destination chain selectors to their verifier contract addresses.
	DestinationVerifiers map[DestinationSelector]string `toml:"destinationVerifiers"`
	// destinationVerifiersParsed holds the parsed addresses, populated during validation.
	destinationVerifiersParsed map[DestinationSelector]protocol.UnknownAddress
}

func (c *Committee) GetQuorumConfig(sourceChainSelector uint64) (*QuorumConfig, bool) {
	sourceSelectorStr := new(big.Int).SetUint64(sourceChainSelector).String()
	qc, exists := c.QuorumConfigs[sourceSelectorStr]
	return qc, exists
}

func (c *Committee) GetDestinationVerifierAddress(destChainSelector uint64) (protocol.UnknownAddress, bool) {
	destSelectorStr := new(big.Int).SetUint64(destChainSelector).String()
	addr, exists := c.destinationVerifiersParsed[destSelectorStr]
	return addr, exists
}

// QuorumConfig represents the configuration for a quorum of signers.
type QuorumConfig struct {
	SourceVerifierAddress string   `toml:"sourceVerifierAddress"`
	Signers               []Signer `toml:"signers"`
	Threshold             uint8    `toml:"threshold"`
	// sourceVerifierAddressParsed holds the parsed address, populated during validation.
	sourceVerifierAddressParsed protocol.UnknownAddress
}

func (q *QuorumConfig) GetSourceVerifierAddress() protocol.UnknownAddress {
	return q.sourceVerifierAddressParsed
}

// StorageType represents the type of storage backend to use.
type StorageType string

const (
	StorageTypePostgreSQL StorageType = "postgres"
)

// StorageConfig represents the configuration for the storage backend.
type StorageConfig struct {
	StorageType     StorageType   `toml:"type"`
	ConnectionURL   string        `toml:"-"`
	PageSize        int           `toml:"pageSize"`
	MaxOpenConns    int           `toml:"maxOpenConns"`
	MaxIdleConns    int           `toml:"maxIdleConns"`
	ConnMaxLifetime time.Duration `toml:"connMaxLifetime"`
	ConnMaxIdleTime time.Duration `toml:"connMaxIdleTime"`
}

// ServerConfig represents the configuration for the server.
type ServerConfig struct {
	Address string `toml:"address"`
	// RequestTimeout is the max duration for any GRPC request (default: 10s)
	RequestTimeout time.Duration `toml:"requestTimeout"`
	// ConnectionTimeout is the timeout for connection establishment (0 = no timeout, GRPC default)
	ConnectionTimeout time.Duration `toml:"connectionTimeout"`
	// KeepaliveMinTime is the minimum time between client pings (0 = 5 min, GRPC default)
	KeepaliveMinTime time.Duration `toml:"keepaliveMinTime"`
	// KeepaliveTime is the time after which server pings idle clients (0 = 2 hours, GRPC default)
	KeepaliveTime time.Duration `toml:"keepaliveTime"`
	// KeepaliveTimeout is the timeout for ping ack before closing connection (0 = 20s, GRPC default)
	KeepaliveTimeout time.Duration `toml:"keepaliveTimeout"`
	// MaxConnectionAge forces connections to be closed after this duration (0 = infinite, GRPC default)
	MaxConnectionAge time.Duration `toml:"maxConnectionAge"`
	// MaxRecvMsgSizeBytes is the maximum message size in bytes the server can receive (default: 4MB)
	MaxRecvMsgSizeBytes int `toml:"maxRecvMsgSizeBytes"`
	// MaxSendMsgSizeBytes is the maximum message size in bytes the server can send (default: 4MB)
	MaxSendMsgSizeBytes int `toml:"maxSendMsgSizeBytes"`
}

// AggregationConfig represents the configuration for the aggregation system.
type AggregationConfig struct {
	// ChannelBufferSize controls the size of the aggregation request channel buffer
	ChannelBufferSize int `toml:"channelBufferSize"`
	// BackgroundWorkerCount controls the number of background workers processing aggregation requests
	BackgroundWorkerCount int `toml:"backgroundWorkerCount"`
	// CheckAggregationTimeout is the timeout for each check aggregation operation in the write commit verifier node result handler.
	// Consider the batch size when setting this value. A larger batch size will require a longer timeout.
	// Example: "5s", "100ms", "1m"
	CheckAggregationTimeout time.Duration `toml:"checkAggregationTimeout"`
	// OperationTimeout is the timeout for each aggregation operation (0 = no timeout)
	OperationTimeout time.Duration `toml:"operationTimeout"`
}

type OrphanRecoveryConfig struct {
	// Enabled controls whether orphan recovery is enabled
	Enabled bool `toml:"enabled"`
	// Interval controls how often orphan recovery runs
	Interval time.Duration `toml:"interval"`
	// CheckAggregationTimeout is the timeout for each check aggregation operation.
	// Example: "5s", "100ms", "1m"
	CheckAggregationTimeout time.Duration `toml:"checkAggregationTimeout"`
	// MaxAge is the maximum age of orphan records to consider for recovery.
	// Records older than this are filtered out from recovery attempts.
	MaxAge time.Duration `toml:"maxAge"`
	// ScanTimeout is the timeout for each orphan recovery scan (0 = no timeout)
	ScanTimeout time.Duration `toml:"scanTimeout"`
}

type HealthCheckConfig struct {
	Enabled bool   `toml:"enabled"`
	Port    string `toml:"port"`
}

// AnonymousAuthConfig configures the anonymous authentication middleware.
type AnonymousAuthConfig struct {
	// TrustedProxies is a list of CIDR ranges or IPs that are trusted to set
	// X-Forwarded-For and X-Real-IP headers. If empty, proxy headers are never trusted
	// and the peer IP is always used for anonymous callers.
	TrustedProxies []string `toml:"trustedProxies"`
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
func (c *RateLimitingConfig) GetEffectiveLimit(callerID, method string, client auth.ClientConfig) *RateLimitConfig {
	// 1. Check specific caller limit (highest priority)
	if callerLimits, exists := c.Limits[callerID]; exists {
		if limit, exists := callerLimits[method]; exists {
			return &limit
		}
	}

	// 2. Check group limits (most restrictive wins if multiple groups)
	if mostRestrictive := c.getMostRestrictiveGroupLimit(client, method); mostRestrictive != nil {
		return mostRestrictive
	}

	// 3. Fall back to default limit
	if limit, exists := c.DefaultLimits[method]; exists {
		return &limit
	}

	return nil // No limit configured
}

// getMostRestrictiveGroupLimit finds the most restrictive rate limit from all groups the API client belongs to.
func (c *RateLimitingConfig) getMostRestrictiveGroupLimit(client auth.ClientConfig, method string) *RateLimitConfig {
	if client == nil {
		return nil
	}

	var mostRestrictive *RateLimitConfig
	for _, group := range client.GetGroups() {
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

// AggregatorConfig is the root configuration for the pb.
type AggregatorConfig struct {
	AggregatorID                                string               `toml:"aggregatorID"`
	GeneratedConfigPath                         string               `toml:"generatedConfigPath"`
	Committee                                   *Committee           `toml:"committee"`
	Server                                      ServerConfig         `toml:"server"`
	Storage                                     *StorageConfig       `toml:"storage"`
	APIClients                                  []*ClientConfig      `toml:"clients"`
	Aggregation                                 AggregationConfig    `toml:"aggregation"`
	OrphanRecovery                              OrphanRecoveryConfig `toml:"orphanRecovery"`
	RateLimiting                                RateLimitingConfig   `toml:"rateLimiting"`
	HealthCheck                                 HealthCheckConfig    `toml:"healthCheck"`
	AnonymousAuth                               AnonymousAuthConfig  `toml:"anonymousAuth"`
	Monitoring                                  MonitoringConfig     `toml:"monitoring"`
	PyroscopeURL                                string               `toml:"pyroscope_url"`
	MaxMessageIDsPerBatch                       int                  `toml:"maxMessageIDsPerBatch"`
	MaxCommitVerifierNodeResultRequestsPerBatch int                  `toml:"maxCommitVerifierNodeResultRequestsPerBatch"`
}

type APIKeyPairEnv struct {
	APIKeyEnvVar string `toml:"apiKeyEnvVar"`
	SecretEnvVar string `toml:"secretEnvVar"`
}

func (c *APIKeyPairEnv) GetAPIKey() string {
	return os.Getenv(c.APIKeyEnvVar)
}

func (c *APIKeyPairEnv) GetSecret() string {
	return os.Getenv(c.SecretEnvVar)
}

func (c *APIKeyPairEnv) Validate() error {
	if c.APIKeyEnvVar == "" {
		return errors.New("apiKeyEnvVar cannot be empty")
	}
	if c.SecretEnvVar == "" {
		return errors.New("secretEnvVar cannot be empty")
	}

	apiKey, ok := os.LookupEnv(c.APIKeyEnvVar)
	if !ok {
		return fmt.Errorf("environment variable %s not found", c.APIKeyEnvVar)
	}
	if err := hmacutil.ValidateAPIKey(apiKey); err != nil {
		return fmt.Errorf("invalid API key in %s: %w", c.APIKeyEnvVar, err)
	}

	secret, ok := os.LookupEnv(c.SecretEnvVar)
	if !ok {
		return fmt.Errorf("environment variable %s not found", c.SecretEnvVar)
	}
	if err := hmacutil.ValidateSecret(secret); err != nil {
		return fmt.Errorf("invalid secret in %s: %w", c.SecretEnvVar, err)
	}

	return nil
}

type ClientConfig struct {
	APIKeyPairs []*APIKeyPairEnv `toml:"apiKeyPair"`
	Groups      []string         `toml:"groups"`
	Description string           `toml:"description"`
	Enabled     bool             `toml:"enabled"`
	ClientID    string           `toml:"clientId"`
}

func (c *ClientConfig) GetClientID() string { return c.ClientID }
func (c *ClientConfig) GetGroups() []string { return c.Groups }
func (c *ClientConfig) IsEnabled() bool     { return c.Enabled }

func (c *ClientConfig) Validate() error {
	if c.ClientID == "" {
		return errors.New("clientId cannot be empty")
	}
	if len(c.APIKeyPairs) == 0 {
		return errors.New("apiKeyPair cannot be empty")
	}
	for _, apiKeyPair := range c.APIKeyPairs {
		if err := apiKeyPair.Validate(); err != nil {
			return fmt.Errorf("apiKeyPair validation failed for client %s: %w", c.ClientID, err)
		}
	}
	return nil
}

func (c *AggregatorConfig) GetClientByAPIKey(apiKey string) (auth.ClientConfig, auth.APIKeyPair, bool) {
	for _, client := range c.APIClients {
		for _, apiKeyPair := range client.APIKeyPairs {
			if apiKeyPair.GetAPIKey() == apiKey {
				return client, apiKeyPair, true
			}
		}
	}
	return nil, nil, false
}

func (c *AggregatorConfig) GetClientByClientID(clientID string) (auth.ClientConfig, bool) {
	for _, client := range c.APIClients {
		if client.ClientID == clientID {
			return client, true
		}
	}
	return nil, false
}

// SetDefaults sets default values for the configuration.
func (c *AggregatorConfig) SetDefaults() {
	// AggregatorID defaults to hostname if not set
	if c.AggregatorID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}
		c.AggregatorID = hostname
	}
	// Batch verifier result defaults
	if c.MaxMessageIDsPerBatch == 0 {
		c.MaxMessageIDsPerBatch = 100
	}
	if c.MaxCommitVerifierNodeResultRequestsPerBatch == 0 {
		c.MaxCommitVerifierNodeResultRequestsPerBatch = 100
	}
	// Aggregation defaults
	if c.Aggregation.ChannelBufferSize == 0 {
		// Set to 10 by default matching the number of background workers
		c.Aggregation.ChannelBufferSize = 10
	}
	if c.Aggregation.BackgroundWorkerCount == 0 {
		c.Aggregation.BackgroundWorkerCount = 10
	}
	// Default check aggregation timeout: 5 seconds
	if c.Aggregation.CheckAggregationTimeout == 0 {
		c.Aggregation.CheckAggregationTimeout = 5 * time.Second
	}
	// Initialize Storage config if nil
	if c.Storage == nil {
		c.Storage = &StorageConfig{}
	}
	if c.Storage.PageSize == 0 {
		c.Storage.PageSize = 100
	}
	// Database connection pool defaults
	if c.Storage.MaxOpenConns == 0 {
		c.Storage.MaxOpenConns = 25
	}
	if c.Storage.MaxIdleConns == 0 {
		c.Storage.MaxIdleConns = 5
	}
	if c.Storage.ConnMaxLifetime == 0 {
		c.Storage.ConnMaxLifetime = time.Hour
	}
	if c.Storage.ConnMaxIdleTime == 0 {
		c.Storage.ConnMaxIdleTime = 5 * time.Minute
	}
	// Default orphan recovery: enabled with 5 minute interval
	if c.OrphanRecovery.Interval == 0 {
		c.OrphanRecovery.Interval = 5 * time.Minute
	}
	// Default check aggregation timeout: 5 seconds
	if c.OrphanRecovery.CheckAggregationTimeout == 0 {
		c.OrphanRecovery.CheckAggregationTimeout = 5 * time.Second
	}
	// Default max age: 7 days
	if c.OrphanRecovery.MaxAge == 0 {
		c.OrphanRecovery.MaxAge = 168 * time.Hour
	}
	// Health check defaults
	if c.HealthCheck.Port == "" {
		c.HealthCheck.Port = "8080"
	}
	// Server defaults
	if c.Server.RequestTimeout == 0 {
		c.Server.RequestTimeout = 10 * time.Second
	}
}

// ValidateClientConfig validates the client configuration.
func (c *AggregatorConfig) ValidateClientConfig() error {
	// Validate each client configuration
	for _, client := range c.APIClients {
		if err := client.Validate(); err != nil {
			return fmt.Errorf("client validation failed for client %s: %w", client.ClientID, err)
		}
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
	if c.MaxCommitVerifierNodeResultRequestsPerBatch <= 0 {
		return errors.New("maxCommitVerifierNodeResultRequestsPerBatch must be greater than 0")
	}
	if c.MaxCommitVerifierNodeResultRequestsPerBatch > 1000 {
		return errors.New("maxCommitVerifierNodeResultRequestsPerBatch cannot exceed 1000")
	}

	return nil
}

// ValidateServerConfig validates the server configuration.
func (c *AggregatorConfig) ValidateServerConfig() error {
	if c.Server.RequestTimeout <= 0 {
		return errors.New("server.requestTimeout must be greater than 0")
	}
	if c.Server.ConnectionTimeout < 0 {
		return errors.New("server.connectionTimeout cannot be negative")
	}
	if c.Server.KeepaliveMinTime < 0 {
		return errors.New("server.keepaliveMinTime cannot be negative")
	}
	if c.Server.KeepaliveTime < 0 {
		return errors.New("server.keepaliveTime cannot be negative")
	}
	if c.Server.KeepaliveTimeout < 0 {
		return errors.New("server.keepaliveTimeout cannot be negative")
	}
	if c.Server.MaxConnectionAge < 0 {
		return errors.New("server.maxConnectionAge cannot be negative")
	}
	if c.Server.MaxRecvMsgSizeBytes < 0 {
		return errors.New("server.maxRecvMsgSizeBytes cannot be negative")
	}
	if c.Server.MaxRecvMsgSizeBytes > 100*1024*1024 {
		return errors.New("server.maxRecvMsgSizeBytes cannot exceed 100MB")
	}
	if c.Server.MaxSendMsgSizeBytes < 0 {
		return errors.New("server.maxSendMsgSizeBytes cannot be negative")
	}
	if c.Server.MaxSendMsgSizeBytes > 100*1024*1024 {
		return errors.New("server.maxSendMsgSizeBytes cannot exceed 100MB")
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
	if c.Aggregation.OperationTimeout < 0 {
		return errors.New("aggregation.operationTimeout cannot be negative")
	}
	if c.Aggregation.CheckAggregationTimeout <= 0 {
		return errors.New("aggregation.checkAggregationTimeout must be greater than 0")
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
	if c.Storage.MaxOpenConns < 0 {
		return errors.New("storage.maxOpenConns cannot be negative")
	}
	if c.Storage.MaxIdleConns < 0 {
		return errors.New("storage.maxIdleConns cannot be negative")
	}
	if c.Storage.MaxIdleConns > c.Storage.MaxOpenConns {
		return errors.New("storage.maxIdleConns cannot exceed storage.maxOpenConns")
	}
	if c.Storage.ConnMaxLifetime < 0 {
		return errors.New("storage.connMaxLifetime cannot be negative")
	}
	if c.Storage.ConnMaxIdleTime < 0 {
		return errors.New("storage.connMaxIdleTime cannot be negative")
	}

	return nil
}

// ValidateOrphanRecoveryConfig validates the orphan recovery configuration.
func (c *AggregatorConfig) ValidateOrphanRecoveryConfig() error {
	if c.OrphanRecovery.ScanTimeout < 0 {
		return errors.New("orphanRecovery.scanTimeout cannot be negative")
	}
	if c.OrphanRecovery.CheckAggregationTimeout <= 0 {
		return errors.New("orphanRecovery.checkAggregationTimeout must be greater than 0")
	}
	if !c.OrphanRecovery.Enabled {
		return nil
	}
	if c.OrphanRecovery.MaxAge < time.Hour {
		return errors.New("orphanRecovery.maxAge must be at least 1 hour")
	}
	if c.OrphanRecovery.Interval < 5*time.Second {
		return errors.New("orphanRecovery.interval must be at least 5 seconds")
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

	if len(c.Committee.DestinationVerifiers) == 0 {
		return errors.New("committee must have at least one destination verifier")
	}

	// Validate and parse destination verifiers
	c.Committee.destinationVerifiersParsed = make(map[DestinationSelector]protocol.UnknownAddress, len(c.Committee.DestinationVerifiers))
	for destSelector, verifierAddress := range c.Committee.DestinationVerifiers {
		if strings.TrimSpace(destSelector) == "" {
			return errors.New("destination selector cannot be empty")
		}

		if _, err := strconv.ParseUint(destSelector, 10, 64); err != nil {
			return fmt.Errorf("invalid destination selector '%s': must be a valid uint64 decimal string", destSelector)
		}

		if strings.TrimSpace(verifierAddress) == "" {
			return fmt.Errorf("destination verifier address cannot be empty for destination '%s'", destSelector)
		}

		parsedAddr, err := protocol.NewUnknownAddressFromHex(verifierAddress)
		if err != nil {
			return fmt.Errorf("invalid destination verifier address '%s' for destination '%s': %w", verifierAddress, destSelector, err)
		}
		c.Committee.destinationVerifiersParsed[destSelector] = parsedAddr
	}

	// Validate each source configuration
	for sourceSelector, quorumConfig := range c.Committee.QuorumConfigs {
		if strings.TrimSpace(sourceSelector) == "" {
			return errors.New("source selector cannot be empty")
		}

		if _, err := strconv.ParseUint(sourceSelector, 10, 64); err != nil {
			return fmt.Errorf("invalid source selector '%s': must be a valid uint64 decimal string", sourceSelector)
		}

		if quorumConfig == nil {
			return fmt.Errorf("quorum config cannot be nil for source '%s'", sourceSelector)
		}

		if quorumConfig.Threshold == 0 {
			return fmt.Errorf("threshold must be greater than 0 for source '%s'", sourceSelector)
		}

		if len(quorumConfig.Signers) == 0 {
			return fmt.Errorf("must have at least one signer for source '%s'", sourceSelector)
		}

		if int(quorumConfig.Threshold) > len(quorumConfig.Signers) {
			return fmt.Errorf("threshold (%d) cannot exceed number of signers (%d) for source '%s'",
				quorumConfig.Threshold, len(quorumConfig.Signers), sourceSelector)
		}

		// Parse and store the source verifier address
		if strings.TrimSpace(quorumConfig.SourceVerifierAddress) == "" {
			return fmt.Errorf("source verifier address cannot be empty for source '%s'", sourceSelector)
		}
		parsedSourceAddr, err := protocol.NewUnknownAddressFromHex(quorumConfig.SourceVerifierAddress)
		if err != nil {
			return fmt.Errorf("invalid source verifier address '%s' for source '%s': %w", quorumConfig.SourceVerifierAddress, sourceSelector, err)
		}
		quorumConfig.sourceVerifierAddressParsed = parsedSourceAddr

		seenSigners := make(map[string]bool)
		for i, signer := range quorumConfig.Signers {
			if strings.TrimSpace(signer.Address) == "" {
				return fmt.Errorf("signer address cannot be empty at index %d for source '%s'", i, sourceSelector)
			}

			normalizedAddr := strings.ToLower(signer.Address)
			if seenSigners[normalizedAddr] {
				return fmt.Errorf("duplicate signer address '%s' for source '%s'", signer.Address, sourceSelector)
			}
			seenSigners[normalizedAddr] = true
		}
	}

	return nil
}

// Validate validates the aggregator configuration for integrity and correctness.
func (c *AggregatorConfig) Validate() error {
	// Set defaults first
	c.SetDefaults()

	// Validate server configuration
	if err := c.ValidateServerConfig(); err != nil {
		return fmt.Errorf("server configuration error: %w", err)
	}

	// Validate committee configuration
	if err := c.ValidateCommitteeConfig(); err != nil {
		return fmt.Errorf("committee configuration error: %w", err)
	}

	// Validate client configuration
	if err := c.ValidateClientConfig(); err != nil {
		return fmt.Errorf("client configuration error: %w", err)
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

	// Validate orphan recovery configuration
	if err := c.ValidateOrphanRecoveryConfig(); err != nil {
		return fmt.Errorf("orphan recovery configuration error: %w", err)
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

	if c.RateLimiting.Storage.Type == RateLimiterStoreTypeRedis && c.RateLimiting.Enabled {
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
