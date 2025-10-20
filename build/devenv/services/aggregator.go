package services

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const (
	DefaultAggregatorName  = "aggregator"
	DefaultAggregatorImage = "aggregator:dev"
	DefaultAggregatorPort  = 8103

	// DynamoDB constants.
	DefaultAggregatorDynamoDBName  = "aggregator-dynamodb"
	DefaultAggregatorDynamoDBImage = "amazon/dynamodb-local:2.2.1"
	DefaultAggregatorDynamoDBPort  = 8000

	// Redis constants.
	DefaultAggregatorRedisName  = "aggregator-redis"
	DefaultAggregatorRedisImage = "redis:7-alpine"
	DefaultAggregatorRedisPort  = 6379
)

type AggregatorInput struct {
	Image            string                  `toml:"image"`
	Port             int                     `toml:"port"`
	SourceCodePath   string                  `toml:"source_code_path"`
	RootPath         string                  `toml:"root_path"`
	ContainerName    string                  `toml:"container_name"`
	UseCache         bool                    `toml:"use_cache"`
	Out              *AggregatorOutput       `toml:"-"`
	AggregatorConfig *model.AggregatorConfig `toml:"aggregator_config"`
	DynamoDBTables   *DynamoDBTablesConfig   `toml:"dynamodb_tables"`
}

type DynamoDBTablesConfig struct {
	CommitVerificationRecords string `toml:"commit_verification_records"`
	AggregatedReports         string `toml:"aggregated_reports"`
	Checkpoints               string `toml:"checkpoints"`
}

type AggregatorOutput struct {
	UseCache           bool   `toml:"use_cache"`
	ContainerName      string `toml:"container_name"`
	Address            string `toml:"address"`
	DBURL              string `toml:"db_url"`
	DBConnectionString string `toml:"db_connection_string"`
}

type Signer struct {
	ParticipantID string   `toml:"participantID"`
	Addresses     []string `toml:"addresses"`
}

// QuorumConfig represents the configuration for a quorum of signers.
type QuorumConfig struct {
	CommitteeVerifierAddress string   `toml:"committeeVerifierAddress"`
	Signers                  []Signer `toml:"signers"`
	Threshold                uint8    `toml:"threshold"`
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

// StorageConfig represents the configuration for the storage backend.
type StorageConfig struct {
	StorageType   string `toml:"type"`
	ConnectionURL string `toml:"connectionURL,omitempty"`
}

// ServerConfig represents the configuration for the server.
type ServerConfig struct {
	Address string `toml:"address"`
}

func aggregatorDefaults(in *AggregatorInput) {
	if in.Image == "" {
		in.Image = DefaultAggregatorImage
	}
	if in.Port == 0 {
		in.Port = DefaultAggregatorPort
	}
	if in.ContainerName == "" {
		in.ContainerName = DefaultAggregatorName
	}
	if in.DynamoDBTables == nil {
		in.DynamoDBTables = &DynamoDBTablesConfig{
			CommitVerificationRecords: "commit_verification_records",
			AggregatedReports:         "aggregated_reports",
			Checkpoints:               "checkpoint_records",
		}
	}
}

func NewAggregator(in *AggregatorInput) (*AggregatorOutput, error) {
	if in == nil {
		return nil, nil
	}
	if in.Out != nil && in.Out.UseCache {
		return in.Out, nil
	}
	ctx := context.Background()
	aggregatorDefaults(in)
	p, err := CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return in.Out, err
	}

	// Create DynamoDB container using generic container for better control
	dynamoReq := testcontainers.ContainerRequest{
		Image:        "amazon/dynamodb-local:2.2.1",
		Name:         DefaultAggregatorDynamoDBName,
		ExposedPorts: []string{"8000/tcp"},
		Networks:     []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {DefaultAggregatorDynamoDBName},
		},
		Labels: framework.DefaultTCLabels(),
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				"8000/tcp": []nat.PortBinding{
					{HostPort: strconv.Itoa(DefaultAggregatorDynamoDBPort)},
				},
			}
		},
		Cmd: []string{"-jar", "DynamoDBLocal.jar", "-sharedDb"},
		WaitingFor: wait.ForHTTP("/").WithMethod("POST").WithStatusCodeMatcher(func(status int) bool {
			return status == 400
		}),
	}

	dynamoContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: dynamoReq,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create DynamoDB container: %w", err)
	}

	// Allow some time for DynamoDB Local to initialize
	time.Sleep(5 * time.Second)

	// Create Redis container for rate limiting
	redisReq := testcontainers.ContainerRequest{
		Image:        DefaultAggregatorRedisImage,
		Name:         DefaultAggregatorRedisName,
		ExposedPorts: []string{"6379/tcp"},
		Networks:     []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {DefaultAggregatorRedisName},
		},
		Labels: framework.DefaultTCLabels(),
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				"6379/tcp": []nat.PortBinding{
					{HostPort: strconv.Itoa(DefaultAggregatorRedisPort)},
				},
			}
		},
		WaitingFor: wait.ForLog("Ready to accept connections"),
	}

	_, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: redisReq,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis container: %w", err)
	}

	// Get the connection string for localhost access (for table creation)
	host, err := dynamoContainer.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get DynamoDB container host: %w", err)
	}

	port, err := dynamoContainer.MappedPort(ctx, "8000")
	if err != nil {
		return nil, fmt.Errorf("failed to get DynamoDB container port: %w", err)
	}

	connectionString := fmt.Sprintf("http://%s:%s", host, port.Port())

	// Create required DynamoDB tables
	err = createDynamoDBTables(ctx, connectionString, in.DynamoDBTables)
	if err != nil {
		return nil, fmt.Errorf("failed to create DynamoDB tables: %w", err)
	}

	// Set the connection string for the aggregator service (using container network name)
	serviceDBConnectionString := fmt.Sprintf("http://%s:8000", DefaultAggregatorDynamoDBName)

	/* Service */
	req := testcontainers.ContainerRequest{
		Image:    in.Image,
		Name:     in.ContainerName,
		Labels:   framework.DefaultTCLabels(),
		Networks: []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {in.ContainerName},
		},
		// add more internal ports here with /tcp suffix, ex.: 9222/tcp
		ExposedPorts: []string{"50051/tcp"},
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				// add more internal/external pairs here, ex.: 9222/tcp as a key and HostPort is the exposed port (no /tcp prefix!)
				"50051/tcp": []nat.PortBinding{
					{HostPort: strconv.Itoa(in.Port)},
				},
			}
		},
	}

	if in.SourceCodePath != "" {
		req.Mounts = testcontainers.Mounts()
		req.Mounts = append(req.Mounts, GoSourcePathMounts(in.RootPath, AppPathInsideContainer)...)
		req.Mounts = append(req.Mounts, GoCacheMounts()...)
		framework.L.Info().
			Str("Service", in.ContainerName).
			Str("Source", p).Msg("Using source code path, hot-reload mode")
	}

	_, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}
	in.Out = &AggregatorOutput{
		ContainerName:      in.ContainerName,
		Address:            fmt.Sprintf("%s:%d", in.ContainerName, in.Port),
		DBConnectionString: serviceDBConnectionString,
	}
	return in.Out, nil
}

func createDynamoDBTables(ctx context.Context, connectionString string, tableConfig *DynamoDBTablesConfig) error {
	// Create AWS config for DynamoDB Local
	awsConfig, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     "dummy",
				SecretAccessKey: "dummy",
			},
		}),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	ddbClient := dynamodb.NewFromConfig(awsConfig, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String(connectionString)
	})

	// Create the commit verification records table
	err = ddb.CreateCommitVerificationRecordsTable(ctx, ddbClient, tableConfig.CommitVerificationRecords)
	if err != nil {
		return fmt.Errorf("failed to create commit verification records table: %w", err)
	}

	// Create the finalized feed table
	err = ddb.CreateFinalizedFeedTable(ctx, ddbClient, tableConfig.AggregatedReports)
	if err != nil {
		return fmt.Errorf("failed to create finalized feed table: %w", err)
	}

	// Create the checkpoint table
	err = ddb.CreateCheckpointTable(ctx, ddbClient, tableConfig.Checkpoints)
	if err != nil {
		return fmt.Errorf("failed to create checkpoint table: %w", err)
	}

	return nil
}
