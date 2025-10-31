package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

var (
	// Global flags.
	apiKey        string
	secret        string
	aggregatorURL string

	// Command-specific flags.
	targetClient    string
	chainSelector   string
	finalizedHeight string
	disabled        bool
)

var rootCmd = &cobra.Command{
	Use:   "admin-cli",
	Short: "Chainlink CCV Aggregator Admin CLI",
	Long: `A command-line interface for interacting with the Chainlink CCV Aggregator Admin API.

This tool allows you to read chain status and perform admin operations like 
overriding chain configurations for specific verifier clients.`,
	Example: `  # Read chain status
  admin-cli read

  # Override chain status for a verifier
  admin-cli write --chain-selector 1 --finalized-height 18500000 --target-client default-verifier-1

  # Disable a chain for a verifier  
  admin-cli write --chain-selector 137 --disabled --target-client default-verifier-2`,
	SilenceUsage: true,
}

var readCmd = &cobra.Command{
	Use:   "read",
	Short: "Read chain status from the aggregator",
	Long: `Read the current chain status from the aggregator.

This command works with any authenticated client and returns the current
finalized block heights for all configured chains.`,
	Example: `  # Read with default credentials
  admin-cli read

  # Read with custom credentials  
  admin-cli read --api-key my-key --secret my-secret`,
	SilenceUsage: true, // Don't show usage on application errors
	RunE: func(cmd *cobra.Command, args []string) error {
		return runReadCommand()
	},
}

var writeCmd = &cobra.Command{
	Use:   "write",
	Short: "Write/override chain status for a verifier",
	Long: `Write or override chain status for a specific verifier client.

This command requires admin privileges (isAdmin: true in server config) and
allows you to set finalized block heights or disable chains for specific verifiers.`,
	Example: `  # Set Ethereum to block 18500000 for default-verifier-1
  admin-cli write --chain-selector 1 --finalized-height 18500000 --target-client default-verifier-1

  # Disable Polygon for default-verifier-2
  admin-cli write --chain-selector 137 --disabled --target-client default-verifier-2`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if chainSelector == "" {
			return fmt.Errorf("--chain-selector is required for write operations")
		}
		if finalizedHeight == "" {
			return fmt.Errorf("--finalized-height is required for write operations")
		}
		return runWriteCommand()
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&apiKey, "api-key", "", "Admin API key")
	rootCmd.PersistentFlags().StringVar(&secret, "secret", "", "Admin secret key")
	rootCmd.PersistentFlags().StringVar(&aggregatorURL, "url", "", "Aggregator gRPC URL")
	rootCmd.PersistentFlags().StringVar(&targetClient, "target-client", "", "Target client ID for admin on-behalf-of operations")

	// Write command flags
	writeCmd.Flags().StringVar(&chainSelector, "chain-selector", "", "Chain selector ID (required)")
	writeCmd.Flags().StringVar(&finalizedHeight, "finalized-height", "", "Finalized block height (required)")
	writeCmd.Flags().BoolVar(&disabled, "disabled", false, "Whether to disable the chain")

	// Mark required flags
	if err := writeCmd.MarkFlagRequired("chain-selector"); err != nil {
		panic(fmt.Sprintf("Failed to mark chain-selector as required: %v", err))
	}
	if err := writeCmd.MarkFlagRequired("finalized-height"); err != nil {
		panic(fmt.Sprintf("Failed to mark finalized-height as required: %v", err))
	}

	// Add commands to root
	rootCmd.AddCommand(readCmd)
	rootCmd.AddCommand(writeCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runReadCommand() error {
	// Connect to the gRPC server
	conn, err := grpc.NewClient(aggregatorURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to aggregator: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close gRPC connection: %v\n", closeErr)
		}
	}()

	client := pb.NewAggregatorClient(conn)
	ctx := context.Background()

	// Create authenticated context
	authCtx, err := createAuthenticatedContextWithOverride(ctx, pb.Aggregator_ReadChainStatus_FullMethodName, &pb.ReadChainStatusRequest{}, targetClient)
	if err != nil {
		return fmt.Errorf("failed to create authenticated context: %w", err)
	}

	// Make the call
	resp, err := client.ReadChainStatus(authCtx, &pb.ReadChainStatusRequest{})
	if err != nil {
		return fmt.Errorf("failed to read chain status: %w", err)
	}

	// Pretty print the response
	output, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	if _, err := fmt.Fprint(os.Stdout, string(output)+"\n"); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	return nil
}

func runWriteCommand() error {
	// Connect to the gRPC server
	conn, err := grpc.NewClient(aggregatorURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to aggregator: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close gRPC connection: %v\n", closeErr)
		}
	}()

	client := pb.NewAggregatorClient(conn)
	ctx := context.Background()

	// Parse chain selector
	chainSelectorInt, err := strconv.ParseUint(chainSelector, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid chain selector '%s': %w", chainSelector, err)
	}

	// Parse finalized height
	finalizedHeightInt, err := strconv.ParseUint(finalizedHeight, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid finalized height '%s': %w", finalizedHeight, err)
	}

	// Create the request
	req := &pb.WriteChainStatusRequest{
		Statuses: []*pb.ChainStatus{
			{
				ChainSelector:        chainSelectorInt,
				FinalizedBlockHeight: finalizedHeightInt,
				Disabled:             disabled,
			},
		},
	}

	// Create authenticated context with admin override
	authCtx, err := createAuthenticatedContextWithOverride(ctx, pb.Aggregator_WriteChainStatus_FullMethodName, req, targetClient)
	if err != nil {
		return fmt.Errorf("failed to create authenticated context: %w", err)
	}

	// Make the call
	resp, err := client.WriteChainStatus(authCtx, req)
	if err != nil {
		return fmt.Errorf("failed to write chain status: %w", err)
	}

	// Pretty print the response
	output, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	if _, err := fmt.Fprint(os.Stdout, string(output)+"\n"); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	return nil
}

func createAuthenticatedContextWithOverride(ctx context.Context, fullMethod string, req any, targetClientID string) (context.Context, error) {
	// Generate timestamp
	timestamp := time.Now().UnixMilli()
	timestampStr := strconv.FormatInt(timestamp, 10)

	// Serialize request body
	body, err := hmac.SerializeRequestBody(req)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize request body: %w", err)
	}

	// Compute body hash
	bodyHash := hmac.ComputeBodyHash(body)

	// Generate string to sign
	stringToSign := hmac.GenerateStringToSign(hmac.HTTPMethodPost, fullMethod, bodyHash, apiKey, timestampStr)

	// Compute HMAC signature
	signature := hmac.ComputeHMAC(secret, stringToSign)

	// Create metadata
	md := metadata.New(map[string]string{
		hmac.HeaderAuthorization: apiKey,
		hmac.HeaderTimestamp:     timestampStr,
		hmac.HeaderSignature:     signature,
	})

	// Add admin override header if specified
	if targetClientID != "" {
		md.Set("x-admin-client-id", targetClientID)
	}

	return metadata.NewOutgoingContext(ctx, md), nil
}
