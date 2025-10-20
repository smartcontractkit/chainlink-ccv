package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	ccvEvm "github.com/smartcontractkit/chainlink-ccv/ccv-evm"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

type TestingContext struct {
	T                *testing.T
	Ctx              context.Context
	Impl             *ccvEvm.CCIP17EVM
	AggregatorClient *ccv.AggregatorClient
	IndexerClient    *ccv.IndexerClient
	Timeout          time.Duration
}

type VerificationResult struct {
	AggregatedResult     *pb.VerifierResult
	IndexedVerifications ccv.GetVerificationsForMessageIDResponse
}

type VerifyMessageOptions struct {
	TickInterval time.Duration
	Timeout      time.Duration
}

func VerifyMessage(tc TestingContext, messageID [32]byte, opts VerifyMessageOptions) (VerificationResult, error) {
	aggregatedResult, err := tc.AggregatorClient.WaitForVerifierResultForMessage(
		tc.Ctx,
		messageID,
		opts.TickInterval,
		opts.Timeout)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("aggregator check failed: %w", err)
	}

	indexedVerifications, err := tc.IndexerClient.WaitForVerificationsForMessageID(
		tc.Ctx,
		messageID,
		opts.TickInterval,
		opts.Timeout)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("indexer check failed: %w", err)
	}

	return VerificationResult{
		AggregatedResult:     aggregatedResult,
		IndexedVerifications: indexedVerifications,
	}, nil
}
