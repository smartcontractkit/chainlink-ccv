package canton

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"

	ledgerv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type sourceReader struct {
	stateServiceClient  ledgerv2.StateServiceClient
	updateServiceClient ledgerv2.UpdateServiceClient
	jwt                 string
}

func NewSourceReader(grpcEndpoint, jwt string, opts ...grpc.DialOption) (chainaccess.SourceReader, error) {
	conn, err := grpc.NewClient(grpcEndpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection to canton node: %w", err)
	}

	return &sourceReader{
		stateServiceClient:  ledgerv2.NewStateServiceClient(conn),
		updateServiceClient: ledgerv2.NewUpdateServiceClient(conn),
		jwt:                 jwt,
	}, nil
}

// FetchMessageSentEvents implements chainaccess.SourceReader.
func (c *sourceReader) FetchMessageSentEvents(ctx context.Context, fromBlock, toBlock *big.Int) ([]protocol.MessageSentEvent, error) {
	panic("unimplemented")
}

// GetBlocksHeaders implements chainaccess.SourceReader.
// The blockNumbers passed in are offset numbers, since that's all we ever return from LatestAndFinalizedBlock.
// So there's no need to do a network call here.
func (c *sourceReader) GetBlocksHeaders(ctx context.Context, blockNumbers []*big.Int) (map[*big.Int]protocol.BlockHeader, error) {
	// TODO: should we check that the block number is less than the latest offset?
	latest, _, err := c.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block: %w", err)
	}
	if latest == nil {
		return nil, fmt.Errorf("latest block is nil")
	}

	headers := make(map[*big.Int]protocol.BlockHeader)
	for _, blockNum := range blockNumbers {
		if blockNum.Uint64() > latest.Number {
			return nil, fmt.Errorf("block number is greater than latest offset: %d > %d", blockNum.Uint64(), latest.Number)
		}

		var h protocol.Bytes32
		binary.BigEndian.PutUint64(h[:], blockNum.Uint64())
		headers[blockNum] = protocol.BlockHeader{
			Number: blockNum.Uint64(),
			Hash:   h,
			// TODO
			// ParentHash: protocol.Bytes32{},
			// Timestamp: time.Time{},
		}
	}

	return headers, nil
}

// GetRMNCursedSubjects implements chainaccess.SourceReader.
func (c *sourceReader) GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error) {
	panic("unimplemented")
}

// LatestAndFinalizedBlock returns the latest offset of the canton validator we are connected to.
// The latest "block" on Canton is always finalized.
func (c *sourceReader) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error) {
	md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", c.jwt))
	ctx = metadata.NewOutgoingContext(ctx, md)
	end, err := c.stateServiceClient.GetLedgerEnd(ctx, &ledgerv2.GetLedgerEndRequest{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get ledger end: %w", err)
	}
	offsetUint64 := uint64(end.GetOffset()) //nolint:gosec // offset is always non-negative
	var h protocol.Bytes32
	binary.BigEndian.PutUint64(h[:], offsetUint64)
	return &protocol.BlockHeader{
			Number: offsetUint64,
			Hash:   h,
			// TODO
			// ParentHash: protocol.Bytes32{},
			// Timestamp: time.Time{},
		}, &protocol.BlockHeader{
			Number: offsetUint64,
			Hash:   h,
			// TODO
			// ParentHash: protocol.Bytes32{},
			// Timestamp: time.Time{},
		}, nil
}

var _ chainaccess.SourceReader = (*sourceReader)(nil)
