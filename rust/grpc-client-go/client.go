// Package grpcclient implements chainaccess.SourceReader over gRPC against a
// Rust ccv-chainaccess-grpc server. It is the Go-side glue that makes the Rust
// implementation a drop-in replacement for the in-process Go EVM SourceReader.
//
// The package holds no state beyond the gRPC connection and is safe for
// concurrent use (gRPC clients are).
package grpcclient

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	pb "github.com/smartcontractkit/chainlink-ccv/rust/grpc-client-go/pb/ccv/chainaccess/v1"
)

// Client implements chainaccess.SourceReader over gRPC.
type Client struct {
	rpc pb.SourceReaderClient
}

var _ chainaccess.SourceReader = (*Client)(nil)

// New returns a chainaccess.SourceReader backed by the given gRPC connection.
func New(conn *grpc.ClientConn) *Client {
	return &Client{rpc: pb.NewSourceReaderClient(conn)}
}

// FetchMessageSentEvents implements chainaccess.SourceReader.
// A nil toBlock queries up to the latest block, exactly like the Go EVM reader.
func (c *Client) FetchMessageSentEvents(ctx context.Context, fromBlock, toBlock *big.Int) ([]protocol.MessageSentEvent, error) {
	from, err := uint64Arg("fromBlock", fromBlock)
	if err != nil {
		return nil, err
	}
	req := &pb.FetchMessageSentEventsRequest{FromBlock: from}
	if toBlock != nil {
		to, err := uint64Arg("toBlock", toBlock)
		if err != nil {
			return nil, err
		}
		req.ToBlock = &to
	}

	resp, err := c.rpc.FetchMessageSentEvents(ctx, req)
	if err != nil {
		return nil, err
	}

	events := make([]protocol.MessageSentEvent, 0, len(resp.Events))
	for _, e := range resp.Events {
		msg, err := protocol.DecodeMessage(e.EncodedMessage)
		if err != nil {
			return nil, fmt.Errorf("server returned an undecodable message (id 0x%x): %w", e.MessageId, err)
		}
		receipts := make([]protocol.ReceiptWithBlob, 0, len(e.Receipts))
		for _, r := range e.Receipts {
			receipts = append(receipts, protocol.ReceiptWithBlob{
				Issuer:            protocol.UnknownAddress(r.Issuer),
				Blob:              r.Blob,
				ExtraArgs:         r.ExtraArgs,
				DestGasLimit:      r.DestGasLimit,
				DestBytesOverhead: r.DestBytesOverhead,
				FeeTokenAmount:    new(big.Int).SetBytes(r.FeeTokenAmount),
			})
		}
		events = append(events, protocol.MessageSentEvent{
			MessageID:   bytes32(e.MessageId),
			Message:     *msg,
			Receipts:    receipts,
			BlockNumber: e.BlockNumber,
			TxHash:      e.TxHash,
		})
	}
	return events, nil
}

// GetBlocksHeaders implements chainaccess.SourceReader.
func (c *Client) GetBlocksHeaders(ctx context.Context, blockNumbers []*big.Int) (map[uint64]protocol.BlockHeader, error) {
	req := &pb.GetBlocksHeadersRequest{BlockNumbers: make([]uint64, 0, len(blockNumbers))}
	for i, bn := range blockNumbers {
		n, err := uint64Arg(fmt.Sprintf("blockNumbers[%d]", i), bn)
		if err != nil {
			return nil, err
		}
		req.BlockNumbers = append(req.BlockNumbers, n)
	}
	resp, err := c.rpc.GetBlocksHeaders(ctx, req)
	if err != nil {
		return nil, err
	}
	headers := make(map[uint64]protocol.BlockHeader, len(resp.Headers))
	for k, v := range resp.Headers {
		headers[k] = pbHeader(v)
	}
	return headers, nil
}

// LatestAndFinalizedBlock implements chainaccess.HeadTracker.
func (c *Client) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error) {
	resp, err := c.rpc.LatestAndFinalizedBlock(ctx, &pb.LatestAndFinalizedBlockRequest{})
	if err != nil {
		return nil, nil, err
	}
	if resp.Latest == nil || resp.Finalized == nil {
		return nil, nil, fmt.Errorf("server returned incomplete heads: latest=%v finalized=%v", resp.Latest != nil, resp.Finalized != nil)
	}
	l, f := pbHeader(resp.Latest), pbHeader(resp.Finalized)
	return &l, &f, nil
}

// LatestSafeBlock implements chainaccess.HeadTracker. Returns nil without an
// error when the chain does not support the safe tag.
func (c *Client) LatestSafeBlock(ctx context.Context) (*protocol.BlockHeader, error) {
	resp, err := c.rpc.LatestSafeBlock(ctx, &pb.LatestSafeBlockRequest{})
	if err != nil {
		return nil, err
	}
	if resp.Safe == nil {
		return nil, nil
	}
	h := pbHeader(resp.Safe)
	return &h, nil
}

// GetRMNCursedSubjects implements chainaccess.RMNCurseReader.
func (c *Client) GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error) {
	resp, err := c.rpc.GetRMNCursedSubjects(ctx, &pb.GetRMNCursedSubjectsRequest{})
	if err != nil {
		return nil, err
	}
	subjects := make([]protocol.Bytes16, 0, len(resp.Subjects))
	for i, s := range resp.Subjects {
		if len(s) != 16 {
			return nil, fmt.Errorf("subject %d must be 16 bytes, got %d", i, len(s))
		}
		subjects = append(subjects, protocol.Bytes16(s))
	}
	return subjects, nil
}

func uint64Arg(name string, v *big.Int) (uint64, error) {
	if v == nil {
		return 0, fmt.Errorf("%s is nil", name)
	}
	if v.Sign() < 0 {
		return 0, fmt.Errorf("%s is negative: %s", name, v)
	}
	if !v.IsUint64() {
		return 0, fmt.Errorf("%s overflows uint64: %s", name, v)
	}
	return v.Uint64(), nil
}

func bytes32(b []byte) (out protocol.Bytes32) {
	// The server guarantees 32 bytes; copy defensively rather than panic.
	copy(out[:], b)
	return out
}

func pbHeader(h *pb.BlockHeader) protocol.BlockHeader {
	return protocol.BlockHeader{
		Number:     h.Number,
		Hash:       bytes32(h.Hash),
		ParentHash: bytes32(h.ParentHash),
		Timestamp:  time.Unix(int64(h.Timestamp), 0).UTC(),
	}
}
