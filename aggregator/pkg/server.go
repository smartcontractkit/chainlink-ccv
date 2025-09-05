// Package aggregator provides the main gRPC server implementation for the aggregator service.
package aggregator

import (
	"context"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/aggregation"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/handlers"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/quorum"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Server represents a gRPC server for the aggregator service.
type Server struct {
	aggregator.UnimplementedAggregatorServer
	aggregator.UnimplementedCCVDataServer

	l                             logger.Logger
	readCommitCCVNodeDataHandler  *handlers.ReadCommitCCVNodeDataHandler
	writeCommitCCVNodeDataHandler *handlers.WriteCommitCCVNodeDataHandler
	getMessagesSinceHandler       *handlers.GetMessagesSinceHandler
	getCCVDataForMessageHandler   *handlers.GetCCVDataForMessageHandler
}

// WriteCommitCCVNodeData handles requests to write commit verification records.
func (s *Server) WriteCommitCCVNodeData(ctx context.Context, req *aggregator.WriteCommitCCVNodeDataRequest) (*aggregator.WriteCommitCCVNodeDataResponse, error) {
	return s.writeCommitCCVNodeDataHandler.Handle(ctx, req)
}

// ReadCommitCCVNodeData handles requests to read commit verification records.
func (s *Server) ReadCommitCCVNodeData(ctx context.Context, req *aggregator.ReadCommitCCVNodeDataRequest) (*aggregator.ReadCommitCCVNodeDataResponse, error) {
	return s.readCommitCCVNodeDataHandler.Handle(ctx, req)
}

func (s *Server) GetCCVDataForMessage(ctx context.Context, req *aggregator.GetCCVDataForMessageRequest) (*aggregator.MessageWithCCVData, error) {
	return s.getCCVDataForMessageHandler.Handle(ctx, req)
}

func (s *Server) GetMessagesSince(ctx context.Context, req *aggregator.GetMessagesSinceRequest) (*aggregator.GetMessagesSinceResponse, error) {
	return s.getMessagesSinceHandler.Handle(ctx, req)
}

// Start starts the gRPC server on the provided listener.
func (s *Server) StartCommitAggregator(lis net.Listener) (func(), error) {
	grpcServer := grpc.NewServer()
	aggregator.RegisterAggregatorServer(grpcServer, s)
	reflection.Register(grpcServer)

	s.l.Info("Aggregator gRPC server started")
	if err := grpcServer.Serve(lis); err != nil {
		return func() {}, err
	}

	return grpcServer.Stop, nil
}

func (s *Server) StartCCVData(lis net.Listener) (func(), error) {
	grpcServer := grpc.NewServer()
	aggregator.RegisterCCVDataServer(grpcServer, s)
	reflection.Register(grpcServer)

	s.l.Info("CCV Data gRPC server started")
	if err := grpcServer.Serve(lis); err != nil {
		return func() {}, err
	}

	return grpcServer.Stop, nil
}

func createAggregator(storage common.CommitVerificationStore, sink common.Sink) (handlers.AggregationTriggerer, error) {
	aggregator := aggregation.NewCommitReportAggregator(storage, sink, &quorum.QuorumValidatorStub{})
	aggregator.StartBackground(context.Background())
	return aggregator, nil
}

// NewServer creates a new aggregator server with the specified logger and configuration.
func NewServer(l logger.Logger, config model.AggregatorConfig) *Server {
	if config.Storage.StorageType != "memory" {
		panic("unknown storage type")
	}

	store := storage.NewInMemoryStorage()

	aggregator, err := createAggregator(store, store)
	if err != nil {
		l.Errorw("failed to create aggregator", "error", err)
		return nil
	}

	readCommitCCVNodeDataHandler := handlers.NewReadCommitCCVNodeDataHandler(store, config.DisableValidation)
	writeCommitCCVNodeDataHandler := handlers.NewWriteCommitCCVNodeDataHandler(store, aggregator, l, config.DisableValidation)
	getMessagesSinceHandler := handlers.NewGetMessagesSinceHandler(store)
	getCCVDataForMessageHandler := handlers.NewGetCCVDataForMessageHandler(store)

	return &Server{
		l:                             l,
		readCommitCCVNodeDataHandler:  readCommitCCVNodeDataHandler,
		writeCommitCCVNodeDataHandler: writeCommitCCVNodeDataHandler,
		getMessagesSinceHandler:       getMessagesSinceHandler,
		getCCVDataForMessageHandler:   getCCVDataForMessageHandler,
	}
}
