// Package aggregator provides the main gRPC server implementation for the aggregator service.
package aggregator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

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

	l                                  logger.Logger
	readCommitCCVNodeDataHandler       handlers.Handler[*aggregator.ReadCommitCCVNodeDataRequest, *aggregator.ReadCommitCCVNodeDataResponse]
	writeCommitCCVNodeDataHandler      handlers.Handler[*aggregator.WriteCommitCCVNodeDataRequest, *aggregator.WriteCommitCCVNodeDataResponse]
	getMessagesSinceHandler            handlers.Handler[*aggregator.GetMessagesSinceRequest, *aggregator.GetMessagesSinceResponse]
	getCCVDataForMessageHandler        handlers.Handler[*aggregator.GetCCVDataForMessageRequest, *aggregator.MessageWithCCVData]
	writeBlockCheckpointHandler        handlers.Handler[*aggregator.WriteBlockCheckpointRequest, *aggregator.WriteBlockCheckpointResponse]
	readBlockCheckpointHandler         handlers.Handler[*aggregator.ReadBlockCheckpointRequest, *aggregator.ReadBlockCheckpointResponse]
	checkpointStorage                  *storage.CheckpointStorage
	grpcServer                         *grpc.Server
	batchWriteCommitCCVNodeDataHandler handlers.Handler[*aggregator.BatchWriteCommitCCVNodeDataRequest, *aggregator.BatchWriteCommitCCVNodeDataResponse]
	closeChan                          chan struct{}
	mu                                 sync.Mutex
	started                            bool
}

// WriteCommitCCVNodeData handles requests to write commit verification records.
func (s *Server) WriteCommitCCVNodeData(ctx context.Context, req *aggregator.WriteCommitCCVNodeDataRequest) (*aggregator.WriteCommitCCVNodeDataResponse, error) {
	return s.writeCommitCCVNodeDataHandler.Handle(ctx, req)
}

func (s *Server) BatchWriteCommitCCVNodeData(ctx context.Context, req *aggregator.BatchWriteCommitCCVNodeDataRequest) (*aggregator.BatchWriteCommitCCVNodeDataResponse, error) {
	return s.batchWriteCommitCCVNodeDataHandler.Handle(ctx, req)
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

// WriteBlockCheckpoint handles requests to write blockchain checkpoints.
func (s *Server) WriteBlockCheckpoint(ctx context.Context, req *aggregator.WriteBlockCheckpointRequest) (*aggregator.WriteBlockCheckpointResponse, error) {
	return s.writeBlockCheckpointHandler.Handle(ctx, req)
}

// ReadBlockCheckpoint handles requests to read blockchain checkpoints.
func (s *Server) ReadBlockCheckpoint(ctx context.Context, req *aggregator.ReadBlockCheckpointRequest) (*aggregator.ReadBlockCheckpointResponse, error) {
	return s.readBlockCheckpointHandler.Handle(ctx, req)
}

func (s *Server) Start(lis net.Listener) error {
	s.mu.Lock()
	if s.closeChan != nil {
		s.mu.Unlock()
		return fmt.Errorf("server already started")
	}
	closeChan := make(chan struct{})
	s.closeChan = closeChan
	s.mu.Unlock()

	go func(closeChan chan struct{}) {
		s.l.Info("gRPC server started")
		err := s.grpcServer.Serve(lis)

		close(closeChan)

		s.mu.Lock()
		if s.closeChan == closeChan {
			s.closeChan = nil
		}
		s.mu.Unlock()

		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			s.l.Errorw("gRPC server stopped with error", "error", err)
		} else {
			s.l.Info("gRPC server stopped")
		}
	}(closeChan)

	return nil
}

func (s *Server) Stop() error {
	s.mu.Lock()
	closeChan := s.closeChan
	s.mu.Unlock()

	if closeChan == nil {
		return nil
	}

	s.grpcServer.GracefulStop()

	select {
	case <-closeChan:
		return nil
	case <-time.After(30 * time.Second):
		s.l.Infow("GracefulStop timeout; forcing Stop")
		s.grpcServer.Stop()
		<-closeChan
		return nil
	}
}

func createAggregator(storage common.CommitVerificationStore, sink common.Sink, validator aggregation.QuorumValidator, lggr logger.SugaredLogger) (handlers.AggregationTriggerer, error) {
	aggregator := aggregation.NewCommitReportAggregator(storage, sink, validator, lggr)
	aggregator.StartBackground(context.Background())
	return aggregator, nil
}

type SignatureAndQuorumValidator interface {
	aggregation.QuorumValidator
	handlers.SignatureValidator
}

// NewServer creates a new aggregator server with the specified logger and configuration.
func NewServer(l logger.SugaredLogger, config *model.AggregatorConfig) *Server {
	// Set defaults for configuration
	config.SetDefaults()

	if config.Storage.StorageType != "memory" {
		panic("unknown storage type")
	}

	store := storage.NewInMemoryStorage()

	var validator SignatureAndQuorumValidator
	if config.StubMode {
		validator = quorum.NewStubQuorumValidator()
	} else {
		validator = quorum.NewQuorumValidator(config, l)
	}

	agg, err := createAggregator(store, store, validator, l)
	if err != nil {
		l.Errorw("failed to create aggregator", "error", err)
		return nil
	}

	writeHandler := handlers.NewWriteCommitCCVNodeDataHandler(store, agg, l, config.DisableValidation, validator)
	readCommitCCVNodeDataHandler := handlers.NewLoggingMiddleware(handlers.NewReadCommitCCVNodeDataHandler(store, config.DisableValidation, l), l)
	writeCommitCCVNodeDataHandler := handlers.NewLoggingMiddleware(writeHandler, l)
	getMessagesSinceHandler := handlers.NewLoggingMiddleware(handlers.NewGetMessagesSinceHandler(store, config.Committees, l), l)
	getCCVDataForMessageHandler := handlers.NewLoggingMiddleware(handlers.NewGetCCVDataForMessageHandler(store, config.Committees, l), l)
	batchWriteCommitCCVNodeDataHandler := handlers.NewLoggingMiddleware(handlers.NewBatchWriteCommitCCVNodeDataHandler(writeHandler), l)

	// Initialize checkpoint storage
	checkpointStorage := storage.NewCheckpointStorage()

	// Initialize checkpoint handlers with configuration support
	writeBlockCheckpointHandler := handlers.NewLoggingMiddleware(
		handlers.NewWriteBlockCheckpointHandler(checkpointStorage, &config.APIKeys, &config.Checkpoints), l)
	readBlockCheckpointHandler := handlers.NewLoggingMiddleware(
		handlers.NewReadBlockCheckpointHandler(checkpointStorage, &config.APIKeys), l)

	grpcServer := grpc.NewServer()
	server := &Server{
		l:                                  l,
		readCommitCCVNodeDataHandler:       readCommitCCVNodeDataHandler,
		writeCommitCCVNodeDataHandler:      writeCommitCCVNodeDataHandler,
		getMessagesSinceHandler:            getMessagesSinceHandler,
		getCCVDataForMessageHandler:        getCCVDataForMessageHandler,
		writeBlockCheckpointHandler:        writeBlockCheckpointHandler,
		readBlockCheckpointHandler:         readBlockCheckpointHandler,
		batchWriteCommitCCVNodeDataHandler: batchWriteCommitCCVNodeDataHandler,
		checkpointStorage:                  checkpointStorage,
		grpcServer:                         grpcServer,
		started:                            false,
		mu:                                 sync.Mutex{},
	}

	aggregator.RegisterCCVDataServer(grpcServer, server)
	aggregator.RegisterAggregatorServer(grpcServer, server)
	reflection.Register(grpcServer)

	return server
}
