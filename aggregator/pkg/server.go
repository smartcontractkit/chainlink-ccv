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

	l                             logger.Logger
	readCommitCCVNodeDataHandler  *handlers.ReadCommitCCVNodeDataHandler
	writeCommitCCVNodeDataHandler *handlers.WriteCommitCCVNodeDataHandler
	getMessagesSinceHandler       *handlers.GetMessagesSinceHandler
	getCCVDataForMessageHandler   *handlers.GetCCVDataForMessageHandler
	grpcServer                    *grpc.Server
	closeChan                     chan struct{}
	mu                            sync.Mutex
	started                       bool
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

	agg, err := createAggregator(store, store)
	if err != nil {
		l.Errorw("failed to create aggregator", "error", err)
		return nil
	}

	readCommitCCVNodeDataHandler := handlers.NewReadCommitCCVNodeDataHandler(store, config.DisableValidation)
	writeCommitCCVNodeDataHandler := handlers.NewWriteCommitCCVNodeDataHandler(store, agg, l, config.DisableValidation)
	getMessagesSinceHandler := handlers.NewGetMessagesSinceHandler(store)
	getCCVDataForMessageHandler := handlers.NewGetCCVDataForMessageHandler(store)

	grpcServer := grpc.NewServer()
	server := &Server{
		l:                             l,
		readCommitCCVNodeDataHandler:  readCommitCCVNodeDataHandler,
		writeCommitCCVNodeDataHandler: writeCommitCCVNodeDataHandler,
		getMessagesSinceHandler:       getMessagesSinceHandler,
		getCCVDataForMessageHandler:   getCCVDataForMessageHandler,
		grpcServer:                    grpcServer,
		started:                       false,
		mu:                            sync.Mutex{},
	}

	aggregator.RegisterCCVDataServer(grpcServer, server)
	aggregator.RegisterAggregatorServer(grpcServer, server)
	reflection.Register(grpcServer)

	return server
}
