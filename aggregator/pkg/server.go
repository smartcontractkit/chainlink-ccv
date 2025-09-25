// Package aggregator provides the main gRPC server implementation for the aggregator service.
package aggregator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/oklog/run"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/aggregation"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/handlers"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/middlewares"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/quorum"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Server represents a gRPC server for the aggregator service.
type Server struct {
	aggregator.UnimplementedAggregatorServer
	aggregator.UnimplementedCCVDataServer

	l                                  logger.Logger
	readCommitCCVNodeDataHandler       *handlers.ReadCommitCCVNodeDataHandler
	writeCommitCCVNodeDataHandler      *handlers.WriteCommitCCVNodeDataHandler
	getMessagesSinceHandler            *handlers.GetMessagesSinceHandler
	getCCVDataForMessageHandler        *handlers.GetCCVDataForMessageHandler
	writeBlockCheckpointHandler        *handlers.WriteBlockCheckpointHandler
	readBlockCheckpointHandler         *handlers.ReadBlockCheckpointHandler
	checkpointStorage                  *storage.CheckpointStorage
	grpcServer                         *grpc.Server
	batchWriteCommitCCVNodeDataHandler *handlers.BatchWriteCommitCCVNodeDataHandler
	runGroup                           *run.Group
	stopChan                           chan struct{}
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
	defer s.mu.Unlock()

	if s.started {
		return fmt.Errorf("server already started")
	}

	s.stopChan = make(chan struct{})

	g := &run.Group{}

	g.Add(func() error {
		s.l.Info("gRPC server started")
		err := s.grpcServer.Serve(lis)
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			s.l.Errorw("gRPC server stopped with error", "error", err)
			return err
		}
		s.l.Info("gRPC server stopped")
		return nil
	}, func(err error) {
		s.l.Info("Shutting down gRPC server")
		s.grpcServer.GracefulStop()
		s.grpcServer.Stop()
	})

	g.Add(func() error {
		<-s.stopChan
		s.l.Info("stop signal received, shutting down")
		return nil
	}, func(error) {})

	g.Add(func() error {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		receivedSig := <-sig
		s.l.Info("received signal, shutting down", "signal", receivedSig)
		return nil
	}, func(error) {})

	s.runGroup = g
	s.started = true

	go func() {
		if err := g.Run(); err != nil {
			s.l.Errorw("Run group stopped with error", "error", err)
		}

		s.mu.Lock()
		s.started = false
		s.runGroup = nil
		if s.stopChan != nil {
			close(s.stopChan)
			s.stopChan = nil
		}
		s.mu.Unlock()
	}()

	return nil
}

func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started || s.stopChan == nil {
		return nil
	}

	s.l.Info("Stopping server gracefully")

	close(s.stopChan)
	s.stopChan = nil

	return nil
}

func createAggregator(storage common.CommitVerificationStore, sink common.Sink, validator aggregation.QuorumValidator, lggr logger.SugaredLogger, monitoring common.AggregatorMonitoring) (handlers.AggregationTriggerer, error) {
	aggregator := aggregation.NewCommitReportAggregator(storage, sink, validator, lggr, monitoring)
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

	var aggMonitoring common.AggregatorMonitoring = &monitoring.NoopAggregatorMonitoring{}

	if config.Monitoring.Enabled {
		// Setup OTEL Monitoring (via beholder)
		m, err := monitoring.InitMonitoring(config, beholder.Config{
			InsecureConnection:       config.Monitoring.Beholder.InsecureConnection,
			CACertFile:               config.Monitoring.Beholder.CACertFile,
			OtelExporterGRPCEndpoint: config.Monitoring.Beholder.OtelExporterGRPCEndpoint,
			OtelExporterHTTPEndpoint: config.Monitoring.Beholder.OtelExporterHTTPEndpoint,
			LogStreamingEnabled:      config.Monitoring.Beholder.LogStreamingEnabled,
			MetricReaderInterval:     time.Duration(config.Monitoring.Beholder.MetricReaderInterval) * time.Second,
			TraceSampleRatio:         config.Monitoring.Beholder.TraceSampleRatio,
			TraceBatchTimeout:        time.Duration(config.Monitoring.Beholder.TraceBatchTimeout) * time.Second,
		})
		if err != nil {
			l.Fatalf("Failed to initialize aggregatorMonitoring monitoring: %v", err)
		}

		aggMonitoring = m
		l.Info("Monitoring enabled")
	}

	if config.Storage.StorageType != "memory" {
		panic("unknown storage type")
	}

	store := storage.WrapWithMetrics(storage.NewInMemoryStorage(), aggMonitoring)

	var validator SignatureAndQuorumValidator
	if config.StubMode {
		validator = quorum.NewStubQuorumValidator()
	} else {
		validator = quorum.NewQuorumValidator(config, l)
	}

	agg, err := createAggregator(store, store, validator, l, aggMonitoring)
	if err != nil {
		l.Errorw("failed to create aggregator", "error", err)
		return nil
	}

	writeHandler := handlers.NewWriteCommitCCVNodeDataHandler(store, agg, l, config.DisableValidation, validator)
	readCommitCCVNodeDataHandler := handlers.NewReadCommitCCVNodeDataHandler(store, config.DisableValidation, l)
	getMessagesSinceHandler := handlers.NewGetMessagesSinceHandler(store, config.Committees, l, aggMonitoring)
	getCCVDataForMessageHandler := handlers.NewGetCCVDataForMessageHandler(store, config.Committees, l)
	batchWriteCommitCCVNodeDataHandler := handlers.NewBatchWriteCommitCCVNodeDataHandler(writeHandler)

	// Initialize checkpoint storage
	checkpointStorage := storage.NewCheckpointStorage()

	// Initialize checkpoint handlers with configuration support
	writeBlockCheckpointHandler := handlers.NewWriteBlockCheckpointHandler(checkpointStorage, &config.APIKeys, &config.Checkpoints)
	readBlockCheckpointHandler := handlers.NewReadBlockCheckpointHandler(checkpointStorage, &config.APIKeys)

	loggingMiddleware := middlewares.NewLoggingMiddleware(l)
	metricsMiddleware := middlewares.NewMetricMiddleware(aggMonitoring)
	scopingMiddleware := middlewares.NewScopingMiddleware()

	aggMonitoring.Metrics().IncrementPendingAggregationsChannelBuffer(context.Background(), 1000) // Pre-increment the buffer size metric
	grpcPanicRecoveryHandler := func(p any) (err error) {
		l.Error("recovered from panic", "panic", p, "stack", debug.Stack())
		return status.Errorf(codes.Internal, "%s", p)
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			recovery.UnaryServerInterceptor(recovery.WithRecoveryHandler(grpcPanicRecoveryHandler)),
			scopingMiddleware.Intercept,
			loggingMiddleware.Intercept,
			metricsMiddleware.Intercept,
		),
	)

	server := &Server{
		l:                                  l,
		readCommitCCVNodeDataHandler:       readCommitCCVNodeDataHandler,
		writeCommitCCVNodeDataHandler:      writeHandler,
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
