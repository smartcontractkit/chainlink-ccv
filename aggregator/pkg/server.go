// Package aggregator provides the main gRPC server implementation for the aggregator service.
package aggregator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/selector"
	"github.com/oklog/run"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/aggregation"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/handlers"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/health"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/middlewares"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/quorum"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// Server represents a gRPC server for the aggregator service.
type Server struct {
	pb.UnimplementedAggregatorServer
	pb.UnimplementedVerifierResultAPIServer

	l                                  logger.Logger
	config                             *model.AggregatorConfig
	store                              common.CommitVerificationStore
	aggregator                         handlers.AggregationTriggerer
	recoverer                          *OrphanRecoverer
	readCommitCCVNodeDataHandler       *handlers.ReadCommitCCVNodeDataHandler
	writeCommitCCVNodeDataHandler      *handlers.WriteCommitCCVNodeDataHandler
	getMessagesSinceHandler            *handlers.GetMessagesSinceHandler
	getCCVDataForMessageHandler        *handlers.GetCCVDataForMessageHandler
	writeChainStatusHandler            *handlers.WriteChainStatusHandler
	readChainStatusHandler             *handlers.ReadChainStatusHandler
	chainStatusStorage                 common.ChainStatusStorageInterface
	grpcServer                         *grpc.Server
	batchWriteCommitCCVNodeDataHandler *handlers.BatchWriteCommitCCVNodeDataHandler
	httpHealthServer                   *health.HTTPHealthServer
	runGroup                           *run.Group
	stopChan                           chan struct{}
	mu                                 sync.Mutex
	started                            bool
}

// WriteCommitCCVNodeData handles requests to write commit verification records.
func (s *Server) WriteCommitCCVNodeData(ctx context.Context, req *pb.WriteCommitCCVNodeDataRequest) (*pb.WriteCommitCCVNodeDataResponse, error) {
	return s.writeCommitCCVNodeDataHandler.Handle(ctx, req)
}

func (s *Server) BatchWriteCommitCCVNodeData(ctx context.Context, req *pb.BatchWriteCommitCCVNodeDataRequest) (*pb.BatchWriteCommitCCVNodeDataResponse, error) {
	return s.batchWriteCommitCCVNodeDataHandler.Handle(ctx, req)
}

// ReadCommitCCVNodeData handles requests to read commit verification records.
func (s *Server) ReadCommitCCVNodeData(ctx context.Context, req *pb.ReadCommitCCVNodeDataRequest) (*pb.ReadCommitCCVNodeDataResponse, error) {
	return s.readCommitCCVNodeDataHandler.Handle(ctx, req)
}

func (s *Server) GetVerifierResultForMessage(ctx context.Context, req *pb.GetVerifierResultForMessageRequest) (*pb.VerifierResult, error) {
	return s.getCCVDataForMessageHandler.Handle(ctx, req)
}

func (s *Server) GetMessagesSince(ctx context.Context, req *pb.GetMessagesSinceRequest) (*pb.GetMessagesSinceResponse, error) {
	return s.getMessagesSinceHandler.Handle(ctx, req)
}

// WriteChainStatus handles requests to write chain statuses.
func (s *Server) WriteChainStatus(ctx context.Context, req *pb.WriteChainStatusRequest) (*pb.WriteChainStatusResponse, error) {
	return s.writeChainStatusHandler.Handle(ctx, req)
}

// ReadChainStatus handles requests to read chain statuses.
func (s *Server) ReadChainStatus(ctx context.Context, req *pb.ReadChainStatusRequest) (*pb.ReadChainStatusResponse, error) {
	return s.readChainStatusHandler.Handle(ctx, req)
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

	ctx, cancel := context.WithCancel(context.Background())
	g.Add(func() error {
		return s.recoverer.Start(ctx)
	}, func(error) {
		cancel()
	})

	if s.httpHealthServer != nil {
		g.Add(func() error {
			if err := s.httpHealthServer.Start(); err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		}, func(error) {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = s.httpHealthServer.Stop(shutdownCtx)
		})
	}

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
	agg := aggregation.NewCommitReportAggregator(storage, sink, validator, lggr, monitoring)
	agg.StartBackground(context.Background())
	return agg, nil
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

	if config.Monitoring.Enabled && config.Monitoring.Type == "beholder" {
		// Setup OTEL Monitoring (via beholder)
		m, err := monitoring.InitMonitoring(beholder.Config{
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

	factory := storage.NewStorageFactory(l)
	store, err := factory.CreateStorage(config.Storage, aggMonitoring)
	if err != nil {
		panic(fmt.Sprintf("failed to create storage: %v", err))
	}

	store = storage.WrapWithMetrics(store, aggMonitoring)

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
	getMessagesSinceHandler := handlers.NewGetMessagesSinceHandler(store, config.Committees, l, aggMonitoring, time.Duration(config.MaxAnonymousGetMessageSinceRange)*time.Second)
	getCCVDataForMessageHandler := handlers.NewGetCCVDataForMessageHandler(store, config.Committees, l)
	batchWriteCommitCCVNodeDataHandler := handlers.NewBatchWriteCommitCCVNodeDataHandler(writeHandler)

	// Initialize chain status storage
	chainStatusStorage, err := factory.CreateChainStatusStorage(config.Storage, aggMonitoring)
	if err != nil {
		panic(fmt.Sprintf("failed to create chain status storage: %v", err))
	}

	chainStatusStorage = storage.WrapChainStatusWithMetrics(chainStatusStorage, aggMonitoring)

	// Initialize chain status handlers
	writeChainStatusHandler := handlers.NewWriteChainStatusHandler(chainStatusStorage)
	readChainStatusHandler := handlers.NewReadChainStatusHandler(chainStatusStorage)

	// Initialize middlewares
	loggingMiddleware := middlewares.NewLoggingMiddleware(l)
	metricsMiddleware := middlewares.NewMetricMiddleware(aggMonitoring)
	scopingMiddleware := middlewares.NewScopingMiddleware()

	// Initialize authentication middlewares
	hmacAuthMiddleware := middlewares.NewHMACAuthMiddleware(&config.APIKeys, l)
	anonymousAuthMiddleware := middlewares.NewAnonymousAuthMiddleware()

	// Initialize rate limiting middleware
	rateLimitingMiddleware, err := middlewares.NewRateLimitingMiddlewareFromConfig(config.RateLimiting, config.APIKeys, l)
	if err != nil {
		l.Fatalf("Failed to initialize rate limiting middleware: %v", err)
	}

	isCCVDataService := func(ctx context.Context, callMeta interceptors.CallMeta) bool {
		return callMeta.Service == pb.VerifierResultAPI_ServiceDesc.ServiceName
	}

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
			hmacAuthMiddleware.Intercept,

			// Anonymous auth fallback - only for CCVData service when HMAC didn't authenticate
			selector.UnaryServerInterceptor(
				anonymousAuthMiddleware.Intercept,
				selector.MatchFunc(isCCVDataService),
			),

			// Require authentication for all requests (ensures identity is set)
			middlewares.RequireAuthInterceptor,

			rateLimitingMiddleware.Intercept,
		),
	)

	recoverer := NewOrphanRecoverer(store, agg, config, l)

	healthManager := health.NewManager()
	healthManager.Register(store)
	healthManager.Register(chainStatusStorage)
	healthManager.Register(rateLimitingMiddleware)
	healthManager.Register(agg)

	var httpHealthServer *health.HTTPHealthServer
	if config.HealthCheck.Enabled {
		httpHealthServer = health.NewHTTPHealthServer(
			healthManager,
			config.HealthCheck.Port,
			l,
		)
	}

	server := &Server{
		l:                                  l,
		config:                             config,
		store:                              store,
		aggregator:                         agg,
		readCommitCCVNodeDataHandler:       readCommitCCVNodeDataHandler,
		writeCommitCCVNodeDataHandler:      writeHandler,
		getMessagesSinceHandler:            getMessagesSinceHandler,
		getCCVDataForMessageHandler:        getCCVDataForMessageHandler,
		writeChainStatusHandler:            writeChainStatusHandler,
		readChainStatusHandler:             readChainStatusHandler,
		chainStatusStorage:                 chainStatusStorage,
		batchWriteCommitCCVNodeDataHandler: batchWriteCommitCCVNodeDataHandler,
		httpHealthServer:                   httpHealthServer,
		grpcServer:                         grpcServer,
		recoverer:                          recoverer,
		started:                            false,
		mu:                                 sync.Mutex{},
	}
	pb.RegisterVerifierResultAPIServer(grpcServer, server)
	pb.RegisterAggregatorServer(grpcServer, server)
	reflection.Register(grpcServer)

	return server
}
