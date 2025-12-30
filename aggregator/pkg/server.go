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
	"google.golang.org/grpc/keepalive"
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

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	msgdiscoverypb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-discovery/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

// Server represents a gRPC server for the aggregator service.
type Server struct {
	committeepb.UnimplementedCommitteeVerifierServer
	verifierpb.UnimplementedVerifierServer
	msgdiscoverypb.UnimplementedMessageDiscoveryServer

	l                                         logger.SugaredLogger
	config                                    *model.AggregatorConfig
	store                                     common.CommitVerificationStore
	aggregator                                *aggregation.CommitReportAggregator
	recoverer                                 *OrphanRecoverer
	readCommitVerifierNodeResultHandler       *handlers.ReadCommitVerifierNodeResultHandler
	writeCommitVerifierNodeResultHandler      *handlers.WriteCommitVerifierNodeResultHandler
	getMessagesSinceHandler                   *handlers.GetMessagesSinceHandler
	getVerifierResultsForMessageHandler       *handlers.GetVerifierResultsForMessageHandler
	grpcServer                                *grpc.Server
	batchWriteCommitVerifierNodeResultHandler *handlers.BatchWriteCommitVerifierNodeResultHandler
	httpHealthServer                          *health.HTTPHealthServer
	healthManager                             *health.Manager
	runGroup                                  *run.Group
	stopChan                                  chan struct{}
	mu                                        sync.Mutex
	started                                   bool
}

// WriteCommitteeVerifierNodeResult handles requests to write commit verification records.
func (s *Server) WriteCommitteeVerifierNodeResult(ctx context.Context, req *committeepb.WriteCommitteeVerifierNodeResultRequest) (*committeepb.WriteCommitteeVerifierNodeResultResponse, error) {
	return s.writeCommitVerifierNodeResultHandler.Handle(ctx, req)
}

func (s *Server) BatchWriteCommitteeVerifierNodeResult(ctx context.Context, req *committeepb.BatchWriteCommitteeVerifierNodeResultRequest) (*committeepb.BatchWriteCommitteeVerifierNodeResultResponse, error) {
	return s.batchWriteCommitVerifierNodeResultHandler.Handle(ctx, req)
}

// ReadCommitteeVerifierNodeResult handles requests to read commit verification records.
func (s *Server) ReadCommitteeVerifierNodeResult(ctx context.Context, req *committeepb.ReadCommitteeVerifierNodeResultRequest) (*committeepb.ReadCommitteeVerifierNodeResultResponse, error) {
	return s.readCommitVerifierNodeResultHandler.Handle(ctx, req)
}

func (s *Server) GetVerifierResultsForMessage(ctx context.Context, req *verifierpb.GetVerifierResultsForMessageRequest) (*verifierpb.GetVerifierResultsForMessageResponse, error) {
	return s.getVerifierResultsForMessageHandler.Handle(ctx, req)
}

func (s *Server) GetMessagesSince(ctx context.Context, req *msgdiscoverypb.GetMessagesSinceRequest) (*msgdiscoverypb.GetMessagesSinceResponse, error) {
	return s.getMessagesSinceHandler.Handle(ctx, req)
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

	// Start aggregator background worker with cancellable context
	aggregatorCtx, aggregatorCancel := context.WithCancel(context.Background())
	g.Add(func() error {
		s.aggregator.StartBackground(aggregatorCtx)
		<-aggregatorCtx.Done()
		return nil
	}, func(error) {
		aggregatorCancel()
	})

	if s.config.OrphanRecovery.Enabled {
		recovererCtx, recovererCancel := context.WithCancel(context.Background())
		g.Add(func() error {
			return s.recoverer.Start(recovererCtx)
		}, func(error) {
			recovererCancel()
		})
	} else {
		s.l.Info("Orphan recovery is disabled in configuration")
	}

	healthManagerCtx, healthManagerCancel := context.WithCancel(context.Background())
	g.Add(func() error {
		return s.healthManager.StartPeriodicHealthLogging(healthManagerCtx, s.l, time.Minute)
	}, func(error) {
		healthManagerCancel()
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

func createAggregator(storage common.CommitVerificationStore, aggregatedStore common.CommitVerificationAggregatedStore, sink common.Sink, validator aggregation.QuorumValidator, config *model.AggregatorConfig, lggr logger.SugaredLogger, monitoring common.AggregatorMonitoring) *aggregation.CommitReportAggregator {
	return aggregation.NewCommitReportAggregator(storage, aggregatedStore, sink, validator, config, lggr, monitoring)
}

func buildGRPCServerOptions(serverConfig model.ServerConfig) []grpc.ServerOption {
	var opts []grpc.ServerOption

	if serverConfig.ConnectionTimeoutSeconds > 0 {
		opts = append(opts, grpc.ConnectionTimeout(
			time.Duration(serverConfig.ConnectionTimeoutSeconds)*time.Second))
	}

	if serverConfig.KeepaliveMinTimeSeconds > 0 {
		opts = append(opts, grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             time.Duration(serverConfig.KeepaliveMinTimeSeconds) * time.Second,
			PermitWithoutStream: true,
		}))
	}

	if serverConfig.KeepaliveTimeSeconds > 0 || serverConfig.KeepaliveTimeoutSeconds > 0 || serverConfig.MaxConnectionAgeSeconds > 0 {
		params := keepalive.ServerParameters{}
		if serverConfig.KeepaliveTimeSeconds > 0 {
			params.Time = time.Duration(serverConfig.KeepaliveTimeSeconds) * time.Second
		}
		if serverConfig.KeepaliveTimeoutSeconds > 0 {
			params.Timeout = time.Duration(serverConfig.KeepaliveTimeoutSeconds) * time.Second
		}
		if serverConfig.MaxConnectionAgeSeconds > 0 {
			params.MaxConnectionAge = time.Duration(serverConfig.MaxConnectionAgeSeconds) * time.Second
		}
		opts = append(opts, grpc.KeepaliveParams(params))
	}

	if serverConfig.MaxRecvMsgSizeBytes > 0 {
		opts = append(opts, grpc.MaxRecvMsgSize(serverConfig.MaxRecvMsgSizeBytes))
	}

	if serverConfig.MaxSendMsgSizeBytes > 0 {
		opts = append(opts, grpc.MaxSendMsgSize(serverConfig.MaxSendMsgSizeBytes))
	}

	return opts
}

type SignatureAndQuorumValidator interface {
	aggregation.QuorumValidator
	handlers.SignatureValidator
}

// NewServer creates a new aggregator server with the specified logger and configuration.
func NewServer(l logger.SugaredLogger, config *model.AggregatorConfig) *Server {
	if err := config.Validate(); err != nil {
		l.Fatalf("Failed to validate server configuration: %v", err)
	}

	l.Infow("Server configuration loaded",
		"storage_type", config.Storage.StorageType,
		"monitoring_enabled", config.Monitoring.Enabled,
		"rate_limiting_enabled", config.RateLimiting.Enabled,
		"health_check_enabled", config.HealthCheck.Enabled,
		"orphan_recovery_enabled", config.OrphanRecovery.Enabled,
		"aggregation_buffer_size", config.Aggregation.ChannelBufferSize,
		"aggregation_workers", config.Aggregation.BackgroundWorkerCount,
	)

	var aggMonitoring common.AggregatorMonitoring = &monitoring.NoopAggregatorMonitoring{}

	if config.Monitoring.Enabled && config.Monitoring.Type == "beholder" {
		// Setup OTEL Monitoring (via beholder)
		m, err := monitoring.InitMonitoring(l, beholder.Config{
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

	store = storage.WrapWithMetrics(store, aggMonitoring, l)
	validator := quorum.NewQuorumValidator(config, l)

	agg := createAggregator(store, store, store, validator, config, l, aggMonitoring)

	writeCommitVerifierNodeResultHandler := handlers.NewWriteCommitCCVNodeDataHandler(store, agg, l, validator)
	readCommitVerifierNodeResultHandler := handlers.NewReadCommitVerifierNodeResultHandler(store, l)
	getMessagesSinceHandler := handlers.NewGetMessagesSinceHandler(store, config.Committee, l, aggMonitoring)
	getVerifierResultsForMessageHandler := handlers.NewGetVerifierResultsForMessageHandler(store, config.Committee, config.MaxMessageIDsPerBatch, l)
	batchWriteCommitVerifierNodeResultHandler := handlers.NewBatchWriteCommitVerifierNodeResultHandler(writeCommitVerifierNodeResultHandler, config.MaxCommitVerifierNodeResultRequestsPerBatch)

	// Initialize middlewares
	loggingMiddleware := middlewares.NewLoggingMiddleware(l)
	metricsMiddleware := middlewares.NewMetricMiddleware(aggMonitoring)
	scopingMiddleware := middlewares.NewScopingMiddleware()

	// Initialize authentication middlewares
	hmacAuthMiddleware := middlewares.NewHMACAuthMiddleware(&config.APIKeys, l)
	anonymousAuthMiddleware, err := middlewares.NewAnonymousAuthMiddleware(config.AnonymousAuth.TrustedProxies, l)
	if err != nil {
		l.Fatalf("Failed to initialize anonymous auth middleware: %v", err)
	}
	requireAuthMiddleware := middlewares.NewRequireAuthMiddleware(l)

	// Initialize rate limiting middleware
	rateLimitingMiddleware, err := middlewares.NewRateLimitingMiddlewareFromConfig(config.RateLimiting, config.APIKeys, l)
	if err != nil {
		l.Fatalf("Failed to initialize rate limiting middleware: %v", err)
	}

	isVerifierResultAPI := func(callMeta interceptors.CallMeta) bool {
		return callMeta.Service == verifierpb.Verifier_ServiceDesc.ServiceName
	}

	aggMonitoring.Metrics().IncrementPendingAggregationsChannelBuffer(context.Background(), config.Aggregation.ChannelBufferSize) // Pre-increment the buffer size metric
	grpcPanicRecoveryHandler := func(p any) (err error) {
		l.Error("recovered from panic", "panic", p, "stack", debug.Stack())
		return status.Errorf(codes.Internal, "%s", p)
	}

	grpcOpts := buildGRPCServerOptions(config.Server)

	// Build interceptor chain
	interceptorChain := []grpc.UnaryServerInterceptor{
		recovery.UnaryServerInterceptor(recovery.WithRecoveryHandler(grpcPanicRecoveryHandler)),
		scopingMiddleware.Intercept,
		metricsMiddleware.Intercept,
		hmacAuthMiddleware.Intercept,

		// Anonymous auth fallback - only for VerifierResultAPI service when HMAC didn't authenticate
		selector.UnaryServerInterceptor(
			anonymousAuthMiddleware.Intercept,
			selector.MatchFunc(func(ctx context.Context, callMeta interceptors.CallMeta) bool {
				return isVerifierResultAPI(callMeta)
			}),
		),

		// Require authentication for all requests (ensures identity is set)
		requireAuthMiddleware.Intercept,

		// Logging after auth so caller_id is available in logs
		loggingMiddleware.Intercept,

		rateLimitingMiddleware.Intercept,
	}

	// Add request timeout interceptor as first in chain
	timeoutMiddleware := middlewares.NewRequestTimeoutMiddleware(
		time.Duration(config.Server.RequestTimeoutSeconds) * time.Second)
	interceptorChain = append([]grpc.UnaryServerInterceptor{timeoutMiddleware.Intercept}, interceptorChain...)

	grpcOpts = append(grpcOpts, grpc.ChainUnaryInterceptor(interceptorChain...))
	grpcServer := grpc.NewServer(grpcOpts...)

	recoverer := NewOrphanRecoverer(store, agg, config, l, aggMonitoring.Metrics())

	healthManager := health.NewManager()
	healthManager.Register(store)
	healthManager.Register(rateLimitingMiddleware)
	healthManager.Register(agg)
	if config.OrphanRecovery.Enabled {
		healthManager.Register(recoverer)
	}

	var httpHealthServer *health.HTTPHealthServer
	if config.HealthCheck.Enabled {
		httpHealthServer = health.NewHTTPHealthServer(
			healthManager,
			config.HealthCheck.Port,
			l,
		)
	}

	server := &Server{
		l:                                    l,
		config:                               config,
		store:                                store,
		aggregator:                           agg,
		readCommitVerifierNodeResultHandler:  readCommitVerifierNodeResultHandler,
		writeCommitVerifierNodeResultHandler: writeCommitVerifierNodeResultHandler,
		getMessagesSinceHandler:              getMessagesSinceHandler,
		getVerifierResultsForMessageHandler:  getVerifierResultsForMessageHandler,
		batchWriteCommitVerifierNodeResultHandler: batchWriteCommitVerifierNodeResultHandler,
		httpHealthServer: httpHealthServer,
		healthManager:    healthManager,
		grpcServer:       grpcServer,
		recoverer:        recoverer,
		started:          false,
		mu:               sync.Mutex{},
	}
	verifierpb.RegisterVerifierServer(grpcServer, server)
	msgdiscoverypb.RegisterMessageDiscoveryServer(grpcServer, server)
	committeepb.RegisterCommitteeVerifierServer(grpcServer, server)

	if os.Getenv("AGGREGATOR_GRPC_REFLECTION_ENABLED") == "true" {
		reflection.Register(grpcServer)
		l.Info("gRPC reflection enabled")
	}

	return server
}
