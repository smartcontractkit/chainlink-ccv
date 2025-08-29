package aggregator

import (
	"context"
	"fmt"
	"net"

	"github.com/rs/zerolog"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/aggregation"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/handlers"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/interfaces"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type server struct {
	aggregator.UnimplementedAggregatorServer

	l                                    zerolog.Logger
	readCommitVerificationRecordHandler  *handlers.ReadCommitVerificationRecordHandler
	writeCommitVerificationRecordHandler *handlers.WriteCommitVerificationRecordHandler
}

func (s *server) WriteCommitVerification(ctx context.Context, req *aggregator.WriteCommitVerificationRequest) (*aggregator.WriteCommitVerificationResponse, error) {
	return s.writeCommitVerificationRecordHandler.Handle(ctx, req)
}

func (s *server) ReadCommitVerification(ctx context.Context, req *aggregator.ReadCommitVerificationRequest) (*aggregator.ReadCommitVerificationResponse, error) {
	return s.readCommitVerificationRecordHandler.Handle(ctx, req)
}

func (s *server) Start(lis net.Listener) (func(), error) {
	grpcServer := grpc.NewServer()
	aggregator.RegisterAggregatorServer(grpcServer, s)

	reflection.Register(grpcServer)

	s.l.Info().Msg("Aggregator gRPC server started")
	if err := grpcServer.Serve(lis); err != nil {
		return func() {}, err
	}

	return grpcServer.Stop, nil
}

func createAggregatorConfig(storage interfaces.CommitVerificationStore, config model.AggregatorConfig) (handlers.AggregationTriggerer, error) {
	switch config.Aggregation.AggregationStrategy {
	case "stub":
		aggregator := aggregation.NewCommitReportAggregator(storage, &aggregation.AggregatorSinkStub{}, config)
		aggregator.StartBackground(context.Background())
		return aggregator, nil
	}

	return nil, fmt.Errorf("unknown aggregation strategy: %s", config.Aggregation.AggregationStrategy)
}

func createStorage(config model.AggregatorConfig) (interfaces.CommitVerificationStore, error) {
	switch config.Storage.StorageType {
	case "memory":
		return storage.NewInMemoryStorage(), nil
	}

	return nil, fmt.Errorf("unknown storage type: %s", config.Storage.StorageType)
}

func NewServer(l zerolog.Logger, config model.AggregatorConfig) *server {
	store, err := createStorage(config)
	if err != nil {
		l.Error().Err(err).Msg("failed to create storage")
		return nil
	}

	aggregator, err := createAggregatorConfig(store, config)
	if err != nil {
		l.Error().Err(err).Msg("failed to create aggregator")
		return nil
	}

	read_commit_verification_record_handler := handlers.NewReadCommitVerificationRecordHandler(store)
	write_commit_verification_record_handler := handlers.NewWriteCommitVerificationRecordHandler(store, aggregator)

	return &server{
		l:                                    l,
		readCommitVerificationRecordHandler:  read_commit_verification_record_handler,
		writeCommitVerificationRecordHandler: write_commit_verification_record_handler,
	}
}
