package token

import (
	"context"
	"net"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"

	"github.com/smartcontractkit/chainlink-ccv/verifier/token/handler"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/storage"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

type Server struct {
	services.StateMachine
	pb.UnimplementedVerifierResultAPIServer

	getVerifierResultsForMessage *handler.VerifierResultsHandler
}

func (s *Server) GetVerifierResultsForMessage(
	ctx context.Context,
	req *pb.GetVerifierResultsForMessageRequest,
) (*pb.GetVerifierResultsForMessageResponse, error) {
	return s.getVerifierResultsForMessage.Handle(ctx, req)
}

func (s *Server) Start(lis net.Listener) error {
	return s.StartOnce("gRPCServer", func() error {
		return nil
	})
}

func (s *Server) Stop() error {
	return s.StopOnce("gRPCServer", func() error {
		return nil
	})
}

func NewServer(
	lggr logger.Logger,
	storage storage.OffchainStorage,
) *Server {
	return &Server{
		getVerifierResultsForMessage: handler.NewVerifierResultsHandler(
			lggr,
			storage,
		),
	}
}
