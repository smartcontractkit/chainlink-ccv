package handlers

import (
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	grpcstatus "google.golang.org/grpc/status"
)

func NewBatchErrorArray(size int) []*status.Status {
	return make([]*status.Status, size)
}

func SetBatchError(errors []*status.Status, index int, code codes.Code, message string) {
	errors[index] = grpcstatus.New(code, message).Proto()
}

func SetBatchSuccess(errors []*status.Status, index int) {
	errors[index] = &status.Status{Code: int32(codes.OK)}
}
