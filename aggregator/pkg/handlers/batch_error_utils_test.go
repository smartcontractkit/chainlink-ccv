package handlers

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestBatchErrorUtils_SetBatchErrorAndSuccess(t *testing.T) {
	errs := NewBatchErrorArray(2)
	SetBatchSuccess(errs, 0)
	SetBatchError(errs, 1, codes.NotFound, "missing")

	require.Equal(t, int32(codes.OK), errs[0].Code)
	require.Equal(t, int32(codes.NotFound), errs[1].Code)
	// ensure array length unchanged
	require.Len(t, errs, 2)
}
