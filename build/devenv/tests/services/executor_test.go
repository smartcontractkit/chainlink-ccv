package services_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
)

func TestServiceExecutor(t *testing.T) {
	out, err := services.NewExecutor(&services.ExecutorInput{
		SourceCodePath: "../../../executor",
		RootPath:       "../../../../",
		ContainerName:  "executor-test",
		Port:           8101,
		Mode:           services.Standalone,
		ExecutorID:     "executor-test",
		ExecutorPool:   []string{"executor-test"},
	})
	require.NoError(t, err)
	t.Run("test #1", func(t *testing.T) {
		_ = out
		// use the data from output, connect HTTP, gRPC clients etc and do the testing
	})
}
