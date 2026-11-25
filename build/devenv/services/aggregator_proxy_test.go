package services

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateNginxConfig_BalancesAllReplicas(t *testing.T) {
	conf := generateNginxConfig([]string{"default-aggregator-replica-1", "default-aggregator-replica-2"}, 50051)

	require.Contains(t, conf, "server default-aggregator-replica-1:50051 resolve;")
	require.Contains(t, conf, "server default-aggregator-replica-2:50051 resolve;")
	require.Contains(t, conf, "listen 443 ssl;")
	require.Contains(t, conf, "listen 50051;")
	require.Equal(t, 2, strings.Count(conf, "grpc_pass grpc://aggregator;"))
}

func TestGenerateNginxConfig_SingleReplicaServesOnlyTLS(t *testing.T) {
	conf := generateNginxConfig([]string{"default-aggregator"}, 50051)

	require.Contains(t, conf, "server default-aggregator:50051 resolve;")
	require.Contains(t, conf, "listen 443 ssl;")
	require.NotContains(t, conf, "listen 50051")
}
