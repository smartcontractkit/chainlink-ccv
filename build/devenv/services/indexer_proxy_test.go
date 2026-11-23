package services

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateIndexerProxyConfig_BalancesAllReplicas(t *testing.T) {
	conf := generateIndexerProxyConfig(8100, []string{"indexer-1-replica-1", "indexer-1-replica-2"})

	require.Contains(t, conf, "server indexer-1-replica-1:8100 resolve;")
	require.Contains(t, conf, "server indexer-1-replica-2:8100 resolve;")
	require.Contains(t, conf, "listen 8100;")
	require.Contains(t, conf, "proxy_next_upstream error timeout http_502 http_503;")
	require.Equal(t, 1, strings.Count(conf, "upstream indexer {"))
}
