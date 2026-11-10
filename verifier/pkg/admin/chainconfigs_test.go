package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type chainInspectorFunc func(context.Context) (chainaccess.ChainInspection, error)

func (f chainInspectorFunc) InspectChain(ctx context.Context) (chainaccess.ChainInspection, error) {
	return f(ctx)
}

func TestChainConfigsPage(t *testing.T) {
	order := int32(1)
	source := NewChainInspectionSource(
		[]protocol.ChainSelector{2, 1},
		map[protocol.ChainSelector]chainaccess.ChainInspector{
			1: chainInspectorFunc(func(context.Context) (chainaccess.ChainInspection, error) {
				return chainaccess.ChainInspection{
					Selector: 1, Family: "test-family", ChainID: "chain-one", Roles: []string{"source", "destination"},
					Endpoints: []chainaccess.ChainEndpoint{{
						Name: "primary", HTTPURL: "https://rpc.example.com", WSURL: "wss://rpc.example.com", HasWebSocket: true, Order: &order,
					}},
					Attributes: []chainaccess.ChainAttribute{
						{Name: "z.value", Value: "last", Source: "operator"},
						{Name: "a.value", Value: "first", Source: "family_default"},
					},
					Diagnostics: []string{"degraded example"},
				}, nil
			}),
			2: chainInspectorFunc(func(context.Context) (chainaccess.ChainInspection, error) {
				return chainaccess.ChainInspection{Selector: 2}, errors.New("driver failed")
			}),
		},
	)
	cfg, err := LoadConfig(writeConfig(t, ""))
	require.NoError(t, err)
	srv, err := NewServer(cfg, Deps{ReadOnly: true, ChainSource: source}, logger.Test(t))
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost:8105/chains", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	for _, expected := range []string{
		"Chain configurations", "test-family", "chain-one", "source, destination",
		"https://rpc.example.com", "wss://rpc.example.com", "degraded example", "driver failed",
		"a.value", "z.value", "family_default", "operator",
	} {
		require.Contains(t, body, expected)
	}
	require.Less(t, strings.Index(body, "a.value"), strings.Index(body, "z.value"))
	require.NotContains(t, body, "Message search")
}

func TestChainConfigsPageWithoutSource(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, ""))
	require.NoError(t, err)
	srv, err := NewServer(cfg, Deps{ReadOnly: true}, logger.Test(t))
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost:8105/chains", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "No chain inspection data is available")
}

func TestChainInspectionSourceReportsUnsupportedChain(t *testing.T) {
	source := NewChainInspectionSource([]protocol.ChainSelector{1}, nil)
	results := source.ChainInspections(context.Background())
	require.Len(t, results, 1)
	require.ErrorContains(t, results[0].Err, "unavailable")
	require.Equal(t, protocol.ChainSelector(1), results[0].Selector)
}
