package admin

import (
	"context"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type staticBalanceSource struct {
	chains []ChainTransmitterBalances
}

func (s staticBalanceSource) TransmitterBalances(context.Context) []ChainTransmitterBalances {
	return append([]ChainTransmitterBalances(nil), s.chains...)
}

func newReadOnlyTestServer(t *testing.T, spec *bootstrap.JobSpec, source TransmitterBalanceSource) *Server {
	t.Helper()
	cfg, err := LoadConfig(writeConfig(t, ""))
	require.NoError(t, err)
	srv, err := NewServer(cfg, Deps{ReadOnly: true, JobSpec: spec, BalanceSource: source}, logger.Test(t))
	require.NoError(t, err)
	return srv
}

func TestReadOnlyJobSpecPage(t *testing.T) {
	spec := &bootstrap.JobSpec{
		Name: "executor-node-1", ExternalJobID: "6f86d107-38a8-45f1-9b4d-3f8e1f34f384",
		SchemaVersion: 1, Type: "ccvexecutor", AppConfig: "executor_id = \"node-1\"\nlabel = \"<raw>\"\n",
	}
	srv := newReadOnlyTestServer(t, spec, nil)

	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost:8105/", nil))
	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/job", rec.Header().Get("Location"))

	rec = httptest.NewRecorder()
	srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost:8105/job", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "executor-node-1")
	require.Contains(t, body, spec.ExternalJobID)
	require.Contains(t, body, "ccvexecutor")
	require.Contains(t, body, "executor_id = &#34;node-1&#34;")
	require.Contains(t, body, "label = &#34;&lt;raw&gt;&#34;")
	require.NotContains(t, body, "label = \"<raw>\"")
	require.NotContains(t, body, "Message search")

	rec = httptest.NewRecorder()
	srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost:8105/search", nil))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestTransmitterKeysPage(t *testing.T) {
	amount, ok := new(big.Int).SetString("1234560000000000000", 10)
	require.True(t, ok)
	source := staticBalanceSource{chains: []ChainTransmitterBalances{
		{ChainSelector: protocol.ChainSelector(2), Err: errors.New("RPC down")},
		{ChainSelector: protocol.ChainSelector(1), Keys: []TransmitterKeyBalance{{
			KeyName: "evm-transmitter", Address: "0x00000000000000000000000000000000000000aa", Amount: amount, Decimals: 18,
		}}},
	}}
	srv := newReadOnlyTestServer(t, &bootstrap.JobSpec{}, source)

	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost:8105/transmitter-keys", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "evm-transmitter")
	require.Contains(t, body, "0x00000000000000000000000000000000000000aa")
	require.Contains(t, body, "1.23456")
	require.Contains(t, body, "1234560000000000000")
	require.Contains(t, body, "RPC down")
	require.Contains(t, body, "Refresh balances")
	require.Less(t, strings.Index(body, ">1</code>"), strings.Index(body, ">2</code>"))
}

func TestFormatNativeBalance(t *testing.T) {
	tests := []struct {
		amount   *big.Int
		decimals uint8
		want     string
	}{
		{nil, 18, "unavailable"},
		{big.NewInt(0), 18, "0"},
		{big.NewInt(200), 2, "2"},
		{big.NewInt(201), 2, "2.01"},
		{big.NewInt(-201), 2, "-2.01"},
		{big.NewInt(200), 0, "200"},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, formatNativeBalance(tt.amount, tt.decimals))
	}
	amount, ok := new(big.Int).SetString("1234560000000000000", 10)
	require.True(t, ok)
	require.Equal(t, "1.23456", formatNativeBalance(amount, 18))
	require.Equal(t, "0.0000000000000002", formatNativeBalance(big.NewInt(200), 18))
}
