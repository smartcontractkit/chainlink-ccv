package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type balanceReaderFunc func(context.Context) ([]chainaccess.TransmitterKeyBalance, error)

func (f balanceReaderFunc) TransmitterBalances(ctx context.Context) ([]chainaccess.TransmitterKeyBalance, error) {
	return f(ctx)
}

func TestTransmitterBalanceSourceSeparatesChainFailures(t *testing.T) {
	source := &transmitterBalanceSource{
		selectors: []protocol.ChainSelector{2, 1},
		readers: map[protocol.ChainSelector]chainaccess.TransmitterBalanceReader{
			1: balanceReaderFunc(func(context.Context) ([]chainaccess.TransmitterKeyBalance, error) {
				return []chainaccess.TransmitterKeyBalance{{
					KeyName: "tx-key", Address: "0xabc", Amount: big.NewInt(42), NativeTokenDecimals: 18,
				}}, nil
			}),
			2: balanceReaderFunc(func(context.Context) ([]chainaccess.TransmitterKeyBalance, error) {
				return nil, errors.New("RPC unavailable")
			}),
		},
	}

	results := source.TransmitterBalances(context.Background())
	require.Len(t, results, 2)
	require.Equal(t, protocol.ChainSelector(2), results[0].ChainSelector)
	require.ErrorContains(t, results[0].Err, "RPC unavailable")
	require.Empty(t, results[0].Keys)
	require.Equal(t, protocol.ChainSelector(1), results[1].ChainSelector)
	require.NoError(t, results[1].Err)
	require.Len(t, results[1].Keys, 1)
	require.Equal(t, "0xabc", results[1].Keys[0].Address)
	require.Equal(t, "42", results[1].Keys[0].Amount.String())
	require.Equal(t, uint8(18), results[1].Keys[0].Decimals)
}

func TestTransmitterBalanceSourceReportsUnsupportedChain(t *testing.T) {
	source := &transmitterBalanceSource{
		selectors: []protocol.ChainSelector{1},
		readers:   map[protocol.ChainSelector]chainaccess.TransmitterBalanceReader{},
	}
	results := source.TransmitterBalances(context.Background())
	require.Len(t, results, 1)
	require.ErrorContains(t, results[0].Err, "unavailable")
}

func TestStartAdminConsoleServesJobAndBalances(t *testing.T) {
	port := freeTCPPort(t)
	configPath := filepath.Join(t.TempDir(), "admin.toml")
	require.NoError(t, os.WriteFile(configPath, fmt.Appendf(nil, "listen_address = \"127.0.0.1:%d\"\n", port), 0o600))
	t.Setenv(admin.ConfigPathEnv, configPath)

	source := &transmitterBalanceSource{
		selectors: []protocol.ChainSelector{1},
		readers: map[protocol.ChainSelector]chainaccess.TransmitterBalanceReader{
			1: balanceReaderFunc(func(context.Context) ([]chainaccess.TransmitterKeyBalance, error) {
				return []chainaccess.TransmitterKeyBalance{{
					KeyName: "tx-key", Address: "0xabc", Amount: big.NewInt(42), NativeTokenDecimals: 18,
				}}, nil
			}),
		},
	}
	stop, err := startAdminConsole(
		logger.Test(t),
		bootstrap.JobSpec{Name: "executor-e2e", AppConfig: "executor_id = \"e2e\""},
		&bootstrap.AdminUISecret{Username: "operator", Password: "secret"},
		source,
	)
	require.NoError(t, err)
	require.NotNil(t, stop)
	t.Cleanup(stop)

	client := &http.Client{Timeout: time.Second}
	get := func(path string, authenticated bool) (int, string, error) {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
		if err != nil {
			return 0, "", err
		}
		if authenticated {
			req.SetBasicAuth("operator", "secret")
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body), err
	}

	var status int
	var body string
	require.Eventually(t, func() bool {
		status, body, err = get("/job", true)
		return err == nil && status == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond)
	require.Contains(t, body, "executor-e2e")
	require.Contains(t, body, "executor_id")

	status, body, err = get("/transmitter-keys", true)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, body, "0xabc")
	require.Contains(t, body, ">42</code>")

	status, _, err = get("/job", false)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, status)
}
