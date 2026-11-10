package executor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const transmitterBalanceQueryTimeout = 10 * time.Second

type transmitterBalanceSource struct {
	selectors []protocol.ChainSelector
	readers   map[protocol.ChainSelector]chainaccess.TransmitterBalanceReader
}

func (s *transmitterBalanceSource) TransmitterBalances(ctx context.Context) []admin.ChainTransmitterBalances {
	results := make([]admin.ChainTransmitterBalances, len(s.selectors))
	var wg sync.WaitGroup
	for i, selector := range s.selectors {
		wg.Go(func() {
			result := admin.ChainTransmitterBalances{ChainSelector: selector}
			reader, ok := s.readers[selector]
			if !ok {
				result.Err = errors.New("transmitter balance monitoring is unavailable for this chain")
				results[i] = result
				return
			}
			queryCtx, cancel := context.WithTimeout(ctx, transmitterBalanceQueryTimeout)
			defer cancel()
			keys, err := reader.TransmitterBalances(queryCtx)
			if err != nil {
				result.Err = err
			}
			result.Keys = make([]admin.TransmitterKeyBalance, 0, len(keys))
			for _, key := range keys {
				result.Keys = append(result.Keys, admin.TransmitterKeyBalance{
					KeyName: key.KeyName, Address: key.Address, Amount: key.Amount, Decimals: key.NativeTokenDecimals,
				})
			}
			results[i] = result
		})
	}
	wg.Wait()
	return results
}

func loadAdminConsoleAuth() (*admin.BasicAuth, error) {
	path := os.Getenv(admin.SecretsPathEnv)
	if path == "" {
		path = admin.DefaultSecretsPath
	}
	if _, err := os.Stat(path); err != nil { //nolint:gosec // G703: operator-provided secrets path, not request input.
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to stat admin console secrets %q: %w", path, err)
	}
	secrets, err := vsecrets.Load(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load admin console secrets: %w", err)
	}
	return admin.BasicAuthFromSecrets(secrets)
}

// startAdminConsole serves the read-only executor console when its config file is present.
func startAdminConsole(lggr logger.Logger, spec bootstrap.JobSpec, balances admin.TransmitterBalanceSource) (func(), error) {
	path := os.Getenv(admin.ConfigPathEnv)
	if path == "" {
		path = admin.DefaultConfigPath
	}
	if _, err := os.Stat(path); err != nil { //nolint:gosec // G703: operator-provided config path, not request input.
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("failed to stat admin console config %q: %w", path, err)
		}
		return nil, nil
	}
	cfg, err := admin.LoadConfig(path)
	if err != nil {
		return nil, err
	}
	auth, err := loadAdminConsoleAuth()
	if err != nil {
		return nil, err
	}
	srv, err := admin.NewServer(cfg, admin.Deps{
		Auth: auth, ReadOnly: true, JobSpec: &spec, BalanceSource: balances,
	}, lggr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Run(ctx); err != nil {
			lggr.Errorw("admin console stopped with error", "error", err)
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}, nil
}
