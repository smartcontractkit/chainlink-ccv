package verifier

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/jmoiron/sqlx"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// startAdminConsole serves the admin console in-process when its config file is
// present (CCV_ADMIN_CONFIG_PATH or /etc/ccv-admin/config.toml); the console shares
// the verifier's application DB and its [admin_ui] credential. Absent file means
// disabled (nil, nil); the returned stop function shuts the console down.
func startAdminConsole(lggr logger.Logger, ds sqlutil.DataSource, secrets *vsecrets.VerifierSecrets, aggregatorAddress string) (func(), error) {
	path := os.Getenv(admin.ConfigPathEnv)
	if path == "" {
		path = admin.DefaultConfigPath
	}
	if _, err := os.Stat(path); err != nil { //nolint:gosec // G703: operator-provided config path, not request input.
		return nil, nil
	}
	cfg, err := admin.LoadConfig(path)
	if err != nil {
		return nil, err
	}
	db, ok := ds.(*sqlx.DB)
	if !ok || db == nil {
		return nil, fmt.Errorf("admin console requires the verifier application database ([db].url in the verifier secrets file)")
	}
	auth, err := admin.BasicAuthFromSecrets(secrets)
	if err != nil {
		return nil, err
	}
	if cfg.AggregatorAddress == "" {
		cfg.AggregatorAddress = aggregatorAddress
	}
	srv, err := admin.NewServer(cfg, admin.Deps{DB: db, Auth: auth, AggregatorAddress: cfg.AggregatorAddress}, lggr)
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
