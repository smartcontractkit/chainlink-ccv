package services_test

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
)

// These have the same names and meaning as in the e2e upgrade tests (tests/e2e/upgrade_rolling_test.go).
const (
	upgradeImageTagEnv     = "CCV_UPGRADE_IMAGE_TAG"
	upgradeFromImageTagEnv = "CCV_UPGRADE_FROM_IMAGE_TAG"
	upgradeServicesEnv     = "CCV_UPGRADE_SERVICES"
)

// upgradeSettleTime is how long a swapped container must stay up before the test continues.
const upgradeSettleTime = 10 * time.Second

// upgradeImages returns the images of repo to upgrade from and to.
// It skips the test if no upgrade tag is set, or if CCV_UPGRADE_SERVICES does not name repo.
func upgradeImages(t *testing.T, repo string) (fromImage, toImage string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping service upgrade test in short mode; requires Docker service containers")
	}
	tag := os.Getenv(upgradeImageTagEnv)
	if tag == "" {
		t.Skipf("%s is not set", upgradeImageTagEnv)
	}
	if svcs := strings.TrimSpace(os.Getenv(upgradeServicesEnv)); svcs != "" {
		names := strings.Split(strings.ReplaceAll(svcs, " ", ""), ",")
		if !slices.Contains(names, repo) {
			t.Skipf("%s=%s does not name %s", upgradeServicesEnv, svcs, repo)
		}
	}
	fromTag := os.Getenv(upgradeFromImageTagEnv)
	if fromTag == "" {
		fromTag = "latest"
	}
	fromImage, toImage = services.ImageWithTag(repo, fromTag), services.ImageWithTag(repo, tag)
	same, err := services.SameImage(t.Context(), fromImage, toImage)
	require.NoError(t, err)
	if same {
		t.Logf("%s and %s are the same image, so each swap is a restart on the existing data", fromImage, toImage)
	}
	return fromImage, toImage
}

// swapContainer replaces the container with one from image, waits until it stays up, then reloads the proxy.
// An empty proxy means that no proxy is in front of the container.
func swapContainer(t *testing.T, ctx context.Context, name, image, repo, proxy string,
	replace func(context.Context, string, string, []services.UpgradeFile) error,
) {
	t.Helper()
	require.NoError(t, replace(ctx, name, image, services.UpgradeFiles(repo)))
	deadline := time.Now().Add(upgradeSettleTime)
	for time.Now().Before(deadline) {
		running, err := services.IsRunning(ctx, name)
		require.NoError(t, err)
		require.True(t, running, "%s stopped after the swap to %s; see its logs", name, image)
		time.Sleep(time.Second)
	}
	if proxy != "" {
		reloadProxy(t, ctx, proxy)
	}
}

// reloadProxy makes nginx resolve the replicas again, which can have new IPs or be stopped.
func reloadProxy(t *testing.T, ctx context.Context, proxy string) {
	t.Helper()
	code, out, err := services.Exec(ctx, proxy, "nginx", "-s", "reload")
	require.NoError(t, err)
	require.Equal(t, 0, code, "reload %s: %s", proxy, out)
}

// tableExists reports whether the table is in the search path of the DB.
func tableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var ok bool
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&ok))
	return ok
}

// columnExists reports whether the table has the column. The table name can have a schema prefix.
func columnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	schema, name, found := strings.Cut(table, ".")
	if !found {
		schema, name = "public", table
	}
	var ok bool
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 AND column_name = $3)`,
		schema, name, column).Scan(&ok))
	return ok
}

// dumpLogs logs the last lines of each container and of its renamed copies, if they exist.
func dumpLogs(t *testing.T, names []string, suffixes ...string) {
	t.Helper()
	for _, name := range names {
		for _, c := range append([]string{name}, func() []string {
			r := make([]string, 0, len(suffixes))
			for _, s := range suffixes {
				r = append(r, name+s)
			}
			return r
		}()...) {
			out, err := exec.Command("docker", "logs", "--tail", "400", c).CombinedOutput()
			if err == nil {
				t.Logf("logs of %s:\n%s", c, out)
			}
		}
	}
}
