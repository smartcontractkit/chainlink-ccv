package verifier

import (
	"flag"
	"fmt"
	"os"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
)

// RunValidateConfig implements the `validate-config` subcommand shared by the
// verifier binaries. It validates the app config referenced by the bootstrap
// config through the factory's own decode and validation path, reading no
// secrets and touching no external services, so it is safe to run in CI.
//
// It terminates the process: 0 on success, 1 on an invalid config, 2 on a usage
// error.
func RunValidateConfig(args []string, fac bootstrap.ServiceFactory) {
	fs := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	configPath := fs.String(
		"config", "",
		"path to the bootstrap config (default: $"+bootstrap.ConfigPathEnv+", then "+bootstrap.DefaultConfigPath+")",
	)
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}

	validator, ok := fac.(bootstrap.ServiceFactoryValidator)
	if !ok {
		_, _ = fmt.Fprintln(os.Stderr, "validate-config: service factory does not support config validation")
		os.Exit(1)
	}

	if err := bootstrap.ValidateLocalAppConfig(*configPath, validator); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "config validation failed: %v\n", err)
		os.Exit(1)
	}

	_, _ = fmt.Fprintln(os.Stdout, "config is valid")
}
