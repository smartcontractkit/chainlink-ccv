package bootstrap

import (
	"fmt"
	"os"
)

// ValidateLocalAppConfig strictly loads the bootstrap config at configPath and
// runs the service factory's own validation on the app config it points at,
// without starting services, loading secrets, connecting to a database, or
// talking to a Job Distributor.
//
// Each app exposes this as its `validate-config` subcommand so CI can validate a
// rendered config through the same decode and validation path as startup, pinned
// to the image being deployed.
//
// configPath may be empty, in which case BOOTSTRAPPER_CONFIG_PATH and then
// DefaultConfigPath are used, matching the service's own resolution.
//
// Only AppConfigModeLocal is supported: in AppConfigModeJD the app config is
// delivered by the Job Distributor when the job loads, so there is no file to
// validate here — the bootstrapper's runner validates it at that point via
// ServiceFactoryValidator.
func ValidateLocalAppConfig(configPath string, fac ServiceFactoryValidator) error {
	path := resolveBootstrapConfigPath(configPath)

	var cfg Config
	mode, err := LoadAndValidateConfig([]string{path}, &cfg)
	if err != nil {
		return fmt.Errorf("invalid bootstrap config %q: %w", path, err)
	}
	if mode != AppConfigModeLocal {
		return fmt.Errorf(
			"bootstrap config %q resolves to app config mode %q; validate-config requires %q (a JD-delivered app config is validated when the job loads)",
			path, mode, AppConfigModeLocal,
		)
	}

	appConfig, err := os.ReadFile(cfg.LocalAppConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read app config %q: %w", cfg.LocalAppConfigPath, err)
	}

	if err := fac.Validate(JobSpec{Name: "validate-config", AppConfig: string(appConfig)}); err != nil {
		return fmt.Errorf("app config %q: %w", cfg.LocalAppConfigPath, err)
	}

	return nil
}
