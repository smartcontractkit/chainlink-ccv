package services

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteLocalAppConfigFile atomically writes app-config TOML to hostPath (bind-mounted into a service
// container running in bootstrap local mode). It writes to a temp file in the same directory and
// renames it into place so a bootstrapper waiting on the file never observes a partial write. Used by
// the no-JD devenv path, which delivers each service's app config as a file after contracts are
// deployed, rather than via a JD job proposal.
func WriteLocalAppConfigFile(hostPath, appConfigTOML string) error {
	if hostPath == "" {
		return fmt.Errorf("no local app config host path; was the service launched in local mode?")
	}
	dir := filepath.Dir(hostPath)
	tmp, err := os.CreateTemp(dir, ".app-*.toml")
	if err != nil {
		return fmt.Errorf("failed to create temp app config file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(appConfigTOML); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to write temp app config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to close temp app config: %w", err)
	}
	if err := os.Rename(tmpName, hostPath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to move app config into place: %w", err)
	}
	return nil
}
