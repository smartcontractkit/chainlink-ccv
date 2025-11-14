package util

import (
	"fmt"
	"os"
	"path"
	"runtime"
)

func CCVConfigDir() string {
	return path.Join(configDir(), "ccv")
}

func configDir() string {
	switch runtime.GOOS {
	case "windows":
		return os.Getenv("APPDATA")
	case "darwin":
		return fmt.Sprintf("%s/Library/Preferences", os.Getenv("HOME"))
	default: // Unix/Linux
		if configHome := os.Getenv("XDG_CONFIG_HOME"); configHome != "" {
			return configHome
		}
		return fmt.Sprintf("%s/.config", os.Getenv("HOME"))
	}
}
