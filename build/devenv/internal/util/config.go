package util

import (
	"fmt"
	"os"
	"path"
	"runtime"
)

func init() {
	if err := os.MkdirAll(CCVConfigDir(), 0o777); err != nil {
		panic("Failed to create CCVConfigDir: " + err.Error())
	}
}

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
