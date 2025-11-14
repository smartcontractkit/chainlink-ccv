package util

import (
	"fmt"
	"os"
	"path"
	"runtime"
)

func CCVConfigDir() string {
	p := path.Join(configDir(), "ccv")
	if err := os.MkdirAll(p, 0777); err != nil {
		panic("Unable to get config dir: " + err.Error())
	}
	return p
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
