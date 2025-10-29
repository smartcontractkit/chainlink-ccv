package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func activeConfigPath() string {
	return filepath.Join(configDir(), "ccv", activeFileName)
}

func getActiveConfig() string {
	activeConfig, err := os.ReadFile(activeConfigPath())
	if err != nil {
		return ""
	}
	return string(activeConfig)
}

func saveActiveConfig(activeConfig string) {
	err := os.WriteFile(activeConfigPath(), []byte(activeConfig), 0o644)
	if err != nil {
		fmt.Printf("Error writing active config file: %v\n", err)
	}
}
