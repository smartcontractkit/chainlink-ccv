package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
)

func activeConfigPath() string {
	return filepath.Join(util.CCVConfigDir(), activeFileName)
}

func getActiveConfig() string {
	activeConfig, err := os.ReadFile(activeConfigPath())
	if err != nil {
		return ""
	}
	return string(activeConfig)
}

func saveActiveConfig(activeConfig string) {
	if !strings.Contains(activeConfig, "toml") {
		return // no new active config to update
	}
	err := os.WriteFile(activeConfigPath(), []byte(activeConfig), 0o644)
	if err != nil {
		fmt.Printf("Error writing active config file: %v\n", err)
	}
}
