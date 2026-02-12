// Package main is a test helper binary for the process runner.
// It reads a config file path from an env var (set by the runner), reads that file,
// and either writes its contents to TEST_OUTPUT_PATH and exits (for "spec passed correctly" tests),
// or blocks forever if TEST_BLOCK=1 (for start/stop lifecycle tests).
package main

import (
	"fmt"
	"os"
	"time"
)

// Env vars used by the test helper (tests set these when running the runner).
const (
	envConfigPath = "TEST_CONFIG_PATH" // set by runner to temp file path
	envOutputPath = "TEST_OUTPUT_PATH" // test sets this to capture config content
	envBlock      = "TEST_BLOCK"       // if "1", sleep forever
)

func main() {
	configPath := os.Getenv(envConfigPath)
	if configPath == "" {
		fmt.Fprintf(os.Stderr, "%s not set\n", envConfigPath)
		os.Exit(1)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read config: %v\n", err)
		os.Exit(1)
	}

	if os.Getenv(envBlock) == "1" {
		for {
			time.Sleep(time.Hour)
		}
	}

	outputPath := os.Getenv(envOutputPath)
	if outputPath == "" {
		fmt.Fprintf(os.Stderr, "%s not set (and %s not 1)\n", envOutputPath, envBlock)
		os.Exit(1)
	}
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		os.Exit(1)
	}
}
