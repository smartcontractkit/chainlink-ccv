package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
)

func historyFilePath() string {
	return filepath.Join(configDir(), "ccv", historyFileName)
}

func getHistory() []string {
	file, err := os.Open(historyFilePath())
	if err != nil {
		return []string{}
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("Error closing history file: %v\n", err)
		}
	}(file)

	var history []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		history = append(history, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading history file: %v\n", err)
	}
	return history
}

func saveHistory(cmd string) {
	historyFile, err := os.OpenFile(historyFilePath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Printf("Error opening history file: %v\n", err)
		return
	}

	if _, err = historyFile.WriteString(cmd + "\n"); err != nil {
		fmt.Printf("Error writing to history file: %v\n", err)
	}

	if err = historyFile.Close(); err != nil {
		fmt.Printf("Error closing history file: %v\n", err)
	}
}
