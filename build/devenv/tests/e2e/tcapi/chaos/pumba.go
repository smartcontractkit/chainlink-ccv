package chaos

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// BuildStopCommand returns a Pumba "stop" command that restarts matching containers
// after duration. targets must be normalized Docker container names.
func BuildStopCommand(duration time.Duration, targets []string) string {
	return fmt.Sprintf("stop --duration=%s --restart re2:%s", duration, formatPumbaTarget(targets))
}

// BuildNetemDelayCommand returns a Pumba "netem delay" command that injects
// delayMs milliseconds of latency to matching containers for the given duration.
// targets must be normalized Docker container names.
func BuildNetemDelayCommand(duration time.Duration, delayMs int, targets []string) string {
	return fmt.Sprintf("netem --tc-image=ghcr.io/alexei-led/pumba-debian-nettools --duration=%s delay --time=%d re2:%s",
		duration, delayMs, formatPumbaTarget(targets))
}

func formatPumbaTarget(targets []string) string {
	if len(targets) == 0 {
		return "^$" // match nothing
	}
	parts := make([]string, len(targets))
	for i, name := range targets {
		parts[i] = fmt.Sprintf("^%s$", regexp.QuoteMeta(name))
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return fmt.Sprintf("(%s)", strings.Join(parts, "|"))
}
