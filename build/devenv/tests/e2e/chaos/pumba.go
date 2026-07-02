package chaos

import (
	"fmt"
	"strings"
	"time"
)

// BuildStopCommand returns a Pumba "stop" command that restarts matching containers
// after duration. targets must be normalized Docker container names.
//
// When literalSingle is true and there is exactly one target, the name is passed to
// Pumba as-is (aggregator nginx). Otherwise each target is wrapped in ^$ anchors;
// multiple targets are combined as a re2 alternation.
func BuildStopCommand(duration time.Duration, targets []string, literalSingle bool) string {
	return fmt.Sprintf("stop --duration=%s --restart re2:%s", duration, formatPumbaTarget(targets, literalSingle))
}

func formatPumbaTarget(targets []string, literalSingle bool) string {
	if len(targets) == 0 {
		return ""
	}
	if literalSingle && len(targets) == 1 {
		return targets[0]
	}
	parts := make([]string, len(targets))
	for i, name := range targets {
		parts[i] = fmt.Sprintf("^%s$", name)
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return fmt.Sprintf("(%s)", strings.Join(parts, "|"))
}
