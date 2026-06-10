package log

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
	"github.com/spf13/cobra"
)

// Command returns the cobra command for dumping service container logs.
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "logs",
		Aliases: []string{"l"},
		Short:   "Dump logs from all service containers",
		Long: `Dump logs from all running containers except known infrastructure
(db, nginx, redis, blockchain, jd, portainer, fake).

Without --sort, logs are grouped by container. With --sort, all log lines are
merged and sorted by their JSON "ts" timestamp field, with the container name
prepended to each line.`,
		RunE: run,
	}
	cmd.Flags().BoolP("sort", "s", false, "Sort all log lines by JSON ts field across containers")
	cmd.Flags().String("since", "", "Show logs since timestamp or duration (e.g. 5m, 1h, 2026-01-01T00:00:00Z)")
	cmd.Flags().String("tail", "", "Number of lines to show from the end of each container's logs (default: all)")
	cmd.Flags().StringP("filter", "f", "", "Only show lines containing this string")
	return cmd
}

func run(cmd *cobra.Command, _ []string) error {
	sortByTime, _ := cmd.Flags().GetBool("sort")
	since, _ := cmd.Flags().GetString("since")
	tail, _ := cmd.Flags().GetString("tail")
	filter, _ := cmd.Flags().GetString("filter")

	dockerClient, err := client.New(client.FromEnv)
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer dockerClient.Close()

	ctx := context.Background()
	result, err := dockerClient.ContainerList(ctx, client.ContainerListOptions{All: false})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	var names []string
	for _, c := range result.Items {
		for _, n := range c.Names {
			n = strings.TrimPrefix(n, "/")
			if isServiceContainer(n) {
				names = append(names, n)
				break
			}
		}
	}

	if len(names) == 0 {
		return fmt.Errorf("no service containers found; is the devenv running?")
	}
	sort.Strings(names)

	matches := func(line string) bool {
		return filter == "" || strings.Contains(line, filter)
	}

	if !sortByTime {
		for _, name := range names {
			lines, err := collectLogs(ctx, dockerClient, name, since, tail)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: %s: %v\n", name, err)
				continue
			}
			fmt.Printf("=== %s ===\n", name)
			for _, l := range lines {
				if matches(l.text) {
					fmt.Println(l.text)
				}
			}
		}
		return nil
	}

	// Collect all lines across containers, then sort by timestamp.
	var all []logLine
	for _, name := range names {
		lines, err := collectLogs(ctx, dockerClient, name, since, tail)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", name, err)
			continue
		}
		all = append(all, lines...)
	}

	// Lines that precede any JSON entry in their container have zero ts and sort last.
	sort.SliceStable(all, func(i, j int) bool {
		ti, tj := all[i].ts, all[j].ts
		if ti.IsZero() && tj.IsZero() {
			return false
		}
		if ti.IsZero() {
			return false
		}
		if tj.IsZero() {
			return true
		}
		return ti.Before(tj)
	})

	for _, l := range all {
		if matches(l.text) {
			fmt.Printf("[%s] %s\n", l.container, l.text)
		}
	}
	return nil
}

type logLine struct {
	container string
	text      string
	ts        time.Time
}

// isServiceContainer returns true for any container that is not known infrastructure
// (db, nginx, redis, blockchain, jd, portainer, fake).
func isServiceContainer(name string) bool {
	for _, suffix := range []string{"-db", "-nginx", "-redis"} {
		if strings.HasSuffix(name, suffix) {
			return false
		}
	}
	for _, prefix := range []string{"blockchain-", "jd-"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	switch name {
	case "fake", "portainer":
		return false
	}
	return true
}

func collectLogs(ctx context.Context, dockerClient *client.Client, name, since, tail string) ([]logLine, error) {
	opts := client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Since:      since,
		Tail:       tail,
	}
	rc, err := dockerClient.ContainerLogs(ctx, name, opts)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	var outBuf, errBuf bytes.Buffer
	if _, err := stdcopy.StdCopy(&outBuf, &errBuf, rc); err != nil && err != io.EOF {
		return nil, err
	}

	combined := append(outBuf.Bytes(), errBuf.Bytes()...)
	var lines []logLine
	scanner := bufio.NewScanner(bytes.NewReader(combined))
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MiB max line length
	var lastTS time.Time
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		ts := extractTS(line)
		if !ts.IsZero() {
			lastTS = ts
		} else {
			ts = lastTS
		}
		lines = append(lines, logLine{
			container: name,
			text:      line,
			ts:        ts,
		})
	}
	return lines, scanner.Err()
}

// extractTS parses the "ts" field from a JSON log line. Returns zero time if
// the line is not JSON or has no valid "ts" field.
func extractTS(line string) time.Time {
	if !strings.HasPrefix(line, "{") {
		return time.Time{}
	}
	var obj struct {
		Ts string `json:"ts"`
	}
	if err := json.Unmarshal([]byte(line), &obj); err != nil || obj.Ts == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, obj.Ts)
	if err != nil {
		return time.Time{}
	}
	return t
}
