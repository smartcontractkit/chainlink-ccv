// Package recovery exposes durable recovery control and evidence without adding
// an HTTP administration surface to the verifier.
package recovery

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	store "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
)

// Store is the subset of the recovery store the CLI drives. It is an interface here so the
// commands can be tested without a database.
type Store interface {
	// Submit accepts a new recovery operation and returns it with its assigned ID.
	Submit(context.Context, store.SubmitRequest) (store.Operation, error)
	// Get returns one operation by ID.
	Get(context.Context, string) (store.Operation, error)
	// List returns operations for a verifier and source chain, newest first, up to limit.
	List(context.Context, string, string, int) ([]store.Operation, error)
	// ChangeState applies an operator action (cancel, resume) and returns the updated operation.
	ChangeState(context.Context, string, string) (store.Operation, error)
	// ListEvents returns a page of audit events matching the filter.
	ListEvents(context.Context, store.EventFilter) (store.EventPage, error)
}

func InitCommandsWithFactory(getStore func() Store) []cli.Command {
	commands := make([]cli.Command, 0)
	for _, mode := range []string{"replay", "reset-reader"} {
		usage := "Submit bounded live source re-verification; returns a durable operation as JSON"
		if mode == "reset-reader" {
			usage = "Re-enable an investigated disabled reader and recover a bounded range without restarting"
		}
		commands = append(commands, cli.Command{Name: mode, Usage: usage, Flags: []cli.Flag{
			cli.StringFlag{Name: "verifier-id", Required: true},
			cli.StringFlag{Name: "chain-selector", Required: true},
			cli.StringFlag{Name: "from-block", Required: true, Usage: "Inclusive first source block"},
			cli.StringFlag{Name: "to-block", Usage: "Inclusive last block; omitted captures the reader's recently reported head now"},
			cli.StringFlag{Name: "actor", Required: true, Usage: "Operator identity recorded with this request"},
			cli.StringFlag{Name: "note", Required: true, Usage: "Recovery reason and investigated boundary evidence"},
			cli.StringFlag{Name: "request-id", Usage: "Optional UUID idempotency key; reuse after a disconnected submission"},
		}, Action: func(c *cli.Context) error {
			from, err := parseNumber(c.String("from-block"), "from-block")
			if err != nil {
				return err
			}
			chain, err := parseNumber(c.String("chain-selector"), "chain-selector")
			if err != nil {
				return err
			}
			var to *uint64
			if c.IsSet("to-block") {
				value, err := parseNumber(c.String("to-block"), "to-block")
				if err != nil {
					return err
				}
				to = &value
			}
			o, err := getStore().Submit(context.Background(), store.SubmitRequest{
				ID: c.String("request-id"), OwnerID: c.String("verifier-id"),
				SourceChain: strconv.FormatUint(chain, 10), FromBlock: from, ToBlock: to, Mode: mode, Actor: c.String("actor"), Note: c.String("note"),
			})
			if err != nil {
				return err
			}
			return writeJSON(o)
		}})
	}
	commands = append(commands, cli.Command{Name: "list", Usage: "List latest recovery operations as JSON (newest first)", Flags: []cli.Flag{
		cli.StringFlag{Name: "verifier-id"}, cli.StringFlag{Name: "chain-selector"}, cli.IntFlag{Name: "limit", Value: 50, Usage: "Maximum rows (1-500)"},
	}, Action: func(c *cli.Context) error {
		if err := validateOptionalNumbers(c, "chain-selector"); err != nil {
			return err
		}
		operations, err := getStore().List(context.Background(), c.String("verifier-id"), c.String("chain-selector"), c.Int("limit"))
		if err != nil {
			return err
		}
		return writeJSON(operations)
	}})
	for _, action := range []string{"status", "cancel", "resume"} {
		commands = append(commands, cli.Command{Name: action, Usage: action + " a durable recovery operation; returns JSON", Flags: []cli.Flag{
			cli.StringFlag{Name: "operation-id", Required: true},
		}, Action: func(c *cli.Context) error {
			id := c.String("operation-id")
			parsedID, err := uuid.Parse(id)
			if err != nil {
				return fmt.Errorf("operation-id must be a UUID: %w", err)
			}
			id = parsedID.String()
			var o store.Operation
			if action == "status" {
				o, err = getStore().Get(context.Background(), id)
			} else {
				o, err = getStore().ChangeState(context.Background(), id, action)
			}
			if err != nil {
				return err
			}
			return writeJSON(o)
		}})
	}
	commands = append(commands, cli.Command{Name: "events", Usage: "Query retained drops and finality incidents as paginated JSON, with coverage metadata", Flags: []cli.Flag{
		cli.StringFlag{Name: "verifier-id"},
		cli.StringFlag{Name: "chain-selector"},
		cli.StringFlag{Name: "dest-chain-selector"},
		cli.StringSliceFlag{Name: "message-id", Usage: "Full message IDs, comma-separated or repeated"},
		cli.StringFlag{Name: "reason", Usage: "remote_chain_cursed, message_disablement_rule, finality_violation or operator_reset"},
		cli.StringFlag{Name: "since", Usage: "RFC3339 observation window start"},
		cli.StringFlag{Name: "until", Usage: "RFC3339 observation window end"},
		cli.StringFlag{Name: "from-block"},
		cli.StringFlag{Name: "to-block"},
		cli.StringFlag{Name: "before-id", Usage: "next_cursor from a previous page"},
		cli.IntFlag{Name: "limit", Value: 50, Usage: "Page size (1-500)"},
	}, Action: func(c *cli.Context) error {
		if err := validateOptionalNumbers(c, "chain-selector", "dest-chain-selector", "from-block", "to-block", "before-id"); err != nil {
			return err
		}
		f := store.EventFilter{
			OwnerID: c.String("verifier-id"), SourceChain: c.String("chain-selector"), DestChain: c.String("dest-chain-selector"),
			Reason: c.String("reason"), FromBlock: c.String("from-block"), ToBlock: c.String("to-block"), BeforeID: c.String("before-id"), Limit: c.Int("limit"),
		}
		if f.FromBlock != "" && f.ToBlock != "" {
			from, _ := parseNumber(f.FromBlock, "from-block")
			to, _ := parseNumber(f.ToBlock, "to-block")
			if from > to {
				return fmt.Errorf("--from-block must not be after --to-block")
			}
		}
		if f.BeforeID != "" {
			if _, err := strconv.ParseInt(f.BeforeID, 10, 64); err != nil {
				return fmt.Errorf("--before-id exceeds the supported cursor range: %w", err)
			}
		}
		if f.Reason != "" && f.Reason != "remote_chain_cursed" && f.Reason != "message_disablement_rule" && f.Reason != "finality_violation" && f.Reason != "operator_reset" {
			return fmt.Errorf("unknown recovery reason %q", f.Reason)
		}
		for _, entry := range []struct {
			name  string
			value **time.Time
		}{{"since", &f.Since}, {"until", &f.Until}} {
			if c.IsSet(entry.name) {
				value, err := time.Parse(time.RFC3339, c.String(entry.name))
				if err != nil {
					return fmt.Errorf("--%s must be RFC3339: %w", entry.name, err)
				}
				*entry.value = &value
			}
		}
		if f.Since != nil && f.Until != nil && f.Since.After(*f.Until) {
			return fmt.Errorf("--since must not be after --until")
		}
		if c.IsSet("message-id") {
			ids, err := jobqueue.ParseMessageIDs(c.StringSlice("message-id"))
			if err != nil {
				return err
			}
			for _, id := range ids {
				f.MessageIDs = append(f.MessageIDs, "0x"+hex.EncodeToString(id))
			}
		}
		page, err := getStore().ListEvents(context.Background(), f)
		if err != nil {
			return err
		}
		return writeJSON(page)
	}})
	return commands
}

func parseNumber(value, name string) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("--%s must be an unsigned decimal integer: %w", name, err)
	}
	return n, nil
}

func validateOptionalNumbers(c *cli.Context, names ...string) error {
	for _, name := range names {
		if c.IsSet(name) {
			if _, err := parseNumber(c.String(name), name); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeJSON(value any) error { return json.NewEncoder(os.Stdout).Encode(value) }
