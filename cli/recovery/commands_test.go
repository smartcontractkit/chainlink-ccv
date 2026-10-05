package recovery

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	store "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
)

type capturedStore struct {
	Store
	request store.SubmitRequest
	filter  store.EventFilter
}

func (s *capturedStore) Submit(_ context.Context, request store.SubmitRequest) (store.Operation, error) {
	s.request = request
	return store.Operation{
		ID: request.ID, OwnerID: request.OwnerID, SourceChain: request.SourceChain,
		FromBlock: request.FromBlock, ToBlock: 100, NextBlock: request.FromBlock, State: "accepted",
	}, nil
}

func (s *capturedStore) ListEvents(_ context.Context, filter store.EventFilter) (store.EventPage, error) {
	s.filter = filter
	return store.EventPage{Events: []store.Event{}, Readers: json.RawMessage("[]"), Coverage: "Observed events only"}, nil
}

func commandJSON(t *testing.T, s Store, args ...string) (string, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	previous := os.Stdout
	os.Stdout = writer
	defer func() {
		os.Stdout = previous
		_ = reader.Close()
		_ = writer.Close()
	}()
	output := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		output <- string(data)
	}()
	app := cli.NewApp()
	app.Commands = InitCommandsWithFactory(func() Store { return s })
	err = app.Run(append([]string{"ccv"}, args...))
	_ = writer.Close()
	return <-output, err
}

func TestReplayCLIUsesExactSelectorAndOmittedTarget(t *testing.T) {
	s := &capturedStore{}
	out, err := commandJSON(t, s, "replay", "--verifier-id", "owner", "--chain-selector", "18446744073709551615",
		"--from-block", "0", "--actor", "operator", "--note", "investigated range",
		"--request-id", "00000000-0000-0000-0000-000000000042")
	require.NoError(t, err)
	require.Equal(t, "18446744073709551615", s.request.SourceChain)
	require.Nil(t, s.request.ToBlock, "the store must capture the submission head")
	require.Equal(t, "replay", s.request.Mode)
	require.Equal(t, "operator", s.request.Actor)
	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &result))
	require.Equal(t, "18446744073709551615", result["source_chain_selector"])
	require.Equal(t, "0", result["from_block"])
}

func TestEventsCLIFiltersAndValidation(t *testing.T) {
	s := &capturedStore{}
	id := strings.Repeat("ab", 32)
	out, err := commandJSON(t, s, "events", "--message-id", "0X"+strings.ToUpper(id)+",0x"+id,
		"--message-id", id, "--reason", "remote_chain_cursed", "--from-block", "0", "--to-block", "100",
		"--before-id", "22", "--limit", "5")
	require.NoError(t, err)
	require.Equal(t, []string{"0x" + id}, s.filter.MessageIDs)
	require.Equal(t, "22", s.filter.BeforeID)
	require.Equal(t, 5, s.filter.Limit)
	require.Contains(t, out, `"events":[]`)
	for _, args := range [][]string{
		{"events", "--message-id", "0x"},
		{"events", "--from-block", "12", "--to-block", "11"},
		{"events", "--before-id", "18446744073709551615"},
		{"events", "--reason", "raw-error-text"},
		{"events", "--since", "2026-09-10T00:00:00Z", "--until", "2026-09-01T00:00:00Z"},
		{"status", "--operation-id", "invalid"},
	} {
		_, err := commandJSON(t, nil, args...)
		require.Error(t, err, "invalid input must fail before accessing the store: %v", args)
	}
}
