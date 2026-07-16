package verifiercli

import "testing"

func TestParseFirstListRow_PlainTable(t *testing.T) {
	t.Parallel()

	//nolint:dupword // Fixture mirrors the CLI header text.
	listOutput := `time=2026-07-15T11:47:04.025Z level=INFO msg="goose: no migrations to run. current version: 7"
{"level":"INFO","ts":"2026-07-15T11:47:04.025Z","logger":"ccv-cli","caller":"verifier/common.go:107","msg":"Using PostgreSQL chain status storage"}
     Chain         Chain Selector       verifier_id     finalized_block_height  disabled       updated_at
 geth-testnet   3379446385462418246   default-verifier  786                     false     2026-07-15T11:47:03Z
 geth-devnet-3  4793464827907405086   default-verifier  787                     false     2026-07-15T11:47:03Z
`

	got, ok := ParseFirstListRow(listOutput)
	if !ok {
		t.Fatal("expected to parse a row from plain table output")
	}
	if got != ChainSelector("3379446385462418246") {
		t.Fatalf("unexpected chain selector: got %q", got)
	}
}

func TestParseFirstListRow_PipeDelimitedTable(t *testing.T) {
	t.Parallel()

	listOutput := `| Chain        | Chain Selector      | verifier_id      | finalized_block_height | disabled | updated_at            |
|--------------|---------------------|------------------|------------------------|----------|-----------------------|
| geth-testnet | 3379446385462418246 | default-verifier | 786                    | false    | 2026-07-15T11:47:03Z |
`

	got, ok := ParseFirstListRow(listOutput)
	if !ok {
		t.Fatal("expected to parse a row from pipe-delimited output")
	}
	if got != ChainSelector("3379446385462418246") {
		t.Fatalf("unexpected chain selector: got %q", got)
	}
}
