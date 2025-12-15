// Generates OpenAPI spec for Indexer API v1.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
)

//go:generate go run generator.go ../../indexer_opanapi_v1.yaml
func main() {
	// Expect a single argument: output file path. Writing to stdout is NOT supported.
	if len(os.Args) != 2 {
		_, _ = fmt.Fprintf(os.Stderr, "usage: %s <output-file> (writing to stdout is not supported)\n", os.Args[0])
		os.Exit(2)
	}

	outPath := os.Args[1]
	out, err := getOutputFile(outPath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "failed to open output file:", err)
		os.Exit(1)
	}
	defer func() { _ = out.Close() }()

	// Create a new stdlib HTTP router.
	mux := http.NewServeMux()

	// Create a Huma v2 API on top of the router.
	api := humago.New(mux, huma.DefaultConfig("Indexer API", "1.0.0"))
	grp := huma.NewGroup(api, "/v1")

	huma.Register(grp, huma.Operation{
		OperationID: "verifier-result",
		Method:      http.MethodGet,
		Path:        "/verifierresult",
		Description: "Get verifier results",
	}, func(ctx context.Context, input *v1.VerifierResultsInput) (*v1.VerifierResultResponse, error) {
		return nil, nil
	})

	huma.Register(grp, huma.Operation{
		OperationID: "message-by-id",
		Method:      http.MethodGet,
		Path:        "/messageid/{messageID}",
		Description: "Get message by ID",
	}, func(ctx context.Context, input *v1.MessageIDInput) (*v1.MessageIDResponse, error) {
		return nil, nil
	})

	huma.Register(grp, huma.Operation{
		OperationID: "get-messages",
		Method:      http.MethodGet,
		Path:        "/messages",
		Description: "Get messages",
	}, func(ctx context.Context, input *v1.MessagesInput) (*v1.MessagesResponse, error) {
		return nil, nil
	})

	yml, err := api.OpenAPI().YAML()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "failed to generate openapi yaml:", err)
		os.Exit(1)
	}

	if _, err := out.Write(yml); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "failed to write file:", err)
		os.Exit(1)
	}

	_, _ = fmt.Fprintf(os.Stderr, "wrote OpenAPI YAML to %s\n", outPath)
}

func getOutputFile(path string) (*os.File, error) {
	// If outPath already exists and is a directory, fail early.
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		_, _ = fmt.Fprintf(os.Stderr, "output path is an existing directory: %s\n", path)
		os.Exit(2)
	}

	// Open output file for writing.
	f, err := os.Create(filepath.Clean(path))
	if err != nil {
		// Maybe the directory doesn't exist yet, don't bother creating it.
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	return f, nil
}
