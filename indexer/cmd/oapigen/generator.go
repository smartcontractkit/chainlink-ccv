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
	cfg := huma.DefaultConfig("Indexer API", "1.0.0")
	api := humago.New(mux, cfg)

	// Huma will use this to override its built in error type.
	huma.NewError = func(status int, msg string, errs ...error) huma.StatusError {
		return v1.ErrorResponse{
			Status:  status,
			Message: msg,
		}
	}
	grp := huma.NewGroup(api, "/v1")

	// Register root-level health and readiness endpoints (explicit type args)
	huma.Register(api, huma.Operation{
		OperationID: "health",
		Method:      http.MethodGet,
		Path:        "/health",
		Description: "Liveness probe that returns a plain 200.",
	}, func(ctx context.Context, _ *struct{}) (*struct{}, error) {
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ready",
		Method:      http.MethodGet,
		Path:        "/ready",
		Description: "Readiness probe that returns 200 if the service has storage access.",
	}, func(ctx context.Context, _ *struct{}) (*struct{}, error) {
		return nil, nil
	})

	// Register v1 endpoints
	huma.Register(grp, huma.Operation{
		OperationID: "verifier-results",
		Method:      http.MethodGet,
		Path:        "/verifierresults",
		Description: "Get verifier results",
	}, func(ctx context.Context, input *v1.VerifierResultsInput) (*v1.VerifierResultsResponse, error) {
		return nil, nil
	})

	huma.Register(grp, huma.Operation{
		OperationID: "verifier-results-by-message-id",
		Method:      http.MethodGet,
		Path:        "/verifierresults/{messageID}",
		Description: "Get message by ID",
	}, func(ctx context.Context, input *v1.VerifierResultsByMessageIDInput) (*v1.VerifierResultsByMessageIDResponse, error) {
		return nil, nil
	})

	huma.Register(grp, huma.Operation{
		OperationID: "messages",
		Method:      http.MethodGet,
		Path:        "/messages",
		Description: "Get messages",
	}, func(ctx context.Context, input *v1.MessagesInput) (*v1.MessagesResponse, error) {
		return nil, nil
	})

	oapi := api.OpenAPI()

	// Remove $schema properties from all schemas (it was only in ErrorResponse)
	if oapi.Components != nil {
		for _, schema := range oapi.Components.Schemas.Map() {
			delete(schema.Properties, "$schema")
		}
	}

	// yml, err := api.OpenAPI().Downgrade()
	yml, err := api.OpenAPI().DowngradeYAML()
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
