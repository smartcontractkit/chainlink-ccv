// Generates OpenAPI spec for Indexer API v1.
package main

import (
	"context"
	"net/http"
	"os"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
)

func main() {
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
		panic(err)
	}

	_, _ = os.Stdout.Write(yml)
}
