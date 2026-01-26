package canton

// Endpoints represents the endpoints for a canton blockchain.
type Endpoints struct {
	// GRPCLedgerAPIURL is the URL of the gRPC ledger API.
	// https://docs.digitalasset.com/build/3.5/reference/lapi-proto-docs.html
	GRPCLedgerAPIURL string
	// JWT is the JWT to use to authenticate with the gRPC ledger APIs.
	JWT string
}
