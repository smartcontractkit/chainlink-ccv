module github.com/smartcontractkit/chainlink-ccv/protocol

go 1.24.6

require (
	github.com/ethereum/go-ethereum v1.16.3
	github.com/smartcontractkit/chainlink-ccv/aggregator v0.0.0
	github.com/smartcontractkit/chainlink-common v0.9.4
	github.com/stretchr/testify v1.11.1
)

replace github.com/smartcontractkit/chainlink-ccv/aggregator => ../aggregator

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/smartcontractkit/chain-selectors v1.0.62 // indirect
	github.com/smartcontractkit/libocr v0.0.0-20250408131511-c90716988ee0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	google.golang.org/grpc v1.75.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
