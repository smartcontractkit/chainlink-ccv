module github.com/smartcontractkit/chainlink-ccv/executor

go 1.24.6

require (
	github.com/smartcontractkit/chainlink-ccv/protocol v0.0.0-00010101000000-000000000000
	github.com/smartcontractkit/chainlink-common v0.9.4
	github.com/stretchr/testify v1.11.1
	go.uber.org/zap v1.27.0
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/ethereum/go-ethereum v1.16.3 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/smartcontractkit/libocr v0.0.0-20250408131511-c90716988ee0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/smartcontractkit/chainlink-ccv/protocol => ../protocol
