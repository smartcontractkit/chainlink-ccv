module github.com/smartcontractkit/chainlink-ccv/executor

go 1.24.6

require (
	github.com/smartcontractkit/chainlink-ccv/protocol v0.0.0-20251003135849-403255766628
	github.com/smartcontractkit/chainlink-common v0.9.6-0.20250929154511-1f5fbda7ae76
	github.com/stretchr/testify v1.11.1
	go.uber.org/zap v1.27.0
	golang.org/x/sync v0.16.0
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/ethereum/go-ethereum v1.16.3 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/smartcontractkit/libocr v0.0.0-20250905115425-2785a5cee79d // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/fbsobreira/gotron-sdk => github.com/smartcontractkit/chainlink-tron/relayer/gotron-sdk v0.0.5-0.20250528121202-292529af39df

	github.com/smartcontractkit/chainlink-ccv/common => ../common
	github.com/smartcontractkit/chainlink-ccv/protocol => ../protocol
)
