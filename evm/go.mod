module github.com/smartcontractkit/chainlink-ccv/evm

go 1.25.7

replace (
	github.com/fbsobreira/gotron-sdk => github.com/smartcontractkit/chainlink-tron/relayer/gotron-sdk v0.0.4
	github.com/smartcontractkit/chainlink-ccv => ..
	github.com/smartcontractkit/chainlink-ccv/deployment => ../deployment
)

require (
	github.com/smartcontractkit/chain-selectors v1.0.98
	github.com/smartcontractkit/chainlink-ccv/deployment v0.0.1
	github.com/smartcontractkit/chainlink-protos/job-distributor v0.18.0
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260401024825-9d38bb4040a9 // indirect
	google.golang.org/grpc v1.80.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
