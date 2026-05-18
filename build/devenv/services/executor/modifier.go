package executor

import (
	"github.com/testcontainers/testcontainers-go"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// ReqModifier modifies an executor testcontainers.ContainerRequest.
type ReqModifier func(
	req testcontainers.ContainerRequest,
	executorInput *Input,
	outputs []*blockchain.Output,
) (testcontainers.ContainerRequest, error)
