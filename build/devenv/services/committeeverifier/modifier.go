package committeeverifier

import (
	"github.com/testcontainers/testcontainers-go"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// ReqModifier modifies a committee verifier testcontainers.ContainerRequest.
type ReqModifier func(
	req testcontainers.ContainerRequest,
	verifierInput *Input,
	outputs []*blockchain.Output,
) (testcontainers.ContainerRequest, error)
