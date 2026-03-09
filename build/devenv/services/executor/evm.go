package executor

import (
	"fmt"

	"github.com/testcontainers/testcontainers-go"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// EVMModifier is a function that modifies a testcontainers.ContainerRequest for EVM.
// TODO: this should get moved to chainlink-evm and registered as a modifier prior to calling New.
func EVMModifier(req testcontainers.ContainerRequest, executorInput *Input, outputs []*blockchain.Output) (testcontainers.ContainerRequest, error) {
	req.Name = fmt.Sprintf("evm-%s", executorInput.ContainerName)

	return req, nil
}
