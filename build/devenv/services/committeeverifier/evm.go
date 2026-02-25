package committeeverifier

import (
	"fmt"

	"github.com/testcontainers/testcontainers-go"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// EVMModifier is a function that modifies a testcontainers.ContainerRequest for EVM.
// TODO: this should get moved to chainlink-evm and registered as a modifier prior to calling NewVerifier.
func EVMModifier(req testcontainers.ContainerRequest, verifierInput *Input, outputs []*blockchain.Output) (testcontainers.ContainerRequest, error) {
	// Update name to reflect chain family.
	req.Name = fmt.Sprintf("evm-%s", verifierInput.ContainerName)

	return req, nil
}
