package evm

import (
	"fmt"

	"github.com/testcontainers/testcontainers-go"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// VerifierModifier adjusts committee verifier container requests for EVM.
func VerifierModifier(req testcontainers.ContainerRequest, verifierInput *committeeverifier.Input, outputs []*blockchain.Output) (testcontainers.ContainerRequest, error) {
	req.Name = fmt.Sprintf("evm-%s", verifierInput.ContainerName)
	return req, nil
}

// ExecutorModifier adjusts executor container requests for EVM.
func ExecutorModifier(req testcontainers.ContainerRequest, executorInput *executor.Input, outputs []*blockchain.Output) (testcontainers.ContainerRequest, error) {
	req.Name = fmt.Sprintf("evm-%s", executorInput.ContainerName)
	return req, nil
}
