package committeeverifier

import (
	"github.com/testcontainers/testcontainers-go"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

var modifierPerFamily = map[string]ReqModifier{}

// ReqModifier modifies a committee verifier testcontainers.ContainerRequest.
type ReqModifier func(
	req testcontainers.ContainerRequest,
	verifierInput *Input,
	outputs []*blockchain.Output,
) (testcontainers.ContainerRequest, error)

// SetModifier registers a modifier for a chain family. Called from chainreg when a family is registered.
func SetModifier(chainFamily string, modifier ReqModifier) {
	modifierPerFamily[chainFamily] = modifier
}
