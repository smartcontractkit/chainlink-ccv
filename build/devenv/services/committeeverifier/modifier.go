package committeeverifier

import (
	"github.com/testcontainers/testcontainers-go"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

var modifierPerFamily = map[string]ReqModifier{}

// ReqModifier is a function that modifies a committee verifier testcontainers.ContainerRequest.
type ReqModifier func(
	req testcontainers.ContainerRequest,
	verifierInput *Input,
	outputs []*blockchain.Output,
) (testcontainers.ContainerRequest, error)

// RegisterModifier registers a modifier for a given chain family.
func RegisterModifier(chainFamily string, modifier ReqModifier) {
	modifierPerFamily[chainFamily] = modifier
}

func init() {
	// NOTE: these will eventually be removed as modifiers are moved to chain implementation repos.
	RegisterModifier(chainsel.FamilyEVM, EVMModifier)
}
