package registration

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/domain"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

type RegisterNodeInput struct {
	Name        string            `json:"name"`
	CSAKey      string            `json:"csa_key"`
	IsBootstrap bool              `json:"is_bootstrap"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type RegisterNodeDeps struct {
	JDClient offchain.Client
	Domain   domain.Domain
	EnvKey   string
}

type RegisterNodeOutput struct {
	NodeID        string `json:"node_id"`
	WasRegistered bool   `json:"was_registered"`
}

// RegisterNodeWithJD registers one node or reconciles its existing registration.
var RegisterNodeWithJD = operations.NewOperation(
	"register-node-with-jd",
	semver.MustParse("1.0.0"),
	"Registers a NOP in JD with product and environment labels, reusing nodes already registered",
	func(b operations.Bundle, deps RegisterNodeDeps, input RegisterNodeInput) (RegisterNodeOutput, error) {
		result, err := Register(b.GetContext(), deps.JDClient, StaticCSAKeyProvider(input.CSAKey), NodeSpec{
			Name:        input.Name,
			Product:     deps.Domain.Key(),
			Environment: deps.EnvKey,
			IsBootstrap: input.IsBootstrap,
			Labels:      input.Labels,
		})
		if err != nil {
			return RegisterNodeOutput{}, fmt.Errorf("failed to register node %s with JD: %w", input.Name, err)
		}
		return RegisterNodeOutput{
			NodeID:        result.NodeID,
			WasRegistered: result.Status == StatusRegistered,
		}, nil
	},
)
