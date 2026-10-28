package registration

import (
	"errors"

	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/domain"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

var _ cldf.ChangeSetV2[CsSaveNodesWithJDInput] = CsSaveNodesWithJD{}

type CsSaveNodesWithJD struct {
	Domain *domain.Domain
}

type CsSaveNodesWithJDInput struct {
	Domain string `json:"domain" yaml:"domain"`
}

func (cs CsSaveNodesWithJD) VerifyPreconditions(_ cldf.Environment, cfg CsSaveNodesWithJDInput) error {
	if cfg.Domain == "" {
		return errors.New("domain is required")
	}
	return nil
}

// Apply regenerates nodes.json from JD; any subsequent Git persistence is caller-owned.
func (cs CsSaveNodesWithJD) Apply(e cldf.Environment, input CsSaveNodesWithJDInput) (cldf.ChangesetOutput, error) {
	d := resolveDomain(cs.Domain, input.Domain)
	deps := SaveNodesJSONDeps{JDClient: e.Offchain, Domain: d, EnvKey: e.Name}
	report, err := operations.ExecuteOperation(
		e.OperationsBundle,
		SaveNodesJSON,
		deps,
		operations.EmptyInput{},
		operations.WithForceExecute[operations.EmptyInput, SaveNodesJSONDeps](),
	)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}

	e.Logger.Infow("saved nodes.json from JD", "path", report.Output.Path, "node_count", report.Output.NodeCount)
	return cldf.ChangesetOutput{}, nil
}
