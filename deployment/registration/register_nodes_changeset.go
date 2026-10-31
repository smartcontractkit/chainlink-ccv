package registration

import (
	"errors"
	"fmt"

	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/domain"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

var _ cldf.ChangeSetV2[CsRegisterNodesWithJDInput] = CsRegisterNodesWithJD{}

type CsRegisterNodesWithJD struct {
	Domain *domain.Domain
}

type CsRegisterNodesWithJDInput struct {
	Domain string             `json:"domain" yaml:"domain"`
	Nodes  []NodeToRegisterJD `json:"nodes"  yaml:"nodes"`
}

type NodeToRegisterJD struct {
	Name        string            `json:"name"         yaml:"name"`
	CSAKey      string            `json:"csa_key"      yaml:"csa_key"`
	IsBootstrap bool              `json:"is_bootstrap" yaml:"is_bootstrap"`
	Labels      map[string]string `json:"labels"       yaml:"labels"`
}

func (cs CsRegisterNodesWithJD) VerifyPreconditions(_ cldf.Environment, cfg CsRegisterNodesWithJDInput) error {
	if cfg.Domain == "" {
		return errors.New("domain is required")
	}
	if len(cfg.Nodes) == 0 {
		return errors.New("no nodes provided in input")
	}
	seenNames := make(map[string]struct{}, len(cfg.Nodes))
	seenCSAKeys := make(map[string]struct{}, len(cfg.Nodes))
	for _, node := range cfg.Nodes {
		if node.Name == "" {
			return errors.New("node name cannot be empty")
		}
		if node.CSAKey == "" {
			return errors.New("node CSA key cannot be empty for node " + node.Name)
		}
		if _, ok := seenNames[node.Name]; ok {
			return errors.New("duplicate node name in input: " + node.Name)
		}
		seenNames[node.Name] = struct{}{}
		if _, ok := seenCSAKeys[node.CSAKey]; ok {
			return errors.New("duplicate csa_key in input for node " + node.Name)
		}
		seenCSAKeys[node.CSAKey] = struct{}{}
	}
	return nil
}

func (cs CsRegisterNodesWithJD) Apply(e cldf.Environment, input CsRegisterNodesWithJDInput) (cldf.ChangesetOutput, error) {
	d := resolveDomain(cs.Domain, input.Domain)
	deps := RegisterNodeDeps{JDClient: e.Offchain, Domain: d, EnvKey: e.Name}

	var registered, skipped, failed int
	for _, node := range input.Nodes {
		report, err := operations.ExecuteOperation(
			e.OperationsBundle,
			RegisterNodeWithJD,
			deps,
			RegisterNodeInput(node),
			operations.WithForceExecute[RegisterNodeInput, RegisterNodeDeps](),
		)
		if err != nil {
			failed++
			e.Logger.Errorw("failed to register node with JD", "name", node.Name, "error", err)
			continue
		}

		if report.Output.WasRegistered {
			registered++
			e.Logger.Infow("registered node with JD", "name", node.Name, "id", report.Output.NodeID)
		} else {
			skipped++
			e.Logger.Infow("node already registered in JD", "name", node.Name, "id", report.Output.NodeID)
		}
	}

	e.Logger.Infow("jd_register_nodes complete",
		"total", len(input.Nodes),
		"registered", registered,
		"skipped", skipped,
		"failed", failed,
	)
	if failed > 0 {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to register %d of %d nodes", failed, len(input.Nodes))
	}

	saveDeps := SaveNodesJSONDeps{JDClient: e.Offchain, Domain: d, EnvKey: e.Name}
	if _, err := operations.ExecuteOperation(
		e.OperationsBundle,
		SaveNodesJSON,
		saveDeps,
		operations.EmptyInput{},
		operations.WithForceExecute[operations.EmptyInput, SaveNodesJSONDeps](),
	); err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to write nodes.json after registration: %w", err)
	}
	return cldf.ChangesetOutput{}, nil
}

func resolveDomain(override *domain.Domain, key string) domain.Domain {
	if override != nil {
		return *override
	}
	return domain.MustGetDomain(key)
}
