package changesets

import (
	"errors"
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

func standaloneExecutorJobNodeIDs(e deployment.Environment, cfg ApplyExecutorConfigInput) (map[shared.JobID]string, error) {
	if e.Offchain == nil || len(adapters.AllDeployedExecutorChains(e.DataStore, cfg.ExecutorQualifier)) == 0 {
		return nil, nil
	}

	nopInputs := make(map[shared.NOPAlias]NOPInput, len(cfg.NOPs))
	for _, nop := range cfg.NOPs {
		nopInputs[nop.Alias] = nop
	}
	targets := cfg.TargetNOPs
	if len(targets) == 0 {
		targets = executorPoolNOPAliases(cfg.Pool)
	}
	standaloneTargets := make([]NOPInput, 0, len(targets))
	for _, alias := range targets {
		nop := nopInputs[alias]
		mode, err := resolveNOPMode(nop.Mode, alias)
		if err != nil {
			return nil, err
		}
		if mode == shared.NOPModeStandalone {
			standaloneTargets = append(standaloneTargets, nop)
		}
	}
	if len(standaloneTargets) == 0 {
		return nil, nil
	}

	allowedNodeIDs := shared.NodeIDsToSet(e.NodeIDs)
	allJobs, err := ccvdeployment.GetAllJobs(e.DataStore)
	if err != nil && !errors.Is(err, datastore.ErrEnvMetadataNotSet) {
		return nil, fmt.Errorf("failed to load executor job metadata: %w", err)
	}

	nodeIDs := make(map[shared.JobID]string, len(standaloneTargets))
	for _, nop := range standaloneTargets {
		jobID := shared.NewExecutorJobID(nop.Alias, shared.ExecutorJobScope{
			ExecutorQualifier: cfg.ExecutorQualifier,
		}).ToJobID()
		nodeID, err := standaloneExecutorNodeID(nop, jobID, allJobs)
		if err != nil {
			return nil, err
		}
		if !allowedNodeIDs[nodeID] {
			return nil, fmt.Errorf("standalone executor job %q targets node %q outside the environment node list", jobID, nodeID)
		}
		nodeIDs[jobID] = nodeID
	}

	return nodeIDs, nil
}

func standaloneExecutorNodeID(nop NOPInput, jobID shared.JobID, allJobs shared.NOPJobs) (string, error) {
	explicitNodeID := nop.ExecutorNodeID
	existing, exists := allJobs[nop.Alias][jobID]
	if !exists {
		if explicitNodeID == "" {
			return "", fmt.Errorf("standalone executor job %q has no JD metadata; set ExecutorNodeID for initial provisioning or run ReconcileJobsWithJD", jobID)
		}
		return explicitNodeID, nil
	}
	if existing.JobID != jobID || existing.NOPAlias != nop.Alias {
		return "", fmt.Errorf("standalone executor job %q has inconsistent datastore identity", jobID)
	}
	if existing.Mode != shared.NOPModeStandalone {
		if explicitNodeID == "" {
			return "", fmt.Errorf("standalone executor job %q has %q-mode JD metadata; run ReconcileJobsWithJD or set ExecutorNodeID", jobID, existing.Mode)
		}
		return explicitNodeID, nil
	}
	if existing.JDJobID == "" || existing.NodeID == "" || existing.ExternalJobID != jobID.ToExternalJobID() {
		return "", fmt.Errorf("standalone executor job %q has incomplete JD metadata; run ReconcileJobsWithJD", jobID)
	}
	if explicitNodeID != "" && explicitNodeID != existing.NodeID {
		return "", fmt.Errorf("standalone executor job %q explicit node ID %q conflicts with reconciled node ID %q", jobID, explicitNodeID, existing.NodeID)
	}
	if explicitNodeID != "" {
		return explicitNodeID, nil
	}
	return existing.NodeID, nil
}
