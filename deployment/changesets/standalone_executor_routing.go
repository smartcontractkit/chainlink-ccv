package changesets

import (
	"errors"
	"fmt"
	"sort"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// standaloneExecutorNodeIDs resolves the JD node of each targeted standalone executor NOP.
// A declared node wins and moves the job; otherwise the recorded standalone node is reused.
func standaloneExecutorNodeIDs(e deployment.Environment, cfg ApplyExecutorConfigInput) (map[shared.NOPAlias]string, error) {
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

	allJobs, err := ccvdeployment.GetAllJobs(e.DataStore)
	if err != nil && !errors.Is(err, datastore.ErrEnvMetadataNotSet) {
		return nil, fmt.Errorf("failed to load executor job metadata: %w", err)
	}
	declared, err := declaredExecutorNodeIDs(e, standaloneTargets)
	if err != nil {
		return nil, err
	}

	allowedNodeIDs := shared.NodeIDsToSet(e.NodeIDs)
	routedJobs := make(map[string]shared.JobID, len(standaloneTargets))
	nodeIDs := make(map[shared.NOPAlias]string, len(standaloneTargets))
	for _, nop := range standaloneTargets {
		jobID := executorJobID(nop.Alias, cfg.ExecutorQualifier)
		nodeID, err := standaloneExecutorNodeID(nop.Alias, jobID, declared[nop.Alias], allJobs)
		if err != nil {
			return nil, err
		}
		if !allowedNodeIDs[nodeID] {
			return nil, fmt.Errorf("standalone executor job %q targets node %q outside the environment node list", jobID, nodeID)
		}
		if other, ok := routedJobs[nodeID]; ok {
			return nil, fmt.Errorf("standalone executor jobs %q and %q both target node %q; each executor needs its own JD node", other, jobID, nodeID)
		}
		if other := otherJobOnNode(allJobs, nodeID, nop.Alias, jobID); other != "" {
			return nil, fmt.Errorf("standalone executor job %q targets node %q, which already runs job %q; a standalone node runs one job", jobID, nodeID, other)
		}
		routedJobs[nodeID] = jobID
		nodeIDs[nop.Alias] = nodeID
	}

	return nodeIDs, nil
}

// standaloneExecutorJobNodeIDs keys the resolved nodes by executor job ID for ManageJobProposals.
func standaloneExecutorJobNodeIDs(qualifier string, nodeIDs map[shared.NOPAlias]string) map[shared.JobID]string {
	if len(nodeIDs) == 0 {
		return nil
	}
	byJob := make(map[shared.JobID]string, len(nodeIDs))
	for alias, nodeID := range nodeIDs {
		byJob[executorJobID(alias, qualifier)] = nodeID
	}
	return byJob
}

func executorJobID(alias shared.NOPAlias, qualifier string) shared.JobID {
	return shared.NewExecutorJobID(alias, shared.ExecutorJobScope{ExecutorQualifier: qualifier}).ToJobID()
}

// declaredExecutorNodeIDs resolves each NOP's declared executor node, given by JD node ID or name.
func declaredExecutorNodeIDs(e deployment.Environment, nops []NOPInput) (map[shared.NOPAlias]string, error) {
	declared := make(map[shared.NOPAlias]string, len(nops))
	var byName []NOPInput
	for _, nop := range nops {
		switch {
		case nop.ExecutorNodeName != "":
			byName = append(byName, nop)
		case nop.ExecutorNodeID != "":
			declared[nop.Alias] = nop.ExecutorNodeID
		}
	}
	if len(byName) == 0 {
		return declared, nil
	}

	lookup, err := shared.FetchNodeLookup(e.GetContext(), e.Offchain, e.NodeIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve executor node names: %w", err)
	}
	for _, nop := range byName {
		node, ok := lookup.FindByName(nop.ExecutorNodeName)
		if !ok {
			return nil, fmt.Errorf("NOP %q executor node %q is not a JD node in the environment", nop.Alias, nop.ExecutorNodeName)
		}
		if nop.ExecutorNodeID != "" && nop.ExecutorNodeID != node.GetId() {
			return nil, fmt.Errorf("NOP %q executor node %q has ID %q, not ExecutorNodeID %q", nop.Alias, nop.ExecutorNodeName, node.GetId(), nop.ExecutorNodeID)
		}
		declared[nop.Alias] = node.GetId()
	}
	return declared, nil
}

func standaloneExecutorNodeID(alias shared.NOPAlias, jobID shared.JobID, declared string, allJobs shared.NOPJobs) (string, error) {
	if declared != "" {
		return declared, nil
	}
	existing, exists := allJobs[alias][jobID]
	switch {
	case !exists || (existing.JDJobID == "" && existing.NodeID == ""):
		return "", fmt.Errorf("standalone executor job %q has no JD node; set the NOP's ExecutorNodeName or ExecutorNodeID", jobID)
	case existing.Mode != shared.NOPModeStandalone:
		return "", fmt.Errorf("standalone executor job %q is recorded in %q mode; set the NOP's ExecutorNodeName or ExecutorNodeID to move it", jobID, existing.Mode)
	case existing.JobID != jobID || existing.NOPAlias != alias || existing.JDJobID == "" || existing.NodeID == "" ||
		existing.ExternalJobID != jobID.ToExternalJobID():
		return "", fmt.Errorf("standalone executor job %q has incomplete JD metadata; set the NOP's ExecutorNodeName or ExecutorNodeID, or run ReconcileJobsWithJD", jobID)
	}
	return existing.NodeID, nil
}

// otherJobOnNode returns a recorded job, other than alias/jobID, whose JD node is nodeID.
func otherJobOnNode(allJobs shared.NOPJobs, nodeID string, alias shared.NOPAlias, jobID shared.JobID) shared.JobID {
	var others []string
	for nopAlias, jobs := range allJobs {
		for id, job := range jobs {
			if job.NodeID == nodeID && (nopAlias != alias || id != jobID) {
				others = append(others, string(id))
			}
		}
	}
	if len(others) == 0 {
		return ""
	}
	sort.Strings(others)
	return shared.JobID(others[0])
}
