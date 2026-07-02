package chaos

import (
	"fmt"
	"strings"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
)

func normalizeContainerName(name string) string {
	return strings.TrimPrefix(name, "/")
}

// DefaultAggregatorNginx returns the nginx TLS proxy container name for the given
// committee's aggregator.
func DefaultAggregatorNginx(cfg *ccv.Cfg, committeeQualifier string) (string, error) {
	for _, agg := range cfg.Aggregator {
		if agg.CommitteeName != committeeQualifier || agg.Out == nil {
			continue
		}
		name := normalizeContainerName(agg.Out.NginxContainerName)
		if name != "" {
			return name, nil
		}
	}
	return "", fmt.Errorf("aggregator nginx container not found for committee %q", committeeQualifier)
}

// VerifierFilter selects verifier inputs for container resolution.
type VerifierFilter func(*committeeverifier.Input) bool

// VerifierContainers returns Docker container names for verifiers in the given
// committee. filter, when non-nil, restricts which verifiers are included.
func VerifierContainers(cfg *ccv.Cfg, committeeQualifier string, filter VerifierFilter) ([]string, error) {
	var names []string
	for _, verifier := range cfg.Verifier {
		if verifier.CommitteeName != committeeQualifier || verifier.Out == nil {
			continue
		}
		if filter != nil && !filter(verifier) {
			continue
		}
		name := normalizeContainerName(verifier.Out.ContainerName)
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no verifier containers found for committee %q", committeeQualifier)
	}
	return names, nil
}

// ExecutorContainers returns Docker container names for executors matching
// executorQualifier. nopAliases, when non-empty, restricts to executors whose
// NOP alias is in the list.
func ExecutorContainers(cfg *ccv.Cfg, executorQualifier string, nopAliases ...string) ([]string, error) {
	aliasSet := make(map[string]struct{}, len(nopAliases))
	for _, alias := range nopAliases {
		aliasSet[alias] = struct{}{}
	}

	var names []string
	for _, exec := range cfg.Executor {
		qualifier := exec.ExecutorQualifier
		if qualifier == "" {
			qualifier = devenvcommon.DefaultExecutorQualifier
		}
		if qualifier != executorQualifier || exec.Out == nil {
			continue
		}
		if len(aliasSet) > 0 {
			if _, ok := aliasSet[exec.NOPAlias]; !ok {
				continue
			}
		}
		name := normalizeContainerName(exec.Out.ContainerName)
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no executor containers found for qualifier %q", executorQualifier)
	}
	return names, nil
}

// ExecutorContainersForDest returns executors assigned to serve destSelector in the
// given executor pool, resolved via EnvironmentTopology.
func ExecutorContainersForDest(cfg *ccv.Cfg, destSelector uint64, executorQualifier string) ([]string, error) {
	if cfg.EnvironmentTopology == nil {
		return nil, fmt.Errorf("environment topology is nil")
	}
	pool, ok := cfg.EnvironmentTopology.ExecutorPools[executorQualifier]
	if !ok {
		return nil, fmt.Errorf("executor pool %q not found in topology", executorQualifier)
	}
	destStr := fmt.Sprintf("%d", destSelector)
	chainCfg, ok := pool.ChainConfigs[destStr]
	if !ok {
		return nil, fmt.Errorf("dest chain %d not found in executor pool %q", destSelector, executorQualifier)
	}
	return ExecutorContainers(cfg, executorQualifier, chainCfg.NOPAliases...)
}

// IndexerContainer returns the Docker container name for the indexer at index.
func IndexerContainer(cfg *ccv.Cfg, index int) (string, error) {
	if index < 0 || index >= len(cfg.Indexer) {
		return "", fmt.Errorf("indexer index %d out of range (have %d)", index, len(cfg.Indexer))
	}
	indexer := cfg.Indexer[index]
	if indexer.Out == nil {
		return "", fmt.Errorf("indexer %d has no output", index)
	}
	name := normalizeContainerName(indexer.Out.ContainerName)
	if name == "" {
		return "", fmt.Errorf("indexer %d container name is empty", index)
	}
	return name, nil
}
