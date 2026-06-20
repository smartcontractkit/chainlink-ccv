package committeeverifier

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// CommitteeAggregatorNames returns, per committee, the ordered topology aggregator names. The
// order matches the per-committee aggregator outputs (TOML order plus expansion clones), so the
// two can be zipped by index. Used to key a verifier's per-aggregator credentials by the same
// name the verifier config carries.
func CommitteeAggregatorNames(topology *ccvdeployment.EnvironmentTopology) map[string][]string {
	result := make(map[string][]string)
	if topology == nil || topology.NOPTopology == nil {
		return result
	}
	for name, committee := range topology.NOPTopology.Committees {
		names := make([]string, len(committee.Aggregators))
		for i, a := range committee.Aggregators {
			names[i] = a.Name
		}
		result[name] = names
	}
	return result
}

// AggregatorCredentialsForVerifier builds the verifier's per-aggregator HMAC credentials, keyed by
// aggregator topology name. aggOuts and aggNames must be index-aligned (committee aggregator
// order). Each aggregator issues its own credential for the verifier, so a consolidated verifier
// (writing to all of them) needs one credential per aggregator.
func AggregatorCredentialsForVerifier(containerName string, aggOuts []*services.AggregatorOutput, aggNames []string) (map[string]hmacutil.Credentials, error) {
	if len(aggNames) != len(aggOuts) {
		return nil, fmt.Errorf("verifier %q: %d aggregator outputs but %d topology names — cannot map credentials", containerName, len(aggOuts), len(aggNames))
	}
	creds := make(map[string]hmacutil.Credentials, len(aggOuts))
	for i, out := range aggOuts {
		name := aggNames[i]
		if name == "" {
			return nil, fmt.Errorf("verifier %q: aggregator at index %d has no topology name", containerName, i)
		}
		c, ok := out.GetCredentialsForClient(containerName)
		if !ok {
			return nil, fmt.Errorf("verifier %q: no HMAC credentials issued by aggregator %q", containerName, name)
		}
		creds[name] = c
	}
	return creds, nil
}

// LaunchStandaloneVerifiers starts standalone verifier containers. Each verifier authenticates to
// every aggregator in its committee with that aggregator's own HMAC credential; committeeAggNames
// maps committee -> ordered topology aggregator names (zipped by index with the committee's
// aggregator outputs) so those credentials can be keyed by name.
// Callers must populate agg.Out (at minimum agg.Out.ClientCredentials) before calling.
// modifiers is a map from chain family to ReqModifier (obtain via chainreg.GetRegistry().GetVerifierModifiers()).
func LaunchStandaloneVerifiers(
	verifiers []*Input,
	aggregators []*services.AggregatorInput,
	committeeAggNames map[string][]string,
	blockchainOutputs []*blockchain.Output,
	jdInfra *jobs.JDInfrastructure,
	modifiers map[string]ReqModifier,
) error {
	aggregatorsByCommittee := make(map[string][]*services.AggregatorOutput)
	for _, agg := range aggregators {
		if agg.Out != nil {
			aggregatorsByCommittee[agg.CommitteeName] = append(aggregatorsByCommittee[agg.CommitteeName], agg.Out)
		}
	}

	for i := range verifiers {
		ver := ApplyDefaults(*verifiers[i])
		verifiers[i] = &ver
	}

	for _, ver := range verifiers {
		if ver.Mode != services.Standalone {
			continue
		}
		aggOuts := aggregatorsByCommittee[ver.CommitteeName]
		if len(aggOuts) == 0 {
			return fmt.Errorf("verifier %q (committee %q): no aggregator outputs found", ver.ContainerName, ver.CommitteeName)
		}
		creds, err := AggregatorCredentialsForVerifier(ver.ContainerName, aggOuts, committeeAggNames[ver.CommitteeName])
		if err != nil {
			return err
		}
		ver.AggregatorCredentials = creds
		ver.AggregatorOutput = aggOuts[ver.NodeIndex%len(aggOuts)]
		out, err := New(ver, blockchainOutputs, jdInfra, modifiers)
		if err != nil {
			return fmt.Errorf("failed to create verifier service: %w", err)
		}
		ver.Out = out
	}
	return nil
}

// RegisterStandaloneVerifiersWithJD registers standalone verifiers with JD in parallel
// and waits for each to establish its WSRPC connection.
func RegisterStandaloneVerifiersWithJD(ctx context.Context, verifiers []*Input, jdClient offchain.Client) error {
	var standalone []*Input
	for _, ver := range verifiers {
		if ver.Mode == services.Standalone {
			standalone = append(standalone, ver)
		}
	}
	if len(standalone) == 0 {
		return nil
	}

	g, gCtx := errgroup.WithContext(ctx)
	var mu sync.Mutex
	for _, ver := range standalone {
		g.Go(func() error {
			if ver.Out == nil || ver.Out.BootstrapKeys.CSAPublicKey == "" {
				return fmt.Errorf("bootstrap %s started but CSAPublicKey not available", ver.ContainerName)
			}
			reg := &jobs.BootstrapJDRegistration{
				Name:         ver.ContainerName,
				CSAPublicKey: ver.Out.BootstrapKeys.CSAPublicKey,
			}
			if err := jobs.RegisterBootstrapWithJD(gCtx, jdClient, reg); err != nil {
				return fmt.Errorf("failed to register bootstrap %s with JD: %w", ver.ContainerName, err)
			}
			mu.Lock()
			ver.Out.JDNodeID = reg.NodeID
			mu.Unlock()
			if err := jobs.WaitForBootstrapConnection(gCtx, jdClient, reg.NodeID, 60*time.Second); err != nil {
				return fmt.Errorf("bootstrap %s failed to connect to JD: %w", ver.ContainerName, err)
			}
			return nil
		})
	}
	return g.Wait()
}
