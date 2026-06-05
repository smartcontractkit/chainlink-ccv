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
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// LaunchStandaloneVerifiers starts standalone verifier containers. Each verifier reads HMAC
// credentials from the matching aggregator output (matched by CommitteeName + NodeIndex).
// Callers must populate agg.Out (at minimum agg.Out.ClientCredentials) before calling.
// modifiers is a map from chain family to ReqModifier (obtain via chainreg.GetRegistry().GetVerifierModifiers()).
func LaunchStandaloneVerifiers(
	verifiers []*Input,
	aggregators []*services.AggregatorInput,
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
