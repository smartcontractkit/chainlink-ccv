package executor

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/sync/errgroup"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const configKey = "executor"

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("executor component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

func (c *component) ValidateConfig(componentConfig any) error {
	_, err := decode(componentConfig)
	return err
}

// RunPhase3 launches standalone executor containers, registers them with JD,
// and emits FundingEffect requests for transmitter addresses. Job spec
// generation and proposal are deferred to Phase 4 because they require
// deployed contract addresses.
func (c *component) RunPhase3(
	ctx context.Context,
	_ map[string]any,
	componentConfig any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	executors, err := decode(componentConfig)
	if err != nil {
		return nil, nil, err
	}
	if len(executors) == 0 {
		return map[string]any{configKey: executors}, nil, nil
	}

	blockchainOutputs, ok := priorOutputs["blockchainOutputs"].([]*ctfblockchain.Output)
	if !ok {
		return nil, nil, fmt.Errorf("phase 1 did not produce []*blockchain.Output under \"blockchainOutputs\"")
	}

	blockchains, _ := priorOutputs["blockchains"].([]*ctfblockchain.Input)

	jdInfra, ok := priorOutputs["jd"].(*jobs.JDInfrastructure)
	if !ok || jdInfra == nil {
		return nil, nil, fmt.Errorf("phase 2 did not produce *jobs.JDInfrastructure under \"jd\"")
	}

	for _, exec := range executors {
		if exec == nil {
			continue
		}
		executorsvc.ApplyDefaults(exec)
		if exec.Mode != services.Standalone {
			continue
		}
		out, err := executorsvc.New(exec, blockchainOutputs, jdInfra)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to launch executor %s: %w", exec.ContainerName, err)
		}
		exec.Out = out
	}

	if err := registerWithJD(ctx, executors, jdInfra); err != nil {
		return nil, nil, err
	}

	var effects []devenvruntime.Effect
	for _, exec := range executors {
		if exec == nil || exec.Mode != services.Standalone || exec.Out == nil {
			continue
		}
		addr := exec.Out.BootstrapKeys.EVMTransmitterAddress
		if addr == "" {
			continue
		}
		family := exec.ChainFamily
		if family == "" {
			family = chainsel.FamilyEVM
		}
		for _, bc := range blockchains {
			if bc == nil {
				continue
			}
			bcFamily, ferr := ctfblockchain.TypeToFamily(bc.Type)
			if ferr != nil || string(bcFamily) != family {
				continue
			}
			sel, serr := chainsel.GetChainDetailsByChainIDAndFamily(bc.ChainID, family)
			if serr != nil {
				continue
			}
			effects = append(effects, devenvruntime.FundingEffect{
				ChainSelector: sel.ChainSelector,
				Address:       addr,
				NativeAmount:  big.NewInt(5),
			})
		}
	}

	return map[string]any{configKey: executors}, effects, nil
}

// registerWithJD registers all standalone executors with JD and waits for their
// WSRPC connections. Mirrors the logic in environment.go:registerExecutorsWithJD.
func registerWithJD(ctx context.Context, executors []*executorsvc.Input, jdInfra *jobs.JDInfrastructure) error {
	var standalone []*executorsvc.Input
	for _, exec := range executors {
		if exec != nil && exec.Mode == services.Standalone && exec.Out != nil {
			standalone = append(standalone, exec)
		}
	}
	if len(standalone) == 0 {
		return nil
	}

	g, gCtx := errgroup.WithContext(ctx)
	var mu sync.Mutex

	for _, exec := range standalone {
		g.Go(func() error {
			if exec.Out.BootstrapKeys.CSAPublicKey == "" {
				return fmt.Errorf("executor %s started but CSAPublicKey not available", exec.ContainerName)
			}
			reg := &jobs.BootstrapJDRegistration{
				Name:         exec.ContainerName,
				CSAPublicKey: exec.Out.BootstrapKeys.CSAPublicKey,
			}
			if err := jobs.RegisterBootstrapWithJD(gCtx, jdInfra.OffchainClient, reg); err != nil {
				return fmt.Errorf("failed to register executor %s with JD: %w", exec.ContainerName, err)
			}
			mu.Lock()
			exec.Out.JDNodeID = reg.NodeID
			mu.Unlock()
			if err := jobs.WaitForBootstrapConnection(gCtx, jdInfra.OffchainClient, reg.NodeID, 60*time.Second); err != nil {
				return fmt.Errorf("executor %s failed to connect to JD: %w", exec.ContainerName, err)
			}
			return nil
		})
	}
	return g.Wait()
}

// decode round-trips the raw TOML []any into []*executorsvc.Input.
func decode(raw any) ([]*executorsvc.Input, error) {
	b, err := toml.Marshal(struct {
		V any `toml:"executor"`
	}{V: raw})
	if err != nil {
		return nil, fmt.Errorf("re-encoding executor config: %w", err)
	}
	var wrapper struct {
		V []*executorsvc.Input `toml:"executor"`
	}
	if err := toml.Unmarshal(b, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding executor config: %w", err)
	}
	return wrapper.V, nil
}
