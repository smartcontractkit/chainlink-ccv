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
	"github.com/smartcontractkit/chainlink-ccv/protocol"
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

// RunPhase3 launches a single standalone executor container, registers it with
// JD, and emits FundingEffect requests for its transmitter address. Job spec
// generation and proposal are deferred to Phase 4 because they require
// deployed contract addresses.
//
// Each [[executor]] entry creates a separate component instance. The runtime
// accumulates the length-1 slices across instances into the final slice.
func (c *component) RunPhase3(
	ctx context.Context,
	_ map[string]any,
	componentConfig any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	exec, err := decode(componentConfig)
	if err != nil {
		return nil, nil, err
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

	executorsvc.ApplyDefaults(exec)
	if exec.Mode == services.Standalone {
		out, err := executorsvc.New(exec, blockchainOutputs, jdInfra)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to launch executor %s: %w", exec.ContainerName, err)
		}
		exec.Out = out
		if err := registerWithJD(ctx, exec, jdInfra); err != nil {
			return nil, nil, err
		}
	}

	var effects []devenvruntime.Effect
	if exec.Mode == services.Standalone && exec.Out != nil {
		addrStr := exec.Out.BootstrapKeys.EVMTransmitterAddress
		if addrStr != "" {
			addr, addrErr := protocol.NewUnknownAddressFromHex(addrStr)
			if addrErr != nil {
				return nil, nil, fmt.Errorf("executor %s invalid transmitter address: %w", exec.ContainerName, addrErr)
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
	}

	return map[string]any{configKey: []*executorsvc.Input{exec}}, effects, nil
}

// registerWithJD registers a single standalone executor with JD and waits for
// its WSRPC connection.
func registerWithJD(ctx context.Context, exec *executorsvc.Input, jdInfra *jobs.JDInfrastructure) error {
	if exec.Out == nil {
		return nil
	}

	g, gCtx := errgroup.WithContext(ctx)
	var mu sync.Mutex

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
	return g.Wait()
}

// decode round-trips a single raw TOML map[string]any into *executorsvc.Input.
func decode(raw any) (*executorsvc.Input, error) {
	b, err := toml.Marshal(struct {
		V any `toml:"executor"`
	}{V: raw})
	if err != nil {
		return nil, fmt.Errorf("re-encoding executor config: %w", err)
	}
	var wrapper struct {
		V *executorsvc.Input `toml:"executor"`
	}
	if err := toml.Unmarshal(b, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding executor config: %w", err)
	}
	return wrapper.V, nil
}
