package ccv

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// RequireFullCLModeForEnvironmentChangeReconcile returns an error if the loaded env-out is not a
// fully Chainlink-backed devenv (topology NOPs CL, verifier and executor services in CL mode, node sets present).
// Environment-change reconcile E2E tests use this to skip standalone smoke env-outs.
func RequireFullCLModeForEnvironmentChangeReconcile(in *Cfg) error {
	if in == nil {
		return fmt.Errorf("cfg is nil")
	}
	if in.EnvironmentTopology == nil || in.EnvironmentTopology.NOPTopology == nil {
		return fmt.Errorf("environment_topology.nop_topology is required")
	}
	for _, nop := range in.EnvironmentTopology.NOPTopology.NOPs {
		if nop.GetMode() != ccvshared.NOPModeCL {
			ident := nop.Alias
			if ident == "" {
				ident = nop.Name
			}
			return fmt.Errorf("NOP %q must use topology mode %q for environment-change reconcile tests (got %q)",
				ident, ccvshared.NOPModeCL, nop.GetMode())
		}
	}
	for _, v := range in.Verifier {
		if v.Mode != services.CL {
			return fmt.Errorf("verifier for nop_alias %q must use mode %q (got %q)",
				v.NOPAlias, services.CL, v.Mode)
		}
	}
	for _, ex := range in.Executor {
		if ex.Mode != services.CL {
			return fmt.Errorf("executor must use mode %q (got %q)", services.CL, ex.Mode)
		}
	}
	if len(in.NodeSets) == 0 {
		return fmt.Errorf("at least one nodeset is required for CL mode")
	}
	return nil
}
