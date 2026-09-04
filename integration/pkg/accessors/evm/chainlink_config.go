package evm

import (
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	clevmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
)

// newChainlinkEVMConfig is the single adapter from CCV's focused standalone
// configuration to chainlink-evm's full configuration model. Keeping the
// boundary explicit prevents additions to the upstream config from silently
// becoming operator-facing CCV settings. Chain-specific upstream defaults are
// used for every setting that CCV does not intentionally override in
// evmconfig.BuildChainlinkEVMTOML.
func newChainlinkEVMConfig(info Info) (*clevmconfig.ChainScoped, error) {
	tomlConfig, err := evmconfig.BuildChainlinkEVMTOML(info)
	if err != nil {
		return nil, err
	}
	return clevmconfig.NewTOMLChainScopedConfig(tomlConfig), nil
}
