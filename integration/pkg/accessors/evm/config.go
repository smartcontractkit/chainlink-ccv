package evm

import (
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
)

// The operator-facing EVM config types live in the evmconfig package, which registers no accessor
// factory, so config readers and converters — devenv, configdoc, `ccv migrate inspect-config` — can
// depend on them without pulling the EVM driver into a binary that runs no EVM chains. These
// aliases keep the accessor's own API spelled the way its callers already spell it.
type (
	Config      = evmconfig.Config
	ChainConfig = evmconfig.ChainConfig
	Node        = evmconfig.Node
	Info        = evmconfig.Info
	Conversion  = evmconfig.Conversion
)

const (
	EVMConfigPathEnv     = evmconfig.EVMConfigPathEnv
	DefaultEVMConfigPath = evmconfig.DefaultEVMConfigPath
)

// NewConfigFromInfos builds operator config from the enumeration-oriented Infos[Info] produced by
// devenv, dropping metadata derived from the selector.
var NewConfigFromInfos = evmconfig.NewConfigFromInfos
