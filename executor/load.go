package executor

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

// cfgWithBlockchainInfos is used only for decoding; T is the chain config type
// (e.g. blockchain.Info for EVM, ReaderConfig for Stellar). Decoding into this
// struct allows strict Undecoded() checking for the whole config, including
// keys under blockchain_infos.
type cfgWithBlockchainInfos[T any] struct {
	Configuration
	BlockchainInfos map[string]*T `toml:"blockchain_infos"`
}

// LoadConfigWithBlockchainInfos decodes the executor config from the job spec
// into a strongly-typed map[string]*T. The type T is chosen by the caller (e.g.
// blockchain.Info for EVM). Strict decode is applied: any unknown key in the
// config (including under blockchain_infos.<selector>) causes an error.
// The returned Configuration has defaults applied via GetNormalizedConfig.
func LoadConfigWithBlockchainInfos[T any](spec JobSpec) (*Configuration, map[string]*T, error) {
	var decodeTarget cfgWithBlockchainInfos[T]
	md, err := toml.Decode(spec.ExecutorConfig, &decodeTarget)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode executor config: %w", err)
	}
	if len(md.Undecoded()) > 0 {
		return nil, nil, fmt.Errorf("unknown fields in executor config: %v", md.Undecoded())
	}

	normalized, err := decodeTarget.GetNormalizedConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to normalize executor config: %w", err)
	}

	return normalized, decodeTarget.BlockchainInfos, nil
}
