package commit

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

// cfgWithBlockchainInfos is used only for decoding; T is the chain config type
// (e.g. blockchain.Info). Decoding into this struct allows strict Undecoded()
// checking for the whole config, including keys under blockchain_infos.
type cfgWithBlockchainInfos[T any] struct {
	Config
	BlockchainInfos map[string]*T `toml:"blockchain_infos"`
}

// LoadConfigWithBlockchainInfos decodes the committee verifier config from the job spec
// into a strongly-typed map[string]*T. The type T is chosen by the caller (e.g.
// blockchain.Info for EVM). Strict decode is applied: any unknown key in the config
// (including under blockchain_infos.<selector>) causes an error.
func LoadConfigWithBlockchainInfos[T any](spec JobSpec) (*Config, map[string]*T, error) {
	var decodeTarget cfgWithBlockchainInfos[T]
	md, err := toml.Decode(spec.CommitteeVerifierConfig, &decodeTarget)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode committee verifier config: %w", err)
	}
	if len(md.Undecoded()) > 0 {
		return nil, nil, fmt.Errorf("unknown fields in committee verifier config: %v", md.Undecoded())
	}
	return &decodeTarget.Config, decodeTarget.BlockchainInfos, nil
}
