package commit

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

// cfgWithBlockchainInfos is used only for decoding; T is the chain config type
// (e.g. blockchain.Info). Decoding into this struct allows strict Undecoded()
// checking for the whole config, including keys under blockchain_infos.
type cfgWithBlockchainInfos struct {
	Config
	BlockchainInfos chainaccess.Infos[any] `toml:"blockchain_infos"`
}

// LoadConfigWithBlockchainInfos decodes the committee verifier config from the job spec
// into a strongly-typed chainaccess.Infos[T]. The type T is chosen by the caller (e.g.
// blockchain.Info for EVM). Strict decode is applied: any unknown key in the config
// (including under blockchain_infos.<selector>) causes an error.
func LoadConfigWithBlockchainInfos(spec JobSpec) (*Config, chainaccess.Infos[any], error) {
	var decodeTarget cfgWithBlockchainInfos
	_, err := toml.Decode(spec.CommitteeVerifierConfig, &decodeTarget)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode committee verifier config: %w", err)
	}
	return &decodeTarget.Config, decodeTarget.BlockchainInfos, nil
}
