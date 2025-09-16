package configuration

import (
	"github.com/smartcontractkit/chainlink-ccv/common/pkg/types"
)

type Configuration struct {
	BlockchainInfos map[string]*types.BlockchainInfo `toml:"blockchain_infos"`
	IndexerAddress  string                           `toml:"indexer_address"`
	PrivateKey      string                           `toml:"private_key"`
}
