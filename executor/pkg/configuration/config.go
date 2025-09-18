package configuration

import (
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common/pkg/types"
)

type Configuration struct {
	BlockchainInfos map[string]*types.BlockchainInfo `toml:"blockchain_infos"`
	IndexerAddress  string                           `toml:"indexer_address"`
	PrivateKey      string                           `toml:"private_key"`
	PollingInterval string                           `toml:"source_polling_interval"`
	BackoffDuration string                           `toml:"source_backoff_duration"`
	LookbackWindow  string                           `toml:"startup_lookback_window"`
}

func (c *Configuration) Validate() error {
	if len(c.BlockchainInfos) == 0 {
		return fmt.Errorf("no destination chains configured to read from")
	}
	if c.PrivateKey == "" {
		return fmt.Errorf("private key is required")
	}
	return nil
}

func (c *Configuration) GetBackoffDuration() time.Duration {
	d, err := time.ParseDuration(c.BackoffDuration)
	if err != nil {
		return 15 * time.Second
	}
	return d
}

func (c *Configuration) GetPollingInterval() time.Duration {
	d, err := time.ParseDuration(c.PollingInterval)
	if err != nil {
		return 5 * time.Second
	}
	return d
}

func (c *Configuration) GetLookbackWindow() time.Duration {
	d, err := time.ParseDuration(c.LookbackWindow)
	if err != nil {
		return 1 * time.Hour
	}
	return d
}
