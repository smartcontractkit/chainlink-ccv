package discovery

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

var _ common.ReaderDiscovery = (*ConfigurationDiscovery)(nil)

type ConfigurationDiscovery struct {
	offChainStorageReaderCh chan types.OffchainStorageReader
	readers                 []types.OffchainStorageReader
}

func NewConfigurationDiscovery(readers []types.OffchainStorageReader) common.ReaderDiscovery {
	return &ConfigurationDiscovery{
		offChainStorageReaderCh: make(chan types.OffchainStorageReader, 1000),
		readers:                 readers,
	}
}

func (d *ConfigurationDiscovery) DiscoverReaders(ctx context.Context) chan types.OffchainStorageReader {
	// Populate the offChainStorageReaderCh with the readers taken from the configuration
	for _, reader := range d.readers {
		d.offChainStorageReaderCh <- reader
	}

	return d.offChainStorageReaderCh
}

func (d *ConfigurationDiscovery) Stop() error {
	close(d.offChainStorageReaderCh)
	return nil
}
