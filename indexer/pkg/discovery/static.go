package discovery

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

var _ common.ReaderDiscovery = (*StaticDiscovery)(nil)

type StaticDiscovery struct {
	offChainStorageReaderCh chan types.OffchainStorageReader
	readers                 []types.OffchainStorageReader
}

func NewStaticDiscovery(readers []types.OffchainStorageReader) common.ReaderDiscovery {
	return &StaticDiscovery{
		offChainStorageReaderCh: make(chan types.OffchainStorageReader, 1000),
		readers:                 readers,
	}
}

func (d *StaticDiscovery) Run(ctx context.Context) chan types.OffchainStorageReader {
	// Populate the offChainStorageReaderCh with the readers taken from the configuration
	for _, reader := range d.readers {
		d.offChainStorageReaderCh <- reader
	}

	return d.offChainStorageReaderCh
}

func (d *StaticDiscovery) AddReaders(readers []types.OffchainStorageReader) {
	// This is primarily used for replays from a given timeframe
	d.readers = append(d.readers, readers...)

	for _, reader := range readers {
		d.offChainStorageReaderCh <- reader
	}
}

func (d *StaticDiscovery) Stop() error {
	close(d.offChainStorageReaderCh)
	return nil
}
