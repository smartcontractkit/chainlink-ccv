package discovery

import (
	"context"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var _ common.ReaderDiscovery = (*StaticDiscovery)(nil)

type StaticDiscovery struct {
	offChainStorageReaderCh chan protocol.OffchainStorageReader
	readers                 []protocol.OffchainStorageReader
	mu                      sync.RWMutex
}

func NewStaticDiscovery(readers []protocol.OffchainStorageReader) common.ReaderDiscovery {
	return &StaticDiscovery{
		offChainStorageReaderCh: make(chan protocol.OffchainStorageReader, 1000),
		readers:                 readers,
	}
}

func (d *StaticDiscovery) Run(ctx context.Context) chan protocol.OffchainStorageReader {
	// Populate the offChainStorageReaderCh with the readers taken from the configuration
	d.mu.RLock()
	readers := make([]protocol.OffchainStorageReader, len(d.readers))
	copy(readers, d.readers)
	d.mu.RUnlock()

	for _, reader := range readers {
		d.offChainStorageReaderCh <- reader
	}

	return d.offChainStorageReaderCh
}

func (d *StaticDiscovery) AddReaders(readers []protocol.OffchainStorageReader) {
	d.mu.Lock()
	d.readers = append(d.readers, readers...)
	d.mu.Unlock()

	for _, reader := range readers {
		d.offChainStorageReaderCh <- reader
	}
}

func (d *StaticDiscovery) Stop() error {
	close(d.offChainStorageReaderCh)
	return nil
}
