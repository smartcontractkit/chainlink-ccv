package sourcereader

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// SourceReaderFactory creates a SourceReader for a specific chain.
type SourceReaderFactory interface {
	GetSourceReader(ctx context.Context, chainSelector protocol.ChainSelector) (chainaccess.SourceReader, error)
}

// Registry holds SourceReaderFactories for different chain families.
type Registry struct {
	blockchainHelper *blockchain.Helper
	factories        map[string]SourceReaderFactory
}

// NewRegistry creates a new Registry.
func NewRegistry(helper *blockchain.Helper) *Registry {
	return &Registry{
		blockchainHelper: helper,
		factories:        make(map[string]SourceReaderFactory),
	}
}

// Register registers a factory for a given chain family.
func (r *Registry) Register(family string, factory SourceReaderFactory) {
	r.factories[family] = factory
}

// GetSourceReader creates a SourceReader for the given chain selector using the registered factory.
func (r *Registry) GetSourceReader(ctx context.Context, chainSelector protocol.ChainSelector) (chainaccess.SourceReader, error) {
	info, err := r.blockchainHelper.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to get blockchain info for chain %d: %w", chainSelector, err)
	}

	factory, ok := r.factories[info.Family]
	if !ok {
		return nil, fmt.Errorf("no factory registered for chain family %s", info.Family)
	}

	return factory.GetSourceReader(ctx, chainSelector)
}
