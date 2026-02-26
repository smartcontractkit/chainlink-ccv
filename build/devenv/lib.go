package ccv

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/rs/zerolog"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/registry"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

type ChainImpl struct {
	cciptestinterfaces.CCIP17
	Details chain_selectors.ChainDetails
}

type Lib struct {
	envOutFile     string
	cfg            *Cfg
	l              *zerolog.Logger
	familiesToLoad []string
}

// NewLib creates a new Lib object given a logger and envOutFile.
// If familiesToLoad is provided, only chains with the given families will be loaded.
// If familiesToLoad is not provided, all chains will be loaded.
// The Lib instance uses the global chain family registry which can be extended
// via RegisterChainFamilyAdapter() before calling NewLib.
func NewLib(logger *zerolog.Logger, envOutFile string, familiesToLoad ...string) (*Lib, error) {
	cfg, err := LoadOutput[Cfg](envOutFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load environment output: %w", err)
	}

	lib := &Lib{
		envOutFile:     envOutFile,
		cfg:            cfg,
		l:              logger,
		familiesToLoad: familiesToLoad,
	}

	if err := lib.verify(); err != nil {
		return nil, fmt.Errorf("invalid library object: %w", err)
	}

	return lib, nil
}

// NewImpl is a convenience function that fetches a specific impl from the library.
func NewImpl(logger *zerolog.Logger, envOutFile string, selector uint64) (cciptestinterfaces.CCIP17, error) {
	lib, err := NewLib(logger, envOutFile)
	if err != nil {
		return ChainImpl{}, fmt.Errorf("failed to create CCV library: %w", err)
	}

	impls, err := lib.ChainsMap(context.Background())
	if err != nil {
		return ChainImpl{}, fmt.Errorf("failed to get chain implementations: %w", err)
	}

	impl, ok := impls[selector]
	if !ok {
		return ChainImpl{}, fmt.Errorf("no implementation found for chain selector %d", selector)
	}

	return impl, nil
}

func (l *Lib) verify() error {
	if l.envOutFile == "" {
		return fmt.Errorf("environment output file is not set")
	}
	if l.cfg == nil {
		return fmt.Errorf("configuration is nil")
	}
	if l.l == nil {
		return fmt.Errorf("logger is nil")
	}
	return nil
}

func (l *Lib) DataStore() (datastore.DataStore, error) {
	if err := l.verify(); err != nil {
		return nil, fmt.Errorf("failed to initialize datastore: %w", err)
	}
	return l.cfg.CLDF.DataStore, nil
}

func (l *Lib) Indexer() (*client.IndexerClient, error) {
	allIndexers, err := l.AllIndexers()
	if err != nil {
		return nil, fmt.Errorf("failed to get all indexer clients: %w", err)
	}
	if len(allIndexers) == 0 {
		return nil, fmt.Errorf("no indexer clients found")
	}
	return allIndexers[0], nil
}

func (l *Lib) AllIndexers() ([]*client.IndexerClient, error) {
	if err := l.verify(); err != nil {
		return nil, fmt.Errorf("failed to initialize indexer client: %w", err)
	}
	if len(l.cfg.IndexerEndpoints) == 0 {
		return nil, fmt.Errorf("no indexer endpoints configured")
	}
	indexers := make([]*client.IndexerClient, 0, len(l.cfg.IndexerEndpoints))
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	for _, endpoint := range l.cfg.IndexerEndpoints {
		ic, err := client.NewIndexerClient(endpoint, httpClient)
		if err != nil {
			l.l.Error().Err(err).Str("endpoint", endpoint).Msg("failed to create IndexerClient")
			continue
		}
		indexers = append(indexers, ic)
	}
	return indexers, nil
}

// Chains returns a slice of Chains in Blockchain cfg order, followed by any
// additional chain implementations that were externally registered via
// registry.GetGlobalChainImplRegistry().Register() but are not present in the cfg.
func (l *Lib) Chains(ctx context.Context) ([]ChainImpl, error) {
	if err := l.verify(); err != nil {
		return nil, fmt.Errorf("invalid library object: %w", err)
	}

	_, env, err := NewCLDFOperationsEnvironment(l.cfg.Blockchains, l.cfg.CLDF.DataStore)
	if err != nil {
		return nil, fmt.Errorf("creating CLDF operations environment: %w", err)
	}

	// Track which selectors were handled from the cfg so we can append registry-only entries afterwards.
	chainImplRegistry := registry.GetGlobalChainImplRegistry()
	seen := make(map[uint64]struct{})
	impls := make([]ChainImpl, 0, len(l.cfg.Blockchains))
	for _, bc := range l.cfg.Blockchains {
		if len(l.familiesToLoad) > 0 && !slices.Contains(l.familiesToLoad, bc.Out.Family) {
			l.l.Info().
				Any("familiesToLoad", l.familiesToLoad).
				Str("chainID", bc.ChainID).
				Str("family", bc.Out.Family).
				Msg("Skipping chain because it is not in the families to load")
			continue
		}

		details, err := chain_selectors.GetChainDetailsByChainIDAndFamily(bc.ChainID, bc.Out.Family)
		if err != nil {
			return nil, fmt.Errorf("getting chain details for chain ID %s and family %s: %w", bc.ChainID, bc.Out.Family, err)
		}

		seen[details.ChainSelector] = struct{}{}

		// Create built-in chain implementations and register them as defaults.
		var impl cciptestinterfaces.CCIP17
		switch bc.Out.Family {
		case chain_selectors.FamilyEVM:
			chainID := bc.ChainID
			wsURL := bc.Out.Nodes[0].ExternalWSUrl
			evmImpl, err := evm.NewCCIP17EVM(ctx, *l.l, env, chainID, wsURL)
			if err != nil {
				return nil, fmt.Errorf("creating CCIP17 EVM implementation for chain ID %s: %w", chainID, err)
			}
			impl = evmImpl
		default:
			fac, err := registry.GetImplFactory(bc.Out.Family)
			if err != nil {
				return nil, fmt.Errorf("getting implementation factory for family %s: %w", bc.Out.Family, err)
			}
			theImpl, err := fac.New(ctx, *l.l, env, bc)
			if err != nil {
				return nil, fmt.Errorf("creating implementation for family %s: %w", bc.Out.Family, err)
			}
			impl = theImpl
		}

		if err := chainImplRegistry.Register(bc.ChainID, bc.Out.Family, impl); err != nil {
			return nil, fmt.Errorf("registering chain implementation for chain ID %s with family %s: %w", bc.ChainID, bc.Out.Family, err)
		}
		impls = append(impls, ChainImpl{
			CCIP17:  impl,
			Details: details,
		})
	}

	// Append any externally registered impls that were not in the cfg but are present in the registry.
	for selector, entry := range chainImplRegistry.GetAll() {
		if _, ok := seen[selector]; ok {
			continue
		}
		impls = append(impls, ChainImpl{
			CCIP17:  entry.Impl,
			Details: entry.Details,
		})
	}

	return impls, nil
}

func (l *Lib) ChainsMap(ctx context.Context) (map[uint64]cciptestinterfaces.CCIP17, error) {
	impls, err := l.Chains(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain implementations: %w", err)
	}
	chainMap := make(map[uint64]cciptestinterfaces.CCIP17)
	for _, impl := range impls {
		chainMap[impl.Details.ChainSelector] = impl
	}

	return chainMap, nil
}
