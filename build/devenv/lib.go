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
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainimpl"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/registry"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

type ChainImpl struct {
	cciptestinterfaces.CCIP17
	Details chain_selectors.ChainDetails
}

// Lib abstracts an environment that CCIP is deployed on so that tests
// can be written once and run on any environment.
//
// Lib is currently implemented with two "backends":
// 1. A CCV devenv output file, i.e. env-out.toml.
// 2. A CLDF environment.
//
// Note that not all methods may be implemented by all backends.
// For example, as of writing, a CLDF environment doesn't store indexer
// or aggregator endpoints, so the [Lib.Indexer] and [Lib.AllIndexers]
// methods will return an error.
type Lib interface {
	// Chains returns a slice of [ChainImpl] objects in an unspecified order.
	Chains(ctx context.Context) ([]ChainImpl, error)

	// ChainsMap returns a map of chain selector to [cciptestinterfaces.CCIP17].
	ChainsMap(ctx context.Context) (map[uint64]cciptestinterfaces.CCIP17, error)

	// CLDFEnvironment returns the CLDF [deployment.Environment], if its available.
	// or an error if no CLDF environment is available.
	CLDFEnvironment() (*deployment.Environment, error)

	// DataStore returns the CLDF [datastore.DataStore], if its available.
	// or an error if no data store is available.
	DataStore() (datastore.DataStore, error)

	// Indexer returns the first indexer client from [Lib.AllIndexers],
	// or an error if no indexer clients are available.
	Indexer() (*client.IndexerClient, error)

	// AllIndexers returns all indexer clients available.
	// or an error if no indexer clients are available.
	AllIndexers() ([]*client.IndexerClient, error)
}

type libFromCCV struct {
	envOutFile     string
	cfg            *Cfg
	l              *zerolog.Logger
	familiesToLoad []string
	cldfEnv        *deployment.Environment
}

// NewLibFromCCVEnv creates Lib given a logger and envOutFile.
// If familiesToLoad is provided, only chains with the given families will be loaded.
// If familiesToLoad is not provided, all chains will be loaded.
// The instance uses the global chain family registry which can be extended
// via RegisterChainFamilyAdapter() before calling NewLibFromCCVEnv.
func NewLibFromCCVEnv(logger *zerolog.Logger, envOutFile string, familiesToLoad ...string) (Lib, error) {
	cfg, err := LoadOutput[Cfg](envOutFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load environment output: %w", err)
	}

	// Load CLDF env
	_, env, err := NewCLDFOperationsEnvironment(cfg.Blockchains, cfg.CLDF.DataStore)
	if err != nil {
		return nil, fmt.Errorf("failed to create CLDF operations environment: %w", err)
	}

	lib := &libFromCCV{
		envOutFile:     envOutFile,
		cfg:            cfg,
		l:              logger,
		familiesToLoad: familiesToLoad,
		cldfEnv:        env,
	}

	if err := lib.verify(); err != nil {
		return nil, fmt.Errorf("invalid library object: %w", err)
	}

	return lib, nil
}

// NewImpl is a convenience function that fetches a specific impl from the library.
func NewImpl(logger *zerolog.Logger, envOutFile string, selector uint64) (cciptestinterfaces.CCIP17, error) {
	lib, err := NewLibFromCCVEnv(logger, envOutFile)
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

func (l *libFromCCV) verify() error {
	if l.envOutFile == "" {
		return fmt.Errorf("environment output file is not set")
	}
	if l.cfg == nil {
		return fmt.Errorf("configuration is nil")
	}
	if l.l == nil {
		return fmt.Errorf("logger is nil")
	}
	if l.cldfEnv == nil {
		return fmt.Errorf("CLDF environment is nil")
	}
	return nil
}

// CLDFEnvironment returns the CLDF environment.
func (l *libFromCCV) CLDFEnvironment() (*deployment.Environment, error) {
	if err := l.verify(); err != nil {
		return nil, fmt.Errorf("failed to initialize CLDF environment: %w", err)
	}
	return l.cldfEnv, nil
}

func (l *libFromCCV) DataStore() (datastore.DataStore, error) {
	if err := l.verify(); err != nil {
		return nil, fmt.Errorf("failed to initialize datastore: %w", err)
	}
	return l.cfg.CLDF.DataStore, nil
}

func (l *libFromCCV) Indexer() (*client.IndexerClient, error) {
	allIndexers, err := l.AllIndexers()
	if err != nil {
		return nil, fmt.Errorf("failed to get all indexer clients: %w", err)
	}
	if len(allIndexers) == 0 {
		return nil, fmt.Errorf("no indexer clients found")
	}
	return allIndexers[0], nil
}

func (l *libFromCCV) AllIndexers() ([]*client.IndexerClient, error) {
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
func (l *libFromCCV) Chains(ctx context.Context) ([]ChainImpl, error) {
	if err := l.verify(); err != nil {
		return nil, fmt.Errorf("invalid library object: %w", err)
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

		// Create chain implementations via the registered ImplFactory for each family.
		fac, err := chainimpl.GetImplFactory(bc.Out.Family)
		if err != nil {
			return nil, fmt.Errorf("getting implementation factory for chain ID %s selector %d family %s: %w", bc.ChainID, details.ChainSelector, bc.Out.Family, err)
		}
		impl, err := fac.New(ctx, *l.l, l.cldfEnv, bc)
		if err != nil {
			return nil, fmt.Errorf("creating implementation for chain ID %s selector %d family %s: %w", bc.ChainID, details.ChainSelector, bc.Out.Family, err)
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

func (l *libFromCCV) ChainsMap(ctx context.Context) (map[uint64]cciptestinterfaces.CCIP17, error) {
	impls, err := l.Chains(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain implementations: %w", err)
	}
	chainMap := make(map[uint64]cciptestinterfaces.CCIP17)
	for _, impl := range impls {
		chainMap[impl.Details.ChainSelector] = impl.CCIP17
	}

	return chainMap, nil
}

type libFromCLDF struct {
	env *deployment.Environment
}

// AllIndexers implements [Lib].
func (l *libFromCLDF) AllIndexers() ([]*client.IndexerClient, error) {
	return nil, fmt.Errorf("no indexer clients available in CLDF environment")
}

// CLDFEnvironment implements [Lib].
func (l *libFromCLDF) CLDFEnvironment() (*deployment.Environment, error) {
	return l.env, nil
}

// Chains implements [Lib].
func (l *libFromCLDF) Chains(ctx context.Context) ([]ChainImpl, error) {
	panic("unimplemented")
}

// ChainsMap implements [Lib].
func (l *libFromCLDF) ChainsMap(ctx context.Context) (map[uint64]cciptestinterfaces.CCIP17, error) {
	panic("unimplemented")
}

// DataStore implements [Lib].
func (l *libFromCLDF) DataStore() (datastore.DataStore, error) {
	return l.env.DataStore, nil
}

// Indexer implements [Lib].
func (l *libFromCLDF) Indexer() (*client.IndexerClient, error) {
	return nil, fmt.Errorf("no indexer clients available in CLDF environment")
}

func NewLibFromCLDFEnv(env *deployment.Environment) (Lib, error) {
	lib := &libFromCLDF{
		env: env,
	}
	return lib, nil
}
