package ccv

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/rs/zerolog"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainimpl"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

type ChainImpl struct {
	cciptestinterfaces.CCIP17
	Details chainsel.ChainDetails
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
	envOutFile string
	cfg        *Cfg
	libCLDF    Lib
	l          zerolog.Logger
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

	cldfLib, err := NewLibFromCLDFEnv(logger, env, familiesToLoad...)
	if err != nil {
		return nil, fmt.Errorf("failed to create CLDF library: %w", err)
	}

	return &libFromCCV{
		envOutFile: envOutFile,
		cfg:        cfg,
		libCLDF:    cldfLib,
		l:          *logger,
	}, nil
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

	return nil
}

// CLDFEnvironment implements [Lib].
func (l *libFromCCV) CLDFEnvironment() (*deployment.Environment, error) {
	if err := l.verify(); err != nil {
		return nil, fmt.Errorf("failed to initialize CLDF environment: %w", err)
	}
	return l.libCLDF.CLDFEnvironment()
}

// DataStore implements [Lib].
func (l *libFromCCV) DataStore() (datastore.DataStore, error) {
	return l.libCLDF.DataStore()
}

// Indexer implements [Lib].
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

// AllIndexers implements [Lib].
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

// Chains implements [Lib].
func (l *libFromCCV) Chains(ctx context.Context) ([]ChainImpl, error) {
	return l.libCLDF.Chains(ctx)
}

// ChainsMap implements [Lib].
func (l *libFromCCV) ChainsMap(ctx context.Context) (map[uint64]cciptestinterfaces.CCIP17, error) {
	return l.libCLDF.ChainsMap(ctx)
}

type libFromCLDF struct {
	env            *deployment.Environment
	familiesToLoad []string
	l              zerolog.Logger
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
	chainMap, err := l.ChainsMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain map: %w", err)
	}

	chainImpls := make([]ChainImpl, 0, len(chainMap))
	for selector, impl := range chainMap {
		details, err := chainsel.GetChainDetails(selector)
		if err != nil {
			return nil, fmt.Errorf("failed to get chain details for chain %d: %w", selector, err)
		}
		chainImpls = append(chainImpls, ChainImpl{
			CCIP17:  impl,
			Details: details,
		})
	}

	return chainImpls, nil
}

// ChainsMap implements [Lib].
func (l *libFromCLDF) ChainsMap(ctx context.Context) (map[uint64]cciptestinterfaces.CCIP17, error) {
	chainMap := make(map[uint64]cciptestinterfaces.CCIP17)
	for selector := range l.env.BlockChains.All() {
		family, err := chainsel.GetSelectorFamily(selector)
		if err != nil {
			return nil, fmt.Errorf("failed to get selector family for chain %d: %w", selector, err)
		}

		if len(l.familiesToLoad) > 0 && !slices.Contains(l.familiesToLoad, family) {
			continue
		}

		implFactory, err := chainimpl.GetImplFactory(family)
		if err != nil {
			return nil, fmt.Errorf("failed to get implementation factory for family %s: %w", family, err)
		}
		impl, err := implFactory.New(ctx, l.l, l.env, selector)
		if err != nil {
			return nil, fmt.Errorf("failed to create implementation for chain %d: %w", selector, err)
		}

		chainMap[selector] = impl
	}

	return chainMap, nil
}

// DataStore implements [Lib].
func (l *libFromCLDF) DataStore() (datastore.DataStore, error) {
	return l.env.DataStore, nil
}

// Indexer implements [Lib].
func (l *libFromCLDF) Indexer() (*client.IndexerClient, error) {
	return nil, fmt.Errorf("no indexer clients available in CLDF environment")
}

func NewLibFromCLDFEnv(logger *zerolog.Logger, env *deployment.Environment, familiesToLoad ...string) (Lib, error) {
	lib := &libFromCLDF{
		env:            env,
		familiesToLoad: familiesToLoad,
		l:              *logger,
	}
	return lib, nil
}
