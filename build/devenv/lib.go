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
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	ccldf "github.com/smartcontractkit/chainlink-ccv/build/devenv/cldf"
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

	// IndexerMonitor returns a new [IndexerMonitor] for the indexer client,
	// or an error if no indexer client is available.
	IndexerMonitor() (*IndexerMonitor, error)

	// AllIndexers returns all indexer clients available.
	// or an error if no indexer clients are available.
	AllIndexers() ([]*client.IndexerClient, error)

	// AllAggregators returns a mapping of qualifier name to the client of the aggregator for that qualifier.
	// or an error if no aggregator clients are available.
	AllAggregators() (map[string]*AggregatorClient, error)
}

type libFromCCV struct {
	envOutFile string
	cfg        *Cfg
	libCLDF    Lib
	l          zerolog.Logger
}

// NewLibFromCCVEnv creates a new [Lib] from a CCV environment output file.
// If familiesToLoad is provided, only chains with the given families will be loaded.
// If familiesToLoad is not provided, all chains will be loaded.
func NewLibFromCCVEnv(logger *zerolog.Logger, envOutFile string, familiesToLoad ...string) (Lib, error) {
	cfg, err := LoadOutput[Cfg](envOutFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load environment output: %w", err)
	}

	// Load CLDF env
	_, env, err := ccldf.NewCLDFOperationsEnvironment(cfg.Blockchains, cfg.CLDF.DataStore)
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

// AllAggregators implements [Lib].
func (l *libFromCCV) AllAggregators() (map[string]*AggregatorClient, error) {
	if err := l.verify(); err != nil {
		return nil, fmt.Errorf("failed to initialize aggregator clients: %w", err)
	}

	if len(l.cfg.AggregatorEndpoints) == 0 {
		return nil, fmt.Errorf("no aggregator endpoints configured")
	}

	aggregators := make(map[string]*AggregatorClient, len(l.cfg.AggregatorEndpoints))
	for qualifier, endpoint := range l.cfg.AggregatorEndpoints {
		ac, err := NewAggregatorClient(l.l, endpoint, l.cfg.AggregatorCACertFiles[qualifier])
		if err != nil {
			return nil, fmt.Errorf("failed to create aggregator client for qualifier %s: %w", qualifier, err)
		}
		aggregators[qualifier] = ac
	}

	return aggregators, nil
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

// IndexerMonitor implements [Lib].
func (l *libFromCCV) IndexerMonitor() (*IndexerMonitor, error) {
	indexerClient, err := l.Indexer()
	if err != nil {
		return nil, fmt.Errorf("failed to get indexer client: %w", err)
	}
	return NewIndexerMonitor(l.l, indexerClient)
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

		reg, err := chainreg.GetRegistry().Get(family)
		if err != nil {
			return nil, fmt.Errorf("failed to get chain registration for family %s: %w", family, err)
		}
		if reg.ImplFactory == nil {
			return nil, fmt.Errorf("implementation factory for family %s not found", family)
		}
		impl, err := reg.ImplFactory.New(ctx, l.l, l.env, selector)
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

// IndexerMonitor implements [Lib].
func (l *libFromCLDF) IndexerMonitor() (*IndexerMonitor, error) {
	return nil, fmt.Errorf("no indexer monitor available in CLDF environment")
}

// AllAggregators implements [Lib].
func (l *libFromCLDF) AllAggregators() (map[string]*AggregatorClient, error) {
	return nil, fmt.Errorf("no aggregator clients available in CLDF environment")
}

// NewLibFromCLDFEnv creates a new [Lib] from a [deployment.Environment].
// If familiesToLoad is provided, only chains with the given families will be loaded.
// If familiesToLoad is not provided, all chains will be loaded.
func NewLibFromCLDFEnv(logger *zerolog.Logger, env *deployment.Environment, familiesToLoad ...string) (Lib, error) {
	lib := &libFromCLDF{
		env:            env,
		familiesToLoad: familiesToLoad,
		l:              *logger,
	}
	return lib, nil
}
