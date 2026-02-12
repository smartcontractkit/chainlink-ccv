package ccv

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/rs/zerolog"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/devenv/canton"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
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
	if err := l.verify(); err != nil {
		return nil, fmt.Errorf("failed to initialize indexer client: %w", err)
	}
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	ic, err := client.NewIndexerClient(l.cfg.IndexerEndpoint, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create IndexerMonitor: %w", err)
	}

	return ic, nil
}

// Chains returns a slice of Chains in Blockchain cfg order.
func (l *Lib) Chains(ctx context.Context) ([]ChainImpl, error) {
	if err := l.verify(); err != nil {
		return nil, fmt.Errorf("invalid library object: %w", err)
	}

	_, env, err := NewCLDFOperationsEnvironment(l.cfg.Blockchains, l.cfg.CLDF.DataStore)
	if err != nil {
		return nil, fmt.Errorf("creating CLDF operations environment: %w", err)
	}

	impls := make([]ChainImpl, len(l.cfg.Blockchains))
	for i, bc := range l.cfg.Blockchains {
		if len(l.familiesToLoad) > 0 && !slices.Contains(l.familiesToLoad, bc.Out.Family) {
			l.l.Info().
				Any("familiesToLoad", l.familiesToLoad).
				Str("chainID", bc.ChainID).
				Str("family", bc.Out.Family).
				Msg("Skipping chain because it is not in the families to load")
			continue
		}

		switch bc.Out.Family {
		case chain_selectors.FamilyEVM:
			chainID := bc.ChainID
			wsURL := bc.Out.Nodes[0].ExternalWSUrl
			details, err := chain_selectors.GetChainDetailsByChainIDAndFamily(chainID, bc.Out.Family)
			if err != nil {
				return nil, fmt.Errorf("getting chain details for chain ID %s and family %s: %w", chainID, bc.Out.Family, err)
			}
			impl, err := evm.NewCCIP17EVM(ctx, *l.l, env, chainID, wsURL)
			if err != nil {
				return nil, fmt.Errorf("creating CCIP17 EVM implementation for chain ID %s: %w", chainID, err)
			}
			impls[i] = ChainImpl{
				CCIP17:  impl,
				Details: details,
			}
		case chain_selectors.FamilyCanton:
			details, err := chain_selectors.GetChainDetailsByChainIDAndFamily(bc.ChainID, bc.Out.Family)
			if err != nil {
				return nil, fmt.Errorf("getting chain details for chain ID %s and family %s: %w", bc.ChainID, bc.Out.Family, err)
			}
			impl, err := canton.New(ctx, *l.l, env, bc.ChainID)
			if err != nil {
				return nil, fmt.Errorf("creating Canton implementation for chain ID %s: %w", bc.ChainID, err)
			}
			impls[i] = ChainImpl{
				CCIP17:  impl,
				Details: details,
			}
		default:
			return nil, fmt.Errorf("unsupported family %s", bc.Out.Family)
		}
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
