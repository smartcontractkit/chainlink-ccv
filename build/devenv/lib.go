package ccv

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

type Lib struct {
	envOutFile string
	cfg        *Cfg
	l          *zerolog.Logger
}

func NewLib(logger *zerolog.Logger, envOutFile string) (*Lib, error) {
	cfg, err := LoadOutput[Cfg](envOutFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load environment output: %w", err)
	}

	return &Lib{
		envOutFile: envOutFile,
		cfg:        cfg,
		l:          logger,
	}, nil
}

// NewImpl is a convenience function that fetches a specific impl from the library.
func NewImpl(logger *zerolog.Logger, envOutFile string, selector uint64) (cciptestinterfaces.CCIP17ProductConfiguration, error) {
	lib, err := NewLib(logger, envOutFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create CCV library: %w", err)
	}

	impls, err := lib.Chains(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get chain implementations: %w", err)
	}

	impl, ok := impls[selector]
	if !ok {
		return nil, fmt.Errorf("no implementation found for chain selector %d", selector)
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
	return nil
}

func (l *Lib) DataStore() (datastore.DataStore, error) {
	if err := l.verify(); err != nil {
		return nil, fmt.Errorf("failed to initialize datastore: %w", err)
	}
	return l.cfg.CLDF.DataStore, nil
}

func (l *Lib) Chains(ctx context.Context) (map[uint64]cciptestinterfaces.CCIP17ProductConfiguration, error) {
	if err := l.verify(); err != nil {
		return nil, fmt.Errorf("invalid library object: %w", err)
	}

	_, env, err := NewCLDFOperationsEnvironment(l.cfg.Blockchains, l.cfg.CLDF.DataStore)
	if err != nil {
		return nil, fmt.Errorf("creating CLDF operations environment: %w", err)
	}

	impls := make(map[uint64]cciptestinterfaces.CCIP17ProductConfiguration)
	for _, bc := range l.cfg.Blockchains {
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
		impls[details.ChainSelector] = impl
	}

	return impls, nil
}
