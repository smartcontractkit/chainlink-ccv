package ccv

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
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

func (l *Lib) verify() error {
	if l.envOutFile == "" {
		return fmt.Errorf("environment output file is not set")
	}
	if l.cfg == nil {
		return fmt.Errorf("configuration is nil")
	}
	return nil
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
		impls[details.ChainSelector] = impl
	}

	return impls, nil
}
