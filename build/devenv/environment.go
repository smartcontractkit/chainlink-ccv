package ccv

import (
	"errors"
	"fmt"

	"golang.org/x/sync/errgroup"

	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/jd"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/s3provider"

	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

type Cfg struct {
	CCV             *CCV                      `toml:"ccv"              validate:"required"`
	StorageProvider *s3provider.Input         `toml:"storage_provider" validate:"required"`
	JD              *jd.Input                 `toml:"jd"`
	Fake            *services.FakeInput       `toml:"fake"             validate:"required"`
	Verifier        *services.VerifierInput   `toml:"verifier"         validate:"required"`
	Verifier2       *services.VerifierInput   `toml:"verifier2"        validate:"required"`
	Executor        *services.ExecutorInput   `toml:"executor"         validate:"required"`
	Indexer         *services.IndexerInput    `toml:"indexer"          validate:"required"`
	Aggregator      *services.AggregatorInput `toml:"aggregator"       validate:"required"`
	Blockchains     []*blockchain.Input       `toml:"blockchains"      validate:"required"`
	NodeSets        []*ns.Input               `toml:"nodesets"         validate:"required"`
}

// verifyEnvironment internal function describing how to verify your environment is working.
func verifyEnvironment(in *Cfg) error {
	if !in.CCV.Verify {
		return nil
	}
	Plog.Info().Msg("Verifying environment")
	// CCV verification, check that example transfer works
	return nil
}

func checkKeys(in *Cfg) error {
	if getNetworkPrivateKey() != DefaultAnvilKey && in.Blockchains[0].ChainID == "1337" && in.Blockchains[1].ChainID == "2337" {
		return errors.New("you are trying to run simulated chains with a key that do not belong to Anvil, please run 'unset PRIVATE_KEY'")
	}
	if getNetworkPrivateKey() == DefaultAnvilKey && in.Blockchains[0].ChainID != "1337" && in.Blockchains[1].ChainID != "2337" {
		return errors.New("you are trying to run on real networks but is not using the Anvil private key, export your private key 'export PRIVATE_KEY=...'")
	}
	return nil
}

// NewEnvironment creates a new datafeeds environment either locally in Docker or remotely in K8s.
func NewEnvironment() (*Cfg, error) {
	if err := framework.DefaultNetwork(nil); err != nil {
		return nil, err
	}
	in, err := Load[Cfg]()
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	if err := checkKeys(in); err != nil {
		return nil, err
	}
	track := NewTimeTracker(Plog)
	eg := &errgroup.Group{}
	for _, b := range in.Blockchains {
		eg.Go(func() error {
			_, err = blockchain.NewBlockchainNetwork(b)
			if err != nil {
				return fmt.Errorf("failed to create blockchain network: %w", err)
			}
			return nil
		})
	}
	eg.Go(func() error {
		in.Fake.Out, err = services.NewFake(in.Fake)
		if err != nil {
			return fmt.Errorf("failed to create fake data provider: %w", err)
		}
		return nil
	})
	aggregatorOutput, err := services.NewAggregator(in.Aggregator)
	if err != nil {
		return nil, fmt.Errorf("failed to create aggregator service: %w", err)
	}

	eg.Go(func() error {
		in.Verifier.VerifierConfig = services.VerifierConfig{
			AggregatorAddress: aggregatorOutput.Address,
			PrivateKey:        "dev-private-key-12345678901234567890",
		}
		_, err = services.NewVerifier(in.Verifier)
		if err != nil {
			return fmt.Errorf("failed to create verifier service: %w", err)
		}
		in.Verifier2.VerifierConfig = services.VerifierConfig{
			AggregatorAddress: aggregatorOutput.Address,
			PrivateKey:        "dev-private-key2-12345678901234567890",
		}
		in.Verifier2.ContainerName = "verifier2"
		in.Verifier2.ConfigFilePath = "/app/verifier2.toml"
		_, err = services.NewVerifier(in.Verifier2)
		if err != nil {
			return fmt.Errorf("failed to create verifier 2 service: %w", err)
		}
		return nil
	})
	eg.Go(func() error {
		_, err = services.NewExecutor(in.Executor)
		if err != nil {
			return fmt.Errorf("failed to create executor service: %w", err)
		}
		return nil
	})
	eg.Go(func() error {
		_, err = services.NewIndexer(in.Indexer)
		if err != nil {
			return fmt.Errorf("failed to create indexer service: %w", err)
		}
		return nil
	})
	// TODO: we need access to pre-built JD image in CI
	//eg.Go(func() error {
	//	_, err = jd.NewJD(in.JD)
	//	if err != nil {
	//		return fmt.Errorf("failed to create job distributor: %w", err)
	//	}
	//	return nil
	//})
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	track.Record("[infra] deploying blockchains")
	if err := DefaultProductConfiguration(in, ConfigureNodesNetwork); err != nil {
		return nil, fmt.Errorf("failed to setup default CLDF orchestration: %w", err)
	}
	track.Record("[changeset] configured nodes network")
	_, err = ns.NewSharedDBNodeSet(in.NodeSets[0], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new shared db node set: %w", err)
	}
	track.Record("[infra] deployed CL nodes")
	if err := DefaultProductConfiguration(in, ConfigureProductContractsJobs); err != nil {
		return nil, fmt.Errorf("failed to setup default CLDF orchestration: %w", err)
	}
	track.Record("[changeset] deployed product contracts")
	track.Print()
	if err := PrintCLDFAddresses(in); err != nil {
		return nil, err
	}
	return in, Store[Cfg](in)
}
