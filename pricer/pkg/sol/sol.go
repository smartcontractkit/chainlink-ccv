package sol

import (
	"context"
	"fmt"
	"time"

	solanago "github.com/gagliardetto/solana-go"

	ks "github.com/smartcontractkit/chainlink-ccv/pricer/pkg/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"
	solclient "github.com/smartcontractkit/chainlink-solana/pkg/solana/client"
	solcfg "github.com/smartcontractkit/chainlink-solana/pkg/solana/config"
	solkeys "github.com/smartcontractkit/chainlink-solana/pkg/solana/keys"
	soltxm "github.com/smartcontractkit/chainlink-solana/pkg/solana/txm"
	solutils "github.com/smartcontractkit/chainlink-solana/pkg/solana/utils"
)

type SOLChainConfig struct {
	solcfg.TOMLConfig
	// Extend with pricer-specific config here if needed.
}

type SolanaChain struct {
	lggr     logger.Logger
	client   *solclient.MultiNodeClient
	txm      *soltxm.Txm
	keystore core.Keystore
}

func (c *SolanaChain) Start(ctx context.Context) error {
	if err := c.client.Dial(ctx); err != nil {
		return fmt.Errorf("failed to dial Solana client: %w", err)
	}
	err := c.txm.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start Solana txm: %w", err)
	}
	c.lggr.Infow("started solana chain")
	return nil
}

func (c *SolanaChain) Close() error {
	if err := c.txm.Close(); err != nil {
		return fmt.Errorf("failed to close Solana txm: %w", err)
	}
	c.client.Close()
	return nil
}

func (c *SolanaChain) Tick(ctx context.Context) error {
	c.lggr.Infow("getting solana addresses")
	addresses, err := c.keystore.Accounts(ctx)
	if err != nil {
		c.lggr.Error("failed to get addresses", "error", err)
		return fmt.Errorf("failed to get addresses: %w", err)
	}
	if len(addresses) == 0 {
		c.lggr.Warn("no Solana addresses found in keystore")
		return fmt.Errorf("no Solana addresses found in keystore")
	}
	balance, err := c.client.Balance(ctx, solanago.MustPublicKeyFromBase58(addresses[0]))
	if err != nil {
		c.lggr.Error("failed to get balance", "error", err)
		return fmt.Errorf("failed to get balance: %w", err)
	}
	c.lggr.Infow("got balance", "address", addresses[0], "balance", balance)
	return nil
}

func (c *SolanaChain) CreateKeystore(ctx context.Context, cfg ks.KMSConfig, keystoreData []byte, keystorePassword string) (core.Keystore, error) {
	if cfg.Ed25519KeyID != "" {
		keyStore, err := ks.LoadKMSKeystore(ctx, cfg.Profile)
		if err != nil {
			return nil, fmt.Errorf("failed to load KMS keystore: %w", err)
		}
		return solkeys.NewTxKeyCoreKeystore(keyStore, solkeys.WithAllowedKeyNames([]string{cfg.Ed25519KeyID})), nil
	}
	keyStore, err := ks.LoadMemoryKeystore(ctx, keystoreData, keystorePassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load memory keystore: %w", err)
	}
	return solkeys.NewTxKeyCoreKeystore(keyStore), nil
}

func LoadSolana(ctx context.Context, lggr logger.Logger, cfg SOLChainConfig, solTxKeyStore core.Keystore, keystoreData []byte, keystorePassword string) (*SolanaChain, error) {
	solClient, err := solclient.NewMultiNodeClient(
		cfg.ListNodes()[0].URL.String(),
		&cfg.TOMLConfig,
		time.Second*10,
		lggr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Solana client: %w", err)
	}
	solClientLoader := solutils.NewOnceLoader[solclient.ReaderWriter](func(ctx context.Context) (solclient.ReaderWriter, error) {
		return solClient, nil
	})
	solTxm, err := soltxm.NewTxm(
		*cfg.ChainID,
		solClientLoader,
		func(ctx context.Context, tx *solanago.Transaction) (solanago.Signature, error) {
			return solClient.SendTx(ctx, tx)
		},
		&cfg,
		solTxKeyStore,
		lggr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Solana txm: %w", err)
	}
	return &SolanaChain{
		lggr:     logger.Named(lggr, "solana"),
		client:   solClient,
		txm:      solTxm,
		keystore: solTxKeyStore,
	}, nil
}
