package pricer

import (
	"context"
	"fmt"
	"time"

	solanago "github.com/gagliardetto/solana-go"

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

type solanaChain struct {
	lggr     logger.Logger
	client   *solclient.MultiNodeClient
	txm      *soltxm.Txm
	keystore core.Keystore
}

func (c *solanaChain) Start(ctx context.Context) error {
	if err := c.client.Dial(ctx); err != nil {
		return fmt.Errorf("failed to dial Solana client: %w", err)
	}
	return c.txm.Start(ctx)
}

func (c *solanaChain) Close() error {
	if err := c.txm.Close(); err != nil {
		return fmt.Errorf("failed to close Solana txm: %w", err)
	}
	c.client.Close()
	return nil
}

func (c *solanaChain) Tick(ctx context.Context) error {
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

func createSolanaKeystore(ctx context.Context, cfg Config, keystoreData []byte, keystorePassword string) (core.Keystore, error) {
	if cfg.KMS.Ed25519KeyID != "" {
		keyStore, err := loadKMSKeystore(ctx, cfg.KMS.Profile)
		if err != nil {
			return nil, fmt.Errorf("failed to load KMS keystore: %w", err)
		}
		return solkeys.NewTxKeyCoreKeystore(keyStore, solkeys.WithAllowedKeyNames([]string{cfg.KMS.Ed25519KeyID})), nil
	}
	keyStore, err := loadMemoryKeystore(ctx, keystoreData, keystorePassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load memory keystore: %w", err)
	}
	return solkeys.NewTxKeyCoreKeystore(keyStore), nil
}

func loadSolana(ctx context.Context, lggr logger.Logger, cfg Config, keystoreData []byte, keystorePassword string) (*solanaChain, error) {
	solClient, err := solclient.NewMultiNodeClient(
		cfg.SOL.ListNodes()[0].URL.String(),
		&cfg.SOL.TOMLConfig,
		time.Second*10,
		lggr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Solana client: %w", err)
	}
	solTxKeyStore, err := createSolanaKeystore(ctx, cfg, keystoreData, keystorePassword)
	if err != nil {
		return nil, err
	}
	solClientLoader := solutils.NewOnceLoader[solclient.ReaderWriter](func(ctx context.Context) (solclient.ReaderWriter, error) {
		return solClient, nil
	})
	solTxm, err := soltxm.NewTxm(
		*cfg.SOL.ChainID,
		solClientLoader,
		func(ctx context.Context, tx *solanago.Transaction) (solanago.Signature, error) {
			return solClient.SendTx(ctx, tx)
		},
		&cfg.SOL,
		solTxKeyStore,
		lggr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Solana txm: %w", err)
	}
	return &solanaChain{
		lggr:     logger.Named(lggr, "solana"),
		client:   solClient,
		txm:      solTxm,
		keystore: solTxKeyStore,
	}, nil
}
