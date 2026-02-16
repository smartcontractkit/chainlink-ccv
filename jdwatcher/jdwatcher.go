package jdwatcher

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"

	jdclient "github.com/smartcontractkit/chainlink-ccv/common/jd/client"
	jdlifecycle "github.com/smartcontractkit/chainlink-ccv/common/jd/lifecycle"
	"github.com/smartcontractkit/chainlink-ccv/common/jd/runner"
	jobstore "github.com/smartcontractkit/chainlink-ccv/common/jd/store"
	"github.com/smartcontractkit/chainlink-ccv/kmd"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

type JDWatcher struct {
	services.StateMachine
	cfg     *Config
	lggr    logger.Logger
	manager *jdlifecycle.Manager
}

func NewJDWatcher(lggr logger.Logger, cfg *Config) (*JDWatcher, error) {
	if lggr == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("failed to validate config: %w", err)
	}
	return &JDWatcher{
		lggr: logger.Sugared(logger.Named(lggr, "JDWatcher")),
		cfg:  cfg,
	}, nil
}

func (j *JDWatcher) Start(ctx context.Context) error {
	return j.StartOnce("JDWatcher", func() error {
		kmdClient := kmd.NewClient(j.cfg.KMDServerURL)

		csaSigner, err := newCSASigner(kmdClient, j.cfg.KMDCSAKeyName)
		if err != nil {
			return fmt.Errorf("failed to create CSA signer: %w", err)
		}

		jdServerPublicKey, err := getJDPublicKey(j.cfg.JDServerCSAPublicKey)
		if err != nil {
			return fmt.Errorf("failed to get JD public key: %w", err)
		}

		jdClient := jdclient.New(csaSigner, jdServerPublicKey, j.cfg.JDServerWSRPCURL, j.lggr)

		rnr := runner.NewProcessRunner(j.lggr, j.cfg.ProcessBinaryPath, j.cfg.ProcessConfigPathEnvVar)
		manager, err := jdlifecycle.NewManager(jdlifecycle.Config{
			JDClient: jdClient,
			JobStore: jobstore.NewFileStore(j.cfg.JobStorePath),
			Runner:   rnr,
			Logger:   j.lggr,
		})
		if err != nil {
			return fmt.Errorf("failed to create lifecycle manager: %w", err)
		}

		if err := manager.Start(ctx); err != nil {
			return fmt.Errorf("failed to start lifecycle manager: %w", err)
		}

		j.lggr.Infow("Lifecycle manager started")

		j.manager = manager

		return nil
	})
}
func (j *JDWatcher) Stop() error {
	return j.StopOnce("JDWatcher", func() error {
		if j.manager == nil {
			return fmt.Errorf("lifecycle manager not started")
		}

		j.lggr.Infow("Stopping lifecycle manager")

		if err := j.manager.Stop(); err != nil {
			return fmt.Errorf("failed to stop lifecycle manager: %w", err)
		}

		j.lggr.Infow("Lifecycle manager stopped")

		return nil
	})
}

func getJDPublicKey(pubKey string) (ed25519.PublicKey, error) {
	jdPublicKey, err := hex.DecodeString(pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode JD public key: %w", err)
	}
	if len(jdPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("JD public key is not an ed25519 public key")
	}

	return ed25519.PublicKey(jdPublicKey), nil
}

type csaSigner struct {
	kmdClient *kmd.Client
	keyName   string
	publicKey ed25519.PublicKey
}

func newCSASigner(kmdClient *kmd.Client, keyName string) (*csaSigner, error) {
	resp, err := kmdClient.GetKeys(context.Background(), keystore.GetKeysRequest{
		KeyNames: []string{keyName},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get keys: %w", err)
	}
	if len(resp.Keys) == 0 {
		// TODO: should we create a key if it doesn't exist?
		return nil, fmt.Errorf("key %s not found", keyName)
	}
	if len(resp.Keys) != 1 {
		return nil, fmt.Errorf("expected 1 key, got %d", len(resp.Keys))
	}
	publicKey := resp.Keys[0].KeyInfo.PublicKey
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is not an ed25519 public key")
	}
	return &csaSigner{
		kmdClient: kmdClient,
		keyName:   keyName,
		publicKey: ed25519.PublicKey(publicKey),
	}, nil
}

// Public implements crypto.Signer.
func (c *csaSigner) Public() crypto.PublicKey {
	return c.publicKey
}

// Sign implements crypto.Signer.
func (c *csaSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	resp, err := c.kmdClient.Sign(context.Background(), keystore.SignRequest{
		KeyName: c.keyName,
		Data:    digest,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}
	return resp.Signature, nil
}

var _ crypto.Signer = &csaSigner{}
