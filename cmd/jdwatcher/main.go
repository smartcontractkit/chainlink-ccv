package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	jdclient "github.com/smartcontractkit/chainlink-ccv/common/jd/client"
	jdlifecycle "github.com/smartcontractkit/chainlink-ccv/common/jd/lifecycle"
	"github.com/smartcontractkit/chainlink-ccv/common/jd/runner"
	jobstore "github.com/smartcontractkit/chainlink-ccv/common/jd/store"
	"github.com/smartcontractkit/chainlink-ccv/kmd"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"go.uber.org/zap/zapcore"
)

const (
	ConfigPathEnv     = "JD_WATCHER_CONFIG_PATH"
	DefaultConfigPath = "/etc/config.toml"
)

type config struct {
	// JDServerWSRPCURL is the URL of the Job Distributor server's WebSocket RPC endpoint.
	JDServerWSRPCURL string `toml:"jd_server_wsrpc_url"`
	// JDServerCSAPublicKey is the public key of the Job Distributor server's CSA key.
	JDServerCSAPublicKey string `toml:"jd_server_csa_public_key"`
	// JobStorePath is the path to the file to save jobs.
	JobStorePath string `toml:"job_store_path"`
	// ProcessBinaryPath is the path to the process binary to run.
	ProcessBinaryPath string `toml:"process_binary_path"`
	// ProcessConfigPathEnvVar is the env var name the process reads for its config file path (e.g. VERIFIER_CONFIG_PATH).
	ProcessConfigPathEnvVar string `toml:"process_config_path_env_var"`
	// KMDURL is the URL of the KMD server.
	KMDServerURL string `toml:"kmd_server_url"`
	// KMDCSAKeyName is the name of the KMD CSA key to use for JD communications.
	KMDCSAKeyName string `toml:"kmd_csa_key_name"`
}

func (c *config) validateJDServerCSAPublicKey() error {
	publicKey, err := hex.DecodeString(c.JDServerCSAPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode JDServerCSAPublicKey: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("JDServerCSAPublicKey is not an ed25519 public key")
	}
	return nil
}

func (c *config) validate() error {
	if c.JDServerWSRPCURL == "" {
		return fmt.Errorf("JDServerWSRPCURL is required")
	}
	if c.JDServerCSAPublicKey == "" {
		return fmt.Errorf("JDServerCSAPublicKey is required")
	}
	if err := c.validateJDServerCSAPublicKey(); err != nil {
		return fmt.Errorf("failed to validate JDServerCSAPublicKey: %w", err)
	}
	if c.JobStorePath == "" {
		return fmt.Errorf("JobStorePath is required")
	}
	if c.ProcessBinaryPath == "" {
		return fmt.Errorf("ProcessBinaryPath is required")
	}
	if c.ProcessConfigPathEnvVar == "" {
		return fmt.Errorf("ProcessConfigPathEnvVar is required")
	}
	if c.KMDServerURL == "" {
		return fmt.Errorf("KMDServerURL is required")
	}
	if c.KMDCSAKeyName == "" {
		return fmt.Errorf("KMDCSAKeyName is required")
	}
	return nil
}

func loadConfig(path string) (*config, error) {
	var cfg config
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}
	if len(md.Undecoded()) > 0 {
		return nil, fmt.Errorf("unknown fields in config: %v", md.Undecoded())
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	return &cfg, nil
}

func main() {
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		panic(fmt.Sprintf("Failed to create logger: %v", err))
	}
	lggr = logger.Sugared(logger.Named(lggr, "JDWatcher"))

	configPath := os.Getenv(ConfigPathEnv)
	if configPath == "" {
		configPath = DefaultConfigPath
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		lggr.Fatalw("Failed to load config", "error", err)
	}

	kmdClient := kmd.NewClient(cfg.KMDServerURL)

	csaSigner, err := newCSASigner(kmdClient, cfg.KMDCSAKeyName)
	if err != nil {
		lggr.Fatalw("Failed to create CSA signer", "error", err)
	}

	jdServerPublicKey, err := getJDPublicKey(cfg.JDServerCSAPublicKey)
	if err != nil {
		lggr.Fatalw("Failed to get JD public key", "error", err)
	}
	jdClient := jdclient.New(csaSigner, jdServerPublicKey, cfg.JDServerWSRPCURL, lggr)

	rnr := runner.NewProcessRunner(lggr, cfg.ProcessBinaryPath, cfg.ProcessConfigPathEnvVar)
	manager, err := jdlifecycle.NewManager(jdlifecycle.Config{
		JDClient: jdClient,
		JobStore: jobstore.NewFileStore(cfg.JobStorePath),
		Runner:   rnr,
		Logger:   lggr,
	})
	if err != nil {
		lggr.Fatalw("Failed to create lifecycle manager", "error", err)
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer startCancel()
	if err := manager.Start(startCtx); err != nil {
		lggr.Fatalw("Failed to start lifecycle manager", "error", err)
	}

	lggr.Infow("Lifecycle manager started")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	lggr.Infow("Received shutdown signal, stopping lifecycle manager...")
	if err := manager.Stop(); err != nil {
		lggr.Fatalw("Failed to stop lifecycle manager", "error", err)
	}
	lggr.Infow("Lifecycle manager stopped")
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
