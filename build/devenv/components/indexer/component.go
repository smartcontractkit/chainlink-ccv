package indexer

import (
	"context"
	"fmt"
	"maps"
	"strconv"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
)

const configKey = "indexer"

// preparedIndexerInputsKey must match the constant in legacy_component.go.
const preparedIndexerInputsKey = "_prepared_indexer_inputs"

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("indexer component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

func (c *component) ValidateConfig(_ any) error { return nil }

// RunPhase4 takes the *services.IndexerInput pointers published by the legacy
// Phase 3 component, wires TLS, aggregator discovery config, and secrets, then
// calls services.NewIndexer. Mutations on the shared pointers are visible to
// runPhasedEnvironmentFinish, which reads idxIn.Out for URL collection.
func (c *component) RunPhase4(
	_ context.Context,
	_ map[string]any,
	_ any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	inputs, ok := priorOutputs[preparedIndexerInputsKey].([]*services.IndexerInput)
	if !ok {
		// No indexer inputs — env.toml omits [[indexer]].
		return map[string]any{}, nil, nil
	}

	aggregators, _ := priorOutputs["aggregators"].([]*services.AggregatorInput)

	var tlsCerts *services.TLSCertPaths
	if v, ok := priorOutputs["shared_tls_certs"].(*services.TLSCertPaths); ok {
		tlsCerts = v
	}

	if len(aggregators) > 0 && tlsCerts == nil {
		return nil, nil, fmt.Errorf("shared TLS certificates are required when aggregators are configured")
	}

	// Build discovery and verifier secrets from aggregator outputs.
	// Ensure every index 0..n-1 has an entry so the written secrets file has
	// Discoveries.0, .1, ...; otherwise the indexer can panic in CI with
	// "discovery index 0 not found in secrets" when merging.
	discoverySecrets := make(map[string]config.DiscoverySecrets)
	verifierSecrets := make(map[string]config.VerifierSecrets)
	for i, agg := range aggregators {
		key := strconv.Itoa(i)
		var disc config.DiscoverySecrets
		var ver config.VerifierSecrets
		if agg.Out != nil {
			if creds, ok := agg.Out.GetCredentialsForClient("indexer"); ok {
				disc = config.DiscoverySecrets{APIKey: creds.APIKey, Secret: creds.Secret}
				ver = config.VerifierSecrets{APIKey: creds.APIKey, Secret: creds.Secret}
			}
		}
		discoverySecrets[key] = disc
		verifierSecrets[key] = ver
	}

	for i, idxIn := range inputs {
		if idxIn == nil {
			continue
		}

		// Container name defaults to indexer-1, indexer-2, ... for consistency.
		if idxIn.ContainerName == "" {
			idxIn.ContainerName = fmt.Sprintf("indexer-%d", i+1)
		}

		// Assign distinct DB host ports for multiple indexers.
		if idxIn.DB != nil && idxIn.DB.HostPort == 0 && len(inputs) > 1 {
			idxIn.DB.HostPort = services.DefaultIndexerDBPort + i
		}

		// Build storage connection URL from DB config.
		// Env.toml may have single-instance URLs; overwrite so migrations and
		// storage use the correct host/credentials for each instance.
		dbName := idxIn.ContainerName
		if idxIn.DB != nil && idxIn.DB.Database != "" {
			dbName = idxIn.DB.Database
		}
		dbUser := idxIn.ContainerName
		if idxIn.DB != nil && idxIn.DB.Username != "" {
			dbUser = idxIn.DB.Username
		}
		dbPass := idxIn.ContainerName
		if idxIn.DB != nil && idxIn.DB.Password != "" {
			dbPass = idxIn.DB.Password
		}
		dbHost := idxIn.ContainerName + "-db"
		idxIn.StorageConnectionURL = fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable", dbUser, dbPass, dbHost, dbName)

		// Wire TLS CA cert so the indexer can verify aggregator gRPC connections.
		if tlsCerts != nil {
			idxIn.TLSCACertFile = tlsCerts.CACertFile
		}

		// Build aggregator discovery config entries.
		if idxIn.IndexerConfig == nil {
			idxIn.IndexerConfig = &config.Config{}
		}
		idxIn.IndexerConfig.Discoveries = make([]config.DiscoveryConfig, len(aggregators))
		for j, agg := range aggregators {
			if agg.Out != nil {
				idxIn.IndexerConfig.Discoveries[j].Address = agg.Out.Address
				if creds, ok := agg.Out.GetCredentialsForClient("indexer"); ok {
					idxIn.IndexerConfig.Discoveries[j].APIKey = creds.APIKey
					idxIn.IndexerConfig.Discoveries[j].Secret = creds.Secret
				}
			}
			if idxIn.IndexerConfig.Discoveries[j].PollInterval == 0 {
				idxIn.IndexerConfig.Discoveries[j].PollInterval = 500
			}
			if idxIn.IndexerConfig.Discoveries[j].Timeout == 0 {
				idxIn.IndexerConfig.Discoveries[j].Timeout = 5000
			}
			if idxIn.IndexerConfig.Discoveries[j].NtpServer == "" {
				idxIn.IndexerConfig.Discoveries[j].NtpServer = "time.google.com"
			}
		}

		// Wire discovery and verifier secrets (same credentials for all indexers).
		if idxIn.Secrets == nil {
			idxIn.Secrets = &config.SecretsConfig{
				Discoveries: make(map[string]config.DiscoverySecrets),
				Verifier:    make(map[string]config.VerifierSecrets),
			}
		}
		if idxIn.Secrets.Discoveries == nil {
			idxIn.Secrets.Discoveries = make(map[string]config.DiscoverySecrets)
		}
		if idxIn.Secrets.Verifier == nil {
			idxIn.Secrets.Verifier = make(map[string]config.VerifierSecrets)
		}
		maps.Copy(idxIn.Secrets.Discoveries, discoverySecrets)
		maps.Copy(idxIn.Secrets.Verifier, verifierSecrets)
		// Indexer loads secrets and overwrites the config URI, so secrets must
		// reference the same DB URL we computed above.
		idxIn.Secrets.Storage.Single.Postgres.URI = idxIn.StorageConnectionURL

		out, err := services.NewIndexer(idxIn)
		if err != nil {
			return nil, nil, fmt.Errorf("starting indexer %q: %w", idxIn.ContainerName, err)
		}
		idxIn.Out = out
	}

	return map[string]any{}, nil, nil
}
