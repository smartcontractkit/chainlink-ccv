package services

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // register the "postgres" sql driver

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	bootstrapdb "github.com/smartcontractkit/chainlink-ccv/bootstrap/db"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
)

// KeySpec declares a key to seed into a bootstrapper's keystore: its keystore name, a human-readable
// purpose label, and its cryptographic type. The names and types must match what the running service
// ensures on startup (see the WithKey options in each service's main), so the service finds the seeded
// keys instead of generating new ones.
type KeySpec struct {
	Name    string
	Purpose string
	Type    keystore.KeyType
}

// seedKeys provisions signing keys directly into a bootstrapper's Postgres keystore without running the
// service. It connects to dbURL (running the bootstrap migrations so the keystore table exists), loads
// the "default" keystore namespace with ksPassword, ensures each spec's key exists (creating it if
// absent), and returns the resulting public key material keyed by key name.
//
// This is devenv-only bring-up code: it lives here (not in the bootstrap package) so the production
// bootstrapper exposes no key-seeding entry point. It reuses only building blocks the running service
// already relies on (the keystore storage, EnsureKey, and the DB migrations). Local-mode devenv uses it
// to generate a node's signing identity up front, so the signer address is known before the container
// starts; the service's own startup then finds these keys already present and reuses them.
func seedKeys(ctx context.Context, dbURL, ksPassword string, specs []KeySpec) (map[string]keystore.KeyInfo, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("no key specs provided")
	}

	db, err := sqlx.ConnectContext(ctx, "postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to keystore database: %w", err)
	}
	defer func() { _ = db.Close() }()
	if err := bootstrapdb.RunMigrations(db); err != nil {
		return nil, fmt.Errorf("failed to run keystore database migrations: %w", err)
	}

	ks, err := keystore.LoadKeystore(ctx, keys.NewPGStorage(db, "default"), ksPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load keystore: %w", err)
	}

	lggr := logger.Nop()
	names := make([]string, 0, len(specs))
	for _, s := range specs {
		if err := keys.EnsureKey(ctx, lggr, ks, s.Name, s.Purpose, s.Type); err != nil {
			return nil, fmt.Errorf("failed to seed key %q (purpose=%q, type=%v): %w", s.Name, s.Purpose, s.Type, err)
		}
		names = append(names, s.Name)
	}

	resp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: names})
	if err != nil {
		return nil, fmt.Errorf("failed to read back seeded keys: %w", err)
	}

	result := make(map[string]keystore.KeyInfo, len(resp.Keys))
	for _, k := range resp.Keys {
		result[k.KeyInfo.Name] = k.KeyInfo
	}
	for _, name := range names {
		if _, ok := result[name]; !ok {
			return nil, fmt.Errorf("seeded key %q missing from keystore after creation", name)
		}
	}
	return result, nil
}
