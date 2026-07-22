package bootstrap

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// KeystoreSetter is implemented by Accessors that support keystore-managed signing keys.
// The executor checks for it so that pkg/chainaccess remains free of keystore dependencies.
type KeystoreSetter interface {
	// SetKeystore injects the keystore so the accessor can build and start any
	// signing services required by its ContractTransmitter.
	SetKeystore(ctx context.Context, ks keystore.Keystore) error
}

// KeystoreRegistry wraps a Registry and automatically injects the keystore into any
// Accessor returned by GetAccessor that implements KeystoreSetter.
type KeystoreRegistry struct {
	lggr  logger.Logger
	inner chainaccess.Registry
	ks    keystore.Keystore
}

// NewKeystoreRegistry returns a Registry that calls SetKeystore on every accessor
// that implements KeystoreSetter.
func NewKeystoreRegistry(lggr logger.Logger, inner chainaccess.Registry, ks keystore.Keystore) *KeystoreRegistry {
	return &KeystoreRegistry{lggr: lggr, inner: inner, ks: ks}
}

func (kr *KeystoreRegistry) GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (chainaccess.Accessor, error) {
	accessor, err := kr.inner.GetAccessor(ctx, chainSelector)
	if err != nil {
		return nil, err
	}
	if setter, ok := accessor.(KeystoreSetter); ok {
		if err := setter.SetKeystore(ctx, kr.ks); err != nil {
			if closeErr := accessor.Close(); closeErr != nil {
				kr.lggr.Warnw("Failed to close accessor after keystore setup failed", "chainSelector", chainSelector, "error", closeErr)
			}
			return nil, fmt.Errorf("failed to inject keystore for chain %d: %w", chainSelector, err)
		}
	} else if kr.ks != nil {
		kr.lggr.Warnw("Accessor does not implement KeystoreSetter; keystore will not be injected", "chainSelector", chainSelector)
	}
	return accessor, nil
}
