package bootstrap

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// KeystoreSetter is implemented by Accessors that support keystore-managed signing keys.
// The executor checks for it so that pkg/chainaccess remains free of keystore dependencies.
type KeystoreSetter interface {
	SetKeystore(ks keystore.Keystore)
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
		setter.SetKeystore(kr.ks)
	} else {
		kr.lggr.Warnw("Accessor does not implement KeystoreSetter; keystore will not be injected", "chainSelector", chainSelector)
	}
	return accessor, nil
}
