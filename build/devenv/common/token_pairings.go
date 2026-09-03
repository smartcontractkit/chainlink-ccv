package common

import (
	"fmt"
	"strconv"

	"github.com/Masterminds/semver/v3"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// TokenPoolRefCfg declares one pool leg by exact type+version+qualifier.
// Deliberately not datastore.AddressRef: no Address (refs resolve against
// [[addresses]]) and string fields, since selectors and this schema stay
// decoupled from CLD Go types.
type TokenPoolRefCfg struct {
	Type      string `toml:"type"`
	Version   string `toml:"version"`
	Qualifier string `toml:"qualifier"`
}

// TokenPairing declares one directional lane. Selectors are strings: they
// exceed the int64 range TOML integer literals decode into.
type TokenPairing struct {
	LocalSelector  string          `toml:"local_selector"`
	RemoteSelector string          `toml:"remote_selector"`
	LocalPool      TokenPoolRefCfg `toml:"local_pool"`
	RemotePool     TokenPoolRefCfg `toml:"remote_pool"`
	CCVQualifiers  []string        `toml:"ccv_qualifiers"`
}

// TokenCombinationsFromPairings resolves declared pairings against the
// datastore. Each leg must exist by exact type+version+qualifier on its
// declared selector; missing refs are named errors. Output order follows
// declaration order.
func TokenCombinationsFromPairings(ds datastore.DataStore, pairs []TokenPairing) ([]TokenCombination, error) {
	combos := make([]TokenCombination, 0, len(pairs))
	for i, p := range pairs {
		local, err := p.LocalPool.leg(ds, "local", p.LocalSelector)
		if err != nil {
			return nil, fmt.Errorf("token pairing %d: %w", i, err)
		}
		remote, err := p.RemotePool.leg(ds, "remote", p.RemoteSelector)
		if err != nil {
			return nil, fmt.Errorf("token pairing %d: %w", i, err)
		}

		// Sides below 2.0.0 predate CCV; only committee-aware sides carry the
		// declared qualifiers (same rule as ComputeTokenCombinations).
		localQ, remoteQ := pairingCCVQualifiers(p.LocalPool.Version, p.CCVQualifiers),
			pairingCCVQualifiers(p.RemotePool.Version, p.CCVQualifiers)
		combo := newTokenCombination(
			local.Type.String(), local.Version.String(), localQ,
			remote.Type.String(), remote.Version.String(), remoteQ,
		)
		combo.localPoolQualifier = local.Qualifier
		combo.remotePoolQualifier = remote.Qualifier
		combos = append(combos, combo)
	}
	return combos, nil
}

// leg resolves one declared pool leg against the datastore by exact
// type+version+qualifier on its declared selector.
func (r TokenPoolRefCfg) leg(ds datastore.DataStore, side, selector string) (datastore.AddressRef, error) {
	sel, err := strconv.ParseUint(selector, 10, 64)
	if err != nil {
		return datastore.AddressRef{}, fmt.Errorf("%s selector: %w", side, err)
	}
	ref, err := r.addressRef()
	if err != nil {
		return datastore.AddressRef{}, fmt.Errorf("%s pool: %w", side, err)
	}
	if !dataStoreHasAddressRef(ds, sel, ref) {
		return datastore.AddressRef{}, fmt.Errorf(
			"%s pool %s %s %q not found on chain %d",
			side, r.Type, r.Version, r.Qualifier, sel)
	}
	return ref, nil
}

// pairingCCVQualifiers returns the declared committee qualifiers when the pool
// version is CCV-aware, else nil.
func pairingCCVQualifiers(version string, ccvQualifiers []string) []string {
	if !IsCCVAwarePoolVersion(version) {
		return nil
	}
	return ccvQualifiers
}

func (r TokenPoolRefCfg) addressRef() (datastore.AddressRef, error) {
	if r.Qualifier == "" {
		return datastore.AddressRef{}, fmt.Errorf("pool qualifier must be set")
	}
	v, err := semver.NewVersion(r.Version)
	if err != nil {
		return datastore.AddressRef{}, fmt.Errorf("invalid pool version %q: %w", r.Version, err)
	}
	return datastore.AddressRef{
		Type:      datastore.ContractType(r.Type),
		Version:   v,
		Qualifier: r.Qualifier,
	}, nil
}
