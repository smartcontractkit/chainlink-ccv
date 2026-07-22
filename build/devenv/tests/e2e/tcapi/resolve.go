package tcapi

import (
	"context"
	"fmt"

	chain_selectors "github.com/smartcontractkit/chain-selectors"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// V3Env holds devenv handles loaded for V3 message resolution. It is
// family-agnostic: the AddressResolver and V3Destination interfaces are
// implemented by every chain family registered in chainreg.
type V3Env struct {
	DS          datastore.DataStore
	Dst         cciptestinterfaces.V3Destination
	SrcResolver chainreg.AddressResolver
	DstResolver chainreg.AddressResolver
}

// LoadV3Env loads the DataStore, destination V3Destination, and source/dest
// AddressResolvers from the chain registry. Returns (env, false) if any
// prerequisite is missing (e.g. no AddressResolver registered for a family).
func LoadV3Env(ctx context.Context, lib ccv.Lib, src, dst uint64) (V3Env, bool) {
	var env V3Env

	ds, err := lib.DataStore()
	if err != nil {
		return env, false
	}
	env.DS = ds

	dstChain, err := lib.V3Destination(ctx, dst)
	if err != nil {
		return env, false
	}
	env.Dst = dstChain

	srcFamily, err := chain_selectors.GetSelectorFamily(src)
	if err != nil {
		return env, false
	}
	dstFamily, err := chain_selectors.GetSelectorFamily(dst)
	if err != nil {
		return env, false
	}

	srcReg, err := chainreg.GetRegistry().Get(srcFamily)
	if err != nil {
		return env, false
	}
	dstReg, err := chainreg.GetRegistry().Get(dstFamily)
	if err != nil {
		return env, false
	}
	if srcReg.AddressResolver == nil || dstReg.AddressResolver == nil {
		return env, false
	}
	env.SrcResolver = srcReg.AddressResolver
	env.DstResolver = dstReg.AddressResolver

	return env, true
}

// GetCommitteeCCV resolves the committee verifier CCV address for the given
// source chain and qualifier via the family's AddressResolver.
func GetCommitteeCCV(resolver chainreg.AddressResolver, ds datastore.DataStore, srcChainSelector uint64, qualifier string) (protocol.CCV, error) {
	addr, err := resolver.GetCommitteeCCV(ds, srcChainSelector, qualifier)
	if err != nil {
		return protocol.CCV{}, err
	}
	return protocol.CCV{CCVAddress: addr, Args: []byte{}, ArgsLen: 0}, nil
}

// ResolveV3SendAddresses resolves the receiver on dst and the default committee
// CCV and default executor on src for a minimal V3 send. It is family-agnostic:
// it uses the chainreg AddressResolver and V3Destination interfaces, which every
// chain family implements. Callers that need family-specific SendArgs or
// ExtraArgs (e.g. Solana's SvmDestBlob) construct those separately.
func ResolveV3SendAddresses(ctx context.Context, lib ccv.Lib, src, dst uint64) (protocol.UnknownAddress, []protocol.CCV, protocol.UnknownAddress, error) {
	env, ok := LoadV3Env(ctx, lib, src, dst)
	if !ok {
		return protocol.UnknownAddress{}, nil, protocol.UnknownAddress{}, fmt.Errorf("prerequisites not met for src %d dst %d (datastore, V3 destination, and address resolvers must be available)", src, dst)
	}
	receiver, err := env.Dst.GetEOAReceiverAddress()
	if err != nil {
		return protocol.UnknownAddress{}, nil, protocol.UnknownAddress{}, fmt.Errorf("dest EOA receiver: %w", err)
	}
	cv, err := GetCommitteeCCV(env.SrcResolver, env.DS, src, common.DefaultCommitteeVerifierQualifier)
	if err != nil {
		return protocol.UnknownAddress{}, nil, protocol.UnknownAddress{}, fmt.Errorf("committee CCV: %w", err)
	}
	executor, err := env.SrcResolver.GetExecutor(env.DS, src, common.DefaultExecutorQualifier)
	if err != nil {
		return protocol.UnknownAddress{}, nil, protocol.UnknownAddress{}, fmt.Errorf("executor: %w", err)
	}
	return receiver, []protocol.CCV{cv}, executor, nil
}
