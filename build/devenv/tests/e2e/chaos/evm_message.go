package chaos

import (
	"context"
	"fmt"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// EVMMessage holds V3 message fields and options hydrated for a simple EOA-receiver
// send with the default committee CCV and executor on the source chain.
type EVMMessage struct {
	Fields  cciptestinterfaces.MessageFields
	MsgOpts cciptestinterfaces.MessageOptions
}

// HydrateEVMEOADefaultVerifier builds message fields for a minimal arb-style V3 send
// between two chains that register chainreg.AddressResolver on source and destination.
func HydrateEVMEOADefaultVerifier(ctx context.Context, lib ccv.Lib, src, dst uint64) (EVMMessage, error) {
	var msg EVMMessage

	ds, err := lib.DataStore()
	if err != nil {
		return msg, fmt.Errorf("datastore: %w", err)
	}

	chainMap, err := lib.ChainsMap(ctx)
	if err != nil {
		return msg, fmt.Errorf("chains map: %w", err)
	}

	dstChain, ok := chainMap[dst]
	if !ok {
		return msg, fmt.Errorf("dest chain %d not found", dst)
	}

	receiver, err := dstChain.GetEOAReceiverAddress()
	if err != nil {
		return msg, fmt.Errorf("dest EOA receiver: %w", err)
	}

	srcFamily, err := chain_selectors.GetSelectorFamily(src)
	if err != nil {
		return msg, fmt.Errorf("source family: %w", err)
	}
	srcReg, err := chainreg.GetRegistry().Get(srcFamily)
	if err != nil {
		return msg, fmt.Errorf("source registry: %w", err)
	}
	if srcReg.AddressResolver == nil {
		return msg, fmt.Errorf("source family %q has no AddressResolver", srcFamily)
	}

	ccvAddr, err := getCommitteeCCV(srcReg.AddressResolver, ds, src, devenvcommon.DefaultCommitteeVerifierQualifier)
	if err != nil {
		return msg, fmt.Errorf("committee CCV: %w", err)
	}

	executorAddr, err := srcReg.AddressResolver.GetExecutor(ds, src, devenvcommon.DefaultExecutorQualifier)
	if err != nil {
		return msg, fmt.Errorf("executor: %w", err)
	}

	msg.Fields = cciptestinterfaces.MessageFields{
		Receiver: receiver,
		Data:     []byte{},
	}
	msg.MsgOpts = cciptestinterfaces.MessageOptions{
		FinalityConfig: 1,
		Executor:       executorAddr,
		CCVs:           []protocol.CCV{ccvAddr},
	}
	return msg, nil
}

func getCommitteeCCV(resolver chainreg.AddressResolver, ds datastore.DataStore, srcChainSelector uint64, qualifier string) (protocol.CCV, error) {
	addr, err := resolver.GetCommitteeCCV(ds, srcChainSelector, qualifier)
	if err != nil {
		return protocol.CCV{}, err
	}
	return protocol.CCV{CCVAddress: addr, Args: []byte{}, ArgsLen: 0}, nil
}
