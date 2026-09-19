package zk

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// LaneKey identifies a lane by its source and destination chain.
type LaneKey struct {
	SourceChainSelector protocol.ChainSelector
	DestChainSelector   protocol.ChainSelector
}

// LaneReaders holds the chain readers of one lane.
type LaneReaders struct {
	Source SourceProofReader
	Proven ProvenBlockReader
}

// DialLanes connects the chain readers of every lane. rpcURLs maps a chain selector to its HTTP JSON-RPC endpoint.
// One connection is shared by every lane that uses the same chain.
func DialLanes(ctx context.Context, lanes []Lane, rpcURLs map[protocol.ChainSelector]string) (map[LaneKey]LaneReaders, error) {
	clients := make(map[protocol.ChainSelector]*rpc.Client)
	dial := func(selector protocol.ChainSelector) (*rpc.Client, error) {
		if client, ok := clients[selector]; ok {
			return client, nil
		}
		family, err := chainsel.GetSelectorFamily(uint64(selector))
		if err != nil {
			return nil, fmt.Errorf("failed to get selector family for chain %d: %w", selector, err)
		}
		if family != chainsel.FamilyEVM {
			return nil, fmt.Errorf("chain %d: no reader for chain family %s", selector, family)
		}
		url, ok := rpcURLs[selector]
		if !ok {
			return nil, fmt.Errorf("chain %d has no RPC endpoint in the EVM config", selector)
		}
		client, err := rpc.DialContext(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("failed to dial chain %d: %w", selector, err)
		}
		clients[selector] = client
		return client, nil
	}

	readers := make(map[LaneKey]LaneReaders, len(lanes))
	for _, lane := range lanes {
		if len(lane.LightClient) != common.AddressLength {
			return nil, fmt.Errorf("light client %s of lane from chain %d to chain %d is not an EVM address", lane.LightClient, lane.SourceChainSelector, lane.DestChainSelector)
		}
		source, err := dial(lane.SourceChainSelector)
		if err != nil {
			return nil, err
		}
		dest, err := dial(lane.DestChainSelector)
		if err != nil {
			return nil, err
		}
		key := LaneKey{SourceChainSelector: lane.SourceChainSelector, DestChainSelector: lane.DestChainSelector}
		readers[key] = LaneReaders{
			Source: NewEVMSourceProofReader(ethclient.NewClient(source)),
			Proven: NewEVMProvenBlockReader(dest, common.BytesToAddress(lane.LightClient)),
		}
	}
	return readers, nil
}
