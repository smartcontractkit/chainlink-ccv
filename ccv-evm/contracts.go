package ccv_evm

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rs/zerolog"
	chainsel "github.com/smartcontractkit/chain-selectors"
	ccvAggregatorOps "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/ccv_aggregator"
	ccvProxyOps "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/ccv_proxy"
	ccvAggregator "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	ccvProxy "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_proxy"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

type Contracts struct {
	Chain1337Details chainsel.ChainDetails
	Chain2337Details chainsel.ChainDetails
	Proxy1337        *ccvProxy.CCVProxy
	Proxy2337        *ccvProxy.CCVProxy
	Agg1337          *ccvAggregator.CCVAggregator
	Agg2337          *ccvAggregator.CCVAggregator
}

// NewContracts creates new smart-contracts wrappers with utility functions
func NewContracts(ctx context.Context, addresses []string, chainIDs []string, wsURLs []string) (*Contracts, error) {
	srcChain, err := chainsel.GetChainDetailsByChainIDAndFamily(chainIDs[0], chainsel.FamilyEVM)
	if err != nil {
		return nil, err
	}
	dstChain, err := chainsel.GetChainDetailsByChainIDAndFamily(chainIDs[1], chainsel.FamilyEVM)
	if err != nil {
		return nil, err
	}
	gas := &GasSettings{
		FeeCapMultiplier: 2,
		TipCapMultiplier: 2,
	}
	rpcSrc, _, _, err := ETHClient(ctx, wsURLs[0], gas)
	if err != nil {
		return nil, err
	}
	rpcDst, _, _, err := ETHClient(ctx, wsURLs[1], gas)
	if err != nil {
		return nil, err
	}
	proxySrcAddr, err := GetContractAddrForSelector(addresses, srcChain.ChainSelector, datastore.ContractType(ccvProxyOps.ContractType))
	if err != nil {
		return nil, err
	}
	proxyDstAddr, err := GetContractAddrForSelector(addresses, dstChain.ChainSelector, datastore.ContractType(ccvProxyOps.ContractType))
	if err != nil {
		return nil, err
	}
	proxySrc, err := ccvProxy.NewCCVProxy(proxySrcAddr, rpcSrc)
	if err != nil {
		return nil, err
	}
	proxyDst, err := ccvProxy.NewCCVProxy(proxyDstAddr, rpcDst)
	if err != nil {
		return nil, err
	}
	aggSrcAddr, err := GetContractAddrForSelector(addresses, srcChain.ChainSelector, datastore.ContractType(ccvAggregatorOps.ContractType))
	if err != nil {
		return nil, err
	}
	aggDstAddr, err := GetContractAddrForSelector(addresses, dstChain.ChainSelector, datastore.ContractType(ccvAggregatorOps.ContractType))
	if err != nil {
		return nil, err
	}
	aggSrc, err := ccvAggregator.NewCCVAggregator(aggSrcAddr, rpcSrc)
	if err != nil {
		return nil, err
	}
	aggDst, err := ccvAggregator.NewCCVAggregator(aggDstAddr, rpcDst)
	if err != nil {
		return nil, err
	}
	return &Contracts{
		Chain1337Details: srcChain,
		Chain2337Details: dstChain,
		Proxy1337:        proxySrc,
		Proxy2337:        proxyDst,
		Agg1337:          aggSrc,
		Agg2337:          aggDst,
	}, nil
}

// FetchAllSentEventsBySelector fetch all CCIPMessageSent events from proxy contract
func FetchAllSentEventsBySelector(ctx context.Context, proxy *ccvProxy.CCVProxy, selector uint64) ([]*ccvProxy.CCVProxyCCIPMessageSent, error) {
	l := zerolog.Ctx(ctx)
	filter, err := proxy.FilterCCIPMessageSent(&bind.FilterOpts{}, []uint64{selector}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create filter: %w", err)
	}
	defer filter.Close()

	var events []*ccvProxy.CCVProxyCCIPMessageSent

	for filter.Next() {
		event := filter.Event
		events = append(events, event)

		l.Info().
			Any("TxHash", event.Raw.TxHash.Hex()).
			Any("SeqNo", event.SequenceNumber).
			Str("MsgID", hexutil.Encode(event.MessageId[:])).
			Msg("Found CCIPMessageSent event")
	}

	if err := filter.Error(); err != nil {
		return nil, fmt.Errorf("filter error: %w", err)
	}

	l.Info().Int("count", len(events)).Msg("Total CCIPMessageSent events found")
	return events, nil
}

// FetchAllExecEventsBySelector fetch all ExecutionStateChanged events from aggregator contract
func FetchAllExecEventsBySelector(ctx context.Context, agg *ccvAggregator.CCVAggregator, selector uint64) ([]*ccvAggregator.CCVAggregatorExecutionStateChanged, error) {
	l := zerolog.Ctx(ctx)
	filter, err := agg.FilterExecutionStateChanged(&bind.FilterOpts{}, []uint64{selector}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create filter: %w", err)
	}
	defer filter.Close()

	var events []*ccvAggregator.CCVAggregatorExecutionStateChanged

	for filter.Next() {
		event := filter.Event
		events = append(events, event)

		l.Info().
			Any("State", event.State).
			Any("TxHash", event.Raw.TxHash.Hex()).
			Any("SeqNo", event.SequenceNumber).
			Str("MsgID", hexutil.Encode(event.MessageId[:])).
			Msg("Found ExecutionStateChanged event")
	}

	if err := filter.Error(); err != nil {
		return nil, fmt.Errorf("filter error: %w", err)
	}

	l.Info().Int("count", len(events)).Msg("Total ExecutionStateChanged events found for selector and sequence")
	return events, nil
}

// WaitOneSentEventBySeqNo wait and fetch strictly one CCIPMessageSent event by selector and sequence number and selector
func WaitOneSentEventBySeqNo(ctx context.Context, proxy *ccvProxy.CCVProxy, selector uint64, seq uint64, timeout time.Duration) (*ccvProxy.CCVProxyCCIPMessageSent, error) {
	l := zerolog.Ctx(ctx)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	l.Info().Msg("Awaiting CCIPMessageSent event")

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			filter, err := proxy.FilterCCIPMessageSent(&bind.FilterOpts{}, []uint64{selector}, []uint64{seq}, nil)
			if err != nil {
				l.Warn().Err(err).Msg("Failed to create filter")
				continue
			}
			var eventFound *ccvProxy.CCVProxyCCIPMessageSent
			eventCount := 0

			for filter.Next() {
				eventCount++
				if eventCount > 1 {
					filter.Close()
					return nil, fmt.Errorf("received multiple events for the same sequence number and selector")
				}
				eventFound = filter.Event
				l.Info().
					Any("TxHash", filter.Event.Raw.TxHash.Hex()).
					Any("SeqNo", filter.Event.SequenceNumber).
					Str("MsgID", hexutil.Encode(filter.Event.MessageId[:])).
					Msg("Received CCIPMessageSent event")
			}
			if err := filter.Error(); err != nil {
				l.Warn().Err(err).Msg("Filter error")
			}
			filter.Close()
			if eventFound != nil {
				return eventFound, nil
			}
		}
	}
}

// WaitOneExecEventBySeqNo wait and fetch strictly one ExecutionStateChanged event by sequence number and selector
func WaitOneExecEventBySeqNo(ctx context.Context, agg *ccvAggregator.CCVAggregator, selector uint64, seq uint64, timeout time.Duration) (*ccvAggregator.CCVAggregatorExecutionStateChanged, error) {
	l := zerolog.Ctx(ctx)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	l.Info().Msg("Awaiting ExecutionStateChanged event")

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			filter, err := agg.FilterExecutionStateChanged(&bind.FilterOpts{}, []uint64{selector}, []uint64{seq}, nil)
			if err != nil {
				l.Warn().Err(err).Msg("Failed to create filter")
				continue
			}

			var eventFound *ccvAggregator.CCVAggregatorExecutionStateChanged
			eventCount := 0

			for filter.Next() {
				eventCount++
				if eventCount > 1 {
					filter.Close()
					return nil, fmt.Errorf("received multiple events for the same sequence number and selector")
				}

				eventFound = filter.Event
				l.Info().
					Any("State", filter.Event.State).
					Any("TxHash", filter.Event.Raw.TxHash.Hex()).
					Any("SeqNo", filter.Event.SequenceNumber).
					Str("MsgID", hexutil.Encode(filter.Event.MessageId[:])).
					Msg("Received ExecutionStateChanged event")
			}

			if err := filter.Error(); err != nil {
				l.Warn().Err(err).Msg("Filter error")
			}

			filter.Close()

			if eventFound != nil {
				return eventFound, nil
			}
		}
	}
}

// GetContractAddrForSelector get contract address by type and chain selector.
func GetContractAddrForSelector(addresses []string, selector uint64, contractType datastore.ContractType) (common.Address, error) {
	var contractAddr common.Address
	for _, addr := range addresses {
		var refs []datastore.AddressRef
		err := json.Unmarshal([]byte(addr), &refs)
		if err != nil {
			return common.Address{}, err
		}
		for _, ref := range refs {
			if ref.ChainSelector == selector && ref.Type == contractType {
				contractAddr = common.HexToAddress(ref.Address)
			}
		}
	}
	return contractAddr, nil
}
