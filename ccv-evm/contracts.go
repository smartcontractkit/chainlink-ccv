package ccv_evm

import (
	"context"
	"encoding/json"
	"fmt"

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
	ProxyBySelector  map[uint64]*ccvProxy.CCVProxy
	AggBySelector    map[uint64]*ccvAggregator.CCVAggregator
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
		ProxyBySelector: map[uint64]*ccvProxy.CCVProxy{
			srcChain.ChainSelector: proxySrc,
			dstChain.ChainSelector: proxyDst,
		},
		AggBySelector: map[uint64]*ccvAggregator.CCVAggregator{
			srcChain.ChainSelector: aggSrc,
			dstChain.ChainSelector: aggDst,
		},
	}, nil
}

// FetchAllSentEventsBySelector fetch all CCIPMessageSent events from proxy contract
func (c *Contracts) FetchAllSentEventsBySelector(ctx context.Context, from, to uint64) ([]*ccvProxy.CCVProxyCCIPMessageSent, error) {
	l := zerolog.Ctx(ctx)
	proxy, ok := c.ProxyBySelector[from]
	if !ok {
		return nil, fmt.Errorf("no proxy for selector %d", from)
	}
	filter, err := proxy.FilterCCIPMessageSent(&bind.FilterOpts{}, []uint64{to}, nil, nil)
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
func (c *Contracts) FetchAllExecEventsBySelector(ctx context.Context, from, to uint64) ([]*ccvAggregator.CCVAggregatorExecutionStateChanged, error) {
	l := zerolog.Ctx(ctx)
	agg, ok := c.AggBySelector[from]
	if !ok {
		return nil, fmt.Errorf("no aggregator for selector %d", from)
	}
	filter, err := agg.FilterExecutionStateChanged(&bind.FilterOpts{}, []uint64{to}, nil, nil)
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
