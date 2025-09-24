package ccv

//
//import (
//	"context"
//	"fmt"
//	"time"
//
//	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
//	"github.com/ethereum/go-ethereum/common/hexutil"
//	chainsel "github.com/smartcontractkit/chain-selectors"
//	ccvAggregatorOps "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/ccv_aggregator"
//	ccvProxyOps "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/ccv_proxy"
//	ccvAggregator "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
//	ccvProxy "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_proxy"
//	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
//)
//
//type Contracts struct {
//	Chain1337Details chainsel.ChainDetails
//	Chain2337Details chainsel.ChainDetails
//	Proxy1337        *ccvProxy.CCVProxy
//	Proxy2337        *ccvProxy.CCVProxy
//	Agg1337          *ccvAggregator.CCVAggregator
//	Agg2337          *ccvAggregator.CCVAggregator
//}
//
//// NewContracts creates new smart-contracts wrappers with utility functions
//func NewContracts(in *Cfg) (*Contracts, error) {
//	srcChain, err := chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[0].ChainID, chainsel.FamilyEVM)
//	if err != nil {
//		return nil, err
//	}
//	dstChain, err := chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[1].ChainID, chainsel.FamilyEVM)
//	if err != nil {
//		return nil, err
//	}
//	rpcSrc, _, _, err := ETHClient(in.Blockchains[0].Out.Nodes[0].ExternalWSUrl, in.CCV.GasSettings)
//	if err != nil {
//		return nil, err
//	}
//	rpcDst, _, _, err := ETHClient(in.Blockchains[1].Out.Nodes[0].ExternalWSUrl, in.CCV.GasSettings)
//	if err != nil {
//		return nil, err
//	}
//	proxySrcAddr, err := GetContractAddrForSelector(in, srcChain.ChainSelector, datastore.ContractType(ccvProxyOps.ContractType))
//	if err != nil {
//		return nil, err
//	}
//	proxyDstAddr, err := GetContractAddrForSelector(in, dstChain.ChainSelector, datastore.ContractType(ccvProxyOps.ContractType))
//	if err != nil {
//		return nil, err
//	}
//	proxySrc, err := ccvProxy.NewCCVProxy(proxySrcAddr, rpcSrc)
//	if err != nil {
//		return nil, err
//	}
//	proxyDst, err := ccvProxy.NewCCVProxy(proxyDstAddr, rpcDst)
//	if err != nil {
//		return nil, err
//	}
//	aggSrcAddr, err := GetContractAddrForSelector(in, srcChain.ChainSelector, datastore.ContractType(ccvAggregatorOps.ContractType))
//	if err != nil {
//		return nil, err
//	}
//	aggDstAddr, err := GetContractAddrForSelector(in, dstChain.ChainSelector, datastore.ContractType(ccvAggregatorOps.ContractType))
//	if err != nil {
//		return nil, err
//	}
//	aggSrc, err := ccvAggregator.NewCCVAggregator(aggSrcAddr, rpcSrc)
//	if err != nil {
//		return nil, err
//	}
//	aggDst, err := ccvAggregator.NewCCVAggregator(aggDstAddr, rpcDst)
//	if err != nil {
//		return nil, err
//	}
//	return &Contracts{
//		Chain1337Details: srcChain,
//		Chain2337Details: dstChain,
//		Proxy1337:        proxySrc,
//		Proxy2337:        proxyDst,
//		Agg1337:          aggSrc,
//		Agg2337:          aggDst,
//	}, nil
//}
//
//// FetchAllSentEventsBySelector fetch all CCIPMessageSent events from proxy contract
//func FetchAllSentEventsBySelector(proxy *ccvProxy.CCVProxy, selector uint64) ([]*ccvProxy.CCVProxyCCIPMessageSent, error) {
//	filter, err := proxy.FilterCCIPMessageSent(&bind.FilterOpts{}, []uint64{selector}, nil, nil)
//	if err != nil {
//		return nil, fmt.Errorf("failed to create filter: %w", err)
//	}
//	defer filter.Close()
//
//	var events []*ccvProxy.CCVProxyCCIPMessageSent
//
//	for filter.Next() {
//		event := filter.Event
//		events = append(events, event)
//
//		Plog.Info().
//			Any("TxHash", event.Raw.TxHash.Hex()).
//			Any("SeqNo", event.SequenceNumber).
//			Str("MsgID", hexutil.Encode(event.MessageId[:])).
//			Msg("Found CCIPMessageSent event")
//	}
//
//	if err := filter.Error(); err != nil {
//		return nil, fmt.Errorf("filter error: %w", err)
//	}
//
//	Plog.Info().Int("count", len(events)).Msg("Total CCIPMessageSent events found")
//	return events, nil
//}
//
//// FetchAllExecEventsBySelector fetch all ExecutionStateChanged events from aggregator contract
//func FetchAllExecEventsBySelector(agg *ccvAggregator.CCVAggregator, selector uint64) ([]*ccvAggregator.CCVAggregatorExecutionStateChanged, error) {
//	filter, err := agg.FilterExecutionStateChanged(&bind.FilterOpts{}, []uint64{selector}, nil, nil)
//	if err != nil {
//		return nil, fmt.Errorf("failed to create filter: %w", err)
//	}
//	defer filter.Close()
//
//	var events []*ccvAggregator.CCVAggregatorExecutionStateChanged
//
//	for filter.Next() {
//		event := filter.Event
//		events = append(events, event)
//
//		Plog.Info().
//			Any("State", event.State).
//			Any("TxHash", event.Raw.TxHash.Hex()).
//			Any("SeqNo", event.SequenceNumber).
//			Str("MsgID", hexutil.Encode(event.MessageId[:])).
//			Msg("Found ExecutionStateChanged event")
//	}
//
//	if err := filter.Error(); err != nil {
//		return nil, fmt.Errorf("filter error: %w", err)
//	}
//
//	Plog.Info().Int("count", len(events)).Msg("Total ExecutionStateChanged events found for selector and sequence")
//	return events, nil
//}
//
//// WaitOneSentEventBySeqNo wait and fetch strictly one CCIPMessageSent event by selector and sequence number and selector
//func WaitOneSentEventBySeqNo(proxy *ccvProxy.CCVProxy, selector uint64, seq uint64, timeout time.Duration) (*ccvProxy.CCVProxyCCIPMessageSent, error) {
//	ctx, cancel := context.WithTimeout(context.Background(), timeout)
//	defer cancel()
//	ticker := time.NewTicker(1 * time.Second)
//	defer ticker.Stop()
//
//	Plog.Info().Msg("Awaiting CCIPMessageSent event")
//
//	for {
//		select {
//		case <-ctx.Done():
//			return nil, ctx.Err()
//		case <-ticker.C:
//			filter, err := proxy.FilterCCIPMessageSent(&bind.FilterOpts{}, []uint64{selector}, []uint64{seq}, nil)
//			if err != nil {
//				Plog.Warn().Err(err).Msg("Failed to create filter")
//				continue
//			}
//			var eventFound *ccvProxy.CCVProxyCCIPMessageSent
//			eventCount := 0
//
//			for filter.Next() {
//				eventCount++
//				if eventCount > 1 {
//					filter.Close()
//					return nil, fmt.Errorf("received multiple events for the same sequence number and selector")
//				}
//				eventFound = filter.Event
//				Plog.Info().
//					Any("TxHash", filter.Event.Raw.TxHash.Hex()).
//					Any("SeqNo", filter.Event.SequenceNumber).
//					Str("MsgID", hexutil.Encode(filter.Event.MessageId[:])).
//					Msg("Received CCIPMessageSent event")
//			}
//			if err := filter.Error(); err != nil {
//				Plog.Warn().Err(err).Msg("Filter error")
//			}
//			filter.Close()
//			if eventFound != nil {
//				return eventFound, nil
//			}
//		}
//	}
//}
//
//// WaitOneExecEventBySeqNo wait and fetch strictly one ExecutionStateChanged event by sequence number and selector
//func WaitOneExecEventBySeqNo(agg *ccvAggregator.CCVAggregator, selector uint64, seq uint64, timeout time.Duration) (*ccvAggregator.CCVAggregatorExecutionStateChanged, error) {
//	ctx, cancel := context.WithTimeout(context.Background(), timeout)
//	defer cancel()
//
//	ticker := time.NewTicker(1 * time.Second)
//	defer ticker.Stop()
//
//	Plog.Info().Msg("Awaiting ExecutionStateChanged event")
//
//	for {
//		select {
//		case <-ctx.Done():
//			return nil, ctx.Err()
//		case <-ticker.C:
//			filter, err := agg.FilterExecutionStateChanged(&bind.FilterOpts{}, []uint64{selector}, []uint64{seq}, nil)
//			if err != nil {
//				Plog.Warn().Err(err).Msg("Failed to create filter")
//				continue
//			}
//
//			var eventFound *ccvAggregator.CCVAggregatorExecutionStateChanged
//			eventCount := 0
//
//			for filter.Next() {
//				eventCount++
//				if eventCount > 1 {
//					filter.Close()
//					return nil, fmt.Errorf("received multiple events for the same sequence number and selector")
//				}
//
//				eventFound = filter.Event
//				Plog.Info().
//					Any("State", filter.Event.State).
//					Any("TxHash", filter.Event.Raw.TxHash.Hex()).
//					Any("SeqNo", filter.Event.SequenceNumber).
//					Str("MsgID", hexutil.Encode(filter.Event.MessageId[:])).
//					Msg("Received ExecutionStateChanged event")
//			}
//
//			if err := filter.Error(); err != nil {
//				Plog.Warn().Err(err).Msg("Filter error")
//			}
//
//			filter.Close()
//
//			if eventFound != nil {
//				return eventFound, nil
//			}
//		}
//	}
//}
