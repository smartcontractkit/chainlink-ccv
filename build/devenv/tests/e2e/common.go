package e2e

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common/hexutil"
	chainsel "github.com/smartcontractkit/chain-selectors"
	ccvAggregatorOps "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/ccv_aggregator"
	ccvProxyOps "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/ccv_proxy"
	ccvAggregator "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	ccvProxy "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_proxy"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

type Contracts struct {
	srcChainDetails chainsel.ChainDetails
	dstChainDetails chainsel.ChainDetails
	proxySrc        *ccvProxy.CCVProxy
	proxyDst        *ccvProxy.CCVProxy
	aggSrc          *ccvAggregator.CCVAggregator
	aggDst          *ccvAggregator.CCVAggregator
}

func NewContracts(in *ccv.Cfg) (*Contracts, error) {
	srcChain, err := chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[0].ChainID, chainsel.FamilyEVM)
	if err != nil {
		return nil, err
	}
	dstChain, err := chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[1].ChainID, chainsel.FamilyEVM)
	if err != nil {
		return nil, err
	}
	rpcSrc, _, _, err := ccv.ETHClient(in.Blockchains[0].Out.Nodes[0].ExternalWSUrl, in.CCV.GasSettings)
	if err != nil {
		return nil, err
	}
	rpcDst, _, _, err := ccv.ETHClient(in.Blockchains[1].Out.Nodes[0].ExternalWSUrl, in.CCV.GasSettings)
	if err != nil {
		return nil, err
	}
	proxySrcAddr, err := ccv.GetContractAddrForSelector(in, srcChain.ChainSelector, datastore.ContractType(ccvProxyOps.ContractType))
	if err != nil {
		return nil, err
	}
	proxyDstAddr, err := ccv.GetContractAddrForSelector(in, dstChain.ChainSelector, datastore.ContractType(ccvProxyOps.ContractType))
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
	aggSrcAddr, err := ccv.GetContractAddrForSelector(in, srcChain.ChainSelector, datastore.ContractType(ccvAggregatorOps.ContractType))
	if err != nil {
		return nil, err
	}
	aggDstAddr, err := ccv.GetContractAddrForSelector(in, dstChain.ChainSelector, datastore.ContractType(ccvAggregatorOps.ContractType))
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
		srcChainDetails: srcChain,
		dstChainDetails: dstChain,
		proxySrc:        proxySrc,
		proxyDst:        proxyDst,
		aggSrc:          aggSrc,
		aggDst:          aggDst,
	}, nil
}

func FetchSentEventBySeqNo(proxy *ccvProxy.CCVProxy, selector uint64, seq uint64, timeout time.Duration) (*ccvProxy.CCVProxyCCIPMessageSent, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	ccv.Plog.Info().Msg("Awaiting CCIPMessageSent event")

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			filter, err := proxy.FilterCCIPMessageSent(&bind.FilterOpts{}, []uint64{selector}, []uint64{seq}, nil)
			if err != nil {
				ccv.Plog.Warn().Err(err).Msg("Failed to create filter")
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
				ccv.Plog.Info().
					Any("TxHash", filter.Event.Raw.TxHash.Hex()).
					Any("SeqNo", filter.Event.SequenceNumber).
					Str("MsgID", hexutil.Encode(filter.Event.MessageId[:])).
					Msg("Received CCIPMessageSent event")
			}
			if err := filter.Error(); err != nil {
				ccv.Plog.Warn().Err(err).Msg("Filter error")
			}
			filter.Close()
			if eventFound != nil {
				return eventFound, nil
			}
		}
	}
}

func FetchExecEventBySeqNo(agg *ccvAggregator.CCVAggregator, selector uint64, seq uint64, timeout time.Duration) (*ccvAggregator.CCVAggregatorExecutionStateChanged, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	ccv.Plog.Info().Msg("Awaiting ExecutionStateChanged event")

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			filter, err := agg.FilterExecutionStateChanged(&bind.FilterOpts{}, []uint64{selector}, []uint64{seq}, nil)
			if err != nil {
				ccv.Plog.Warn().Err(err).Msg("Failed to create filter")
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
				ccv.Plog.Info().
					Any("State", filter.Event.State).
					Any("TxHash", filter.Event.Raw.TxHash.Hex()).
					Any("SeqNo", filter.Event.SequenceNumber).
					Str("MsgID", hexutil.Encode(filter.Event.MessageId[:])).
					Msg("Received ExecutionStateChanged event")
			}

			if err := filter.Error(); err != nil {
				ccv.Plog.Warn().Err(err).Msg("Filter error")
			}

			filter.Close()

			if eventFound != nil {
				return eventFound, nil
			}
		}
	}
}
