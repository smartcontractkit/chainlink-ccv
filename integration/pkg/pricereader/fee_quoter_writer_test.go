package pricereader_test

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/pricereader"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestLoggingFeeQuoterWriterLogsTheUpdates(t *testing.T) {
	lggr, logs := logger.TestObserved(t, zapcore.InfoLevel)
	fq := common.HexToAddress("0xfee")
	writer := pricereader.NewLoggingFeeQuoterWriter(lggr, fq)

	err := writer.UpdatePrices(context.Background(),
		[]protocol.FeeTokenPriceUpdate{{
			Address: common.HexToAddress("0x1").Bytes(),
			Price:   (*protocol.USDPerWholeToken)(big.NewInt(15)),
		}},
		[]protocol.GasTokenPriceUpdate{{
			ChainSelector: 5009297550715157269,
			USDGasPrice: protocol.USDGasPrice{
				ExecutionFee: (*protocol.USDPerGasUnit)(big.NewInt(3)),
				DAFee:        nil,
			},
		}},
	)
	require.NoError(t, err)

	entries := logs.FilterMessage("Fee quoter price update not sent, the writer only logs").All()
	require.Len(t, entries, 1)
	fields := entries[0].ContextMap()
	require.Equal(t, fq.Hex(), fields["feeQuoter"])
	require.Equal(t, []map[string]string{{"address": "0x0000000000000000000000000000000000000001", "usdPerWholeToken": "15"}}, fields["tokenPrices"])
	require.Equal(t, []map[string]any{{
		"chainSelector":   protocol.ChainSelector(5009297550715157269),
		"executionFeeUSD": "3",
		"daFeeUSD":        "<nil>",
	}}, fields["gasPrices"])
}

func TestLoggingFeeQuoterWriterAcceptsAnEmptyUpdate(t *testing.T) {
	writer := pricereader.NewLoggingFeeQuoterWriter(logger.Test(t), common.Address{})
	require.NoError(t, writer.UpdatePrices(context.Background(), nil, nil))
}
