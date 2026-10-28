package pricereader

import (
	"context"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/fee_quoter"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/pricereader/pricereadertest"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/txmgr"
)

func TestEVMFeeQuoterWriterLogsTheUpdates(t *testing.T) {
	lggr, logs := logger.TestObserved(t, zapcore.InfoLevel)
	env := pricereadertest.New(t)
	fq := common.HexToAddress("0xfee")
	writer := NewEVMFeeQuoterWriter(lggr, env.Client, fq)

	err := writer.UpdatePrices(context.Background(),
		[]protocol.FeeTokenPriceUpdate{{
			Address: env.USDC.Bytes(),
			Price:   (*protocol.USDPerWholeToken)(big.NewInt(1e18)),
		}},
		[]protocol.GasTokenPriceUpdate{{
			ChainSelector: 5009297550715157269,
			USDGasPrice: protocol.USDGasPrice{
				ExecutionFee: (*protocol.USDPerGasUnit)(big.NewInt(3e18)),
				DAFee:        (*protocol.USDPerGasUnit)(big.NewInt(2e18)),
			},
		}},
	)
	require.NoError(t, err)

	entries := logs.FilterMessage("Fee quoter price update not sent, the writer has no transaction manager").All()
	require.Len(t, entries, 1)
	fields := entries[0].ContextMap()
	require.Equal(t, fq.Hex(), fields["feeQuoter"])
	prices, ok := fields["prices"].(fee_quoter.InternalPriceUpdates)
	require.True(t, ok, "prices should be the updatePrices argument")

	require.Len(t, prices.TokenPriceUpdates, 1)
	token := prices.TokenPriceUpdates[0]
	require.Equal(t, env.USDC, token.SourceToken)
	// 15e18 * 1e18 / 10^6 = 1e30, USDC has 6 decimals.
	require.Equal(t, new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil), token.UsdPerToken)

	require.Len(t, prices.GasPriceUpdates, 1)
	gas := prices.GasPriceUpdates[0]
	require.EqualValues(t, 5009297550715157269, gas.DestChainSelector)
	packed := new(big.Int).Or(new(big.Int).Lsh(big.NewInt(2e18), 112), big.NewInt(3e18))
	require.Equal(t, packed, gas.UsdPerUnitGas)
}

func TestEVMFeeQuoterWriterAcceptsAnEmptyUpdate(t *testing.T) {
	writer := NewEVMFeeQuoterWriter(logger.Test(t), nil, common.Address{})
	require.NoError(t, writer.UpdatePrices(context.Background(), nil, nil))
}

// countingClient counts the RPC batches sent to the wrapped client.
type countingClient struct {
	batchClient
	batches atomic.Int32
}

func (c *countingClient) BatchCallContext(ctx context.Context, b []rpc.BatchElem) error {
	c.batches.Add(1)
	return c.batchClient.BatchCallContext(ctx, b)
}

func TestTokenDecimalsReadsDecimalsFromTheTokens(t *testing.T) {
	env := pricereadertest.New(t)
	writer := NewEVMFeeQuoterWriter(logger.Test(t), env.Client, common.Address{})

	got, err := writer.tokenDecimals(context.Background(), []common.Address{env.USDC, env.Link})
	require.NoError(t, err)
	require.Equal(t, map[common.Address]uint8{env.USDC: 6, env.Link: 18}, got)
}

func TestTokenDecimalsReadsTokensInOneBatchWithoutDuplicates(t *testing.T) {
	env := pricereadertest.New(t)
	client := &countingClient{batchClient: env.Client}
	writer := NewEVMFeeQuoterWriter(logger.Test(t), client, common.Address{})

	got, err := writer.tokenDecimals(context.Background(), []common.Address{env.USDC, env.Link, env.USDC})
	require.NoError(t, err)
	require.Equal(t, map[common.Address]uint8{env.USDC: 6, env.Link: 18}, got)
	require.EqualValues(t, 1, client.batches.Load())
}

func TestTokenDecimalsCachesDecimals(t *testing.T) {
	env := pricereadertest.New(t)
	client := &countingClient{batchClient: env.Client}
	writer := NewEVMFeeQuoterWriter(logger.Test(t), client, common.Address{})

	_, err := writer.tokenDecimals(context.Background(), []common.Address{env.USDC})
	require.NoError(t, err)
	require.EqualValues(t, 1, client.batches.Load())

	// A cached token is not read again; only the new token is.
	got, err := writer.tokenDecimals(context.Background(), []common.Address{env.USDC, env.Link})
	require.NoError(t, err)
	require.Equal(t, map[common.Address]uint8{env.USDC: 6, env.Link: 18}, got)
	require.EqualValues(t, 2, client.batches.Load())

	_, err = writer.tokenDecimals(context.Background(), []common.Address{env.USDC, env.Link})
	require.NoError(t, err)
	require.EqualValues(t, 2, client.batches.Load())
}

func TestTokenDecimalsWithoutTokensDoesNotNeedAClient(t *testing.T) {
	writer := NewEVMFeeQuoterWriter(logger.Test(t), nil, common.Address{})
	got, err := writer.tokenDecimals(context.Background(), nil)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestTokenDecimalsWithoutAClientFails(t *testing.T) {
	writer := NewEVMFeeQuoterWriter(logger.Test(t), nil, common.Address{})
	_, err := writer.tokenDecimals(context.Background(), []common.Address{common.HexToAddress("0x1")})
	require.ErrorContains(t, err, "no client")
}

func TestTokenDecimalsFailsForAnAddressThatIsNotAToken(t *testing.T) {
	env := pricereadertest.New(t)
	writer := NewEVMFeeQuoterWriter(logger.Test(t), env.Client, common.Address{})
	_, err := writer.tokenDecimals(context.Background(), []common.Address{common.HexToAddress("0xdead")})
	require.Error(t, err)
}

func TestScaleTokenPrices(t *testing.T) {
	usdc, link, zero := common.HexToAddress("0x1"), common.HexToAddress("0x2"), common.HexToAddress("0x3")
	decimals := map[common.Address]uint8{usdc: 6, link: 18, zero: 0}
	update := func(token common.Address, price string) protocol.FeeTokenPriceUpdate {
		return protocol.FeeTokenPriceUpdate{Address: token.Bytes(), Price: (*protocol.USDPerWholeToken)(mustBig(t, price))}
	}

	in := []protocol.FeeTokenPriceUpdate{
		update(usdc, "1000000000000000000"),
		update(link, "15000000000000000000"),
		update(zero, "2"),
		update(usdc, "0"),
	}
	out, err := scaleTokenPrices(in, decimals)
	require.NoError(t, err)
	require.Len(t, out, len(in))

	want := []string{"1000000000000000000000000000000", "15000000000000000000", "2000000000000000000", "0"}
	for i, price := range want {
		require.Equal(t, in[i].Address, out[i].Address)
		requireSameInt(t, mustBig(t, price), (*big.Int)(out[i].Price))
	}
	require.Equal(t, mustBig(t, "15000000000000000000"), (*big.Int)(in[0].Price), "input must not change")
}

func TestScaleTokenPricesIsTheInverseOfTheReaderConversion(t *testing.T) {
	token := common.HexToAddress("0x1")
	for _, decimals := range []uint8{0, 6, 8, 18} {
		price := mustBig(t, "15000000000000000000")
		out, err := scaleTokenPrices(
			[]protocol.FeeTokenPriceUpdate{{Address: token.Bytes(), Price: (*protocol.USDPerWholeToken)(price)}},
			map[common.Address]uint8{token: decimals},
		)
		require.NoError(t, err)
		back := onChainTokenPriceToUSDPerWholeToken((*big.Int)(out[0].Price), decimals)
		requireSameInt(t, price, back.ToInt())
	}
}

func TestScaleTokenPricesRejectsInvalidPrices(t *testing.T) {
	token := common.HexToAddress("0x1")
	for name, price := range map[string]*protocol.USDPerWholeToken{
		"nil":      nil,
		"negative": (*protocol.USDPerWholeToken)(big.NewInt(-1)),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := scaleTokenPrices(
				[]protocol.FeeTokenPriceUpdate{{Address: token.Bytes(), Price: price}},
				map[common.Address]uint8{token: 18},
			)
			require.ErrorContains(t, err, "invalid price")
		})
	}
}

func TestScaleTokenPricesWithNoUpdates(t *testing.T) {
	out, err := scaleTokenPrices(nil, nil)
	require.NoError(t, err)
	require.Empty(t, out)
}

func TestScaleGasPriceScalesOnlyHedera(t *testing.T) {
	gasPrice := func(selector uint64, exec, da int64) protocol.GasTokenPriceUpdate {
		return protocol.GasTokenPriceUpdate{
			ChainSelector: protocol.ChainSelector(selector),
			USDGasPrice: protocol.USDGasPrice{
				ExecutionFee: (*protocol.USDPerGasUnit)(big.NewInt(exec)),
				DAFee:        (*protocol.USDPerGasUnit)(big.NewInt(da)),
			},
		}
	}
	in := []protocol.GasTokenPriceUpdate{
		gasPrice(chainsel.HEDERA_MAINNET.Selector, 5e10, 3e10),
		gasPrice(chainsel.HEDERA_TESTNET.Selector, 7e10, 1e10),
		gasPrice(5009297550715157269, 5e10, 3e10),
	}
	out := scaleGasPrice(in)
	require.Len(t, out, len(in))

	require.EqualValues(t, 5, out[0].USDGasPrice.ExecutionFee.ToInt().Int64())
	require.EqualValues(t, 3, out[0].USDGasPrice.DAFee.ToInt().Int64())
	require.EqualValues(t, 7, out[1].USDGasPrice.ExecutionFee.ToInt().Int64())
	require.EqualValues(t, 1, out[1].USDGasPrice.DAFee.ToInt().Int64())
	require.EqualValues(t, 5e10, out[2].USDGasPrice.ExecutionFee.ToInt().Int64())
	require.EqualValues(t, 3e10, out[2].USDGasPrice.DAFee.ToInt().Int64())
	for i := range in {
		require.Equal(t, in[i].ChainSelector, out[i].ChainSelector)
	}
	require.EqualValues(t, 5e10, in[0].USDGasPrice.ExecutionFee.ToInt().Int64(), "input must not change")
}

func TestScaleGasPriceKeepsANilFeeOnHedera(t *testing.T) {
	out := scaleGasPrice([]protocol.GasTokenPriceUpdate{{
		ChainSelector: protocol.ChainSelector(chainsel.HEDERA_MAINNET.Selector),
		USDGasPrice:   protocol.USDGasPrice{ExecutionFee: (*protocol.USDPerGasUnit)(big.NewInt(2e10))},
	}})
	require.EqualValues(t, 2, out[0].USDGasPrice.ExecutionFee.ToInt().Int64())
	require.Nil(t, out[0].USDGasPrice.DAFee)
}

func TestScaleGasPriceWithNoUpdates(t *testing.T) {
	require.Empty(t, scaleGasPrice(nil))
}

func TestScaleWeiBar(t *testing.T) {
	require.Nil(t, scaleWeiBar(nil))

	tests := []struct {
		name  string
		price string
		want  string
	}{
		{name: "one tinybar", price: "10000000000", want: "1"},
		{name: "one hbar worth", price: "1000000000000000000", want: "100000000"},
		{name: "rounds down", price: "19999999999", want: "1"},
		{name: "below one tinybar", price: "9999999999", want: "0"},
		{name: "zero", price: "0", want: "0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := (*protocol.USDPerGasUnit)(mustBig(t, tt.price))
			got := scaleWeiBar(in)
			requireSameInt(t, mustBig(t, tt.want), got.ToInt())
			require.Equal(t, mustBig(t, tt.price), in.ToInt(), "input must not change")
		})
	}
}

func TestPackFeeComponents(t *testing.T) {
	maxPart := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), packedGasPriceBits), big.NewInt(1))
	tests := []struct {
		name          string
		da, execution *big.Int
		want          *big.Int
	}{
		{name: "both set", da: big.NewInt(2), execution: big.NewInt(3), want: new(big.Int).Or(new(big.Int).Lsh(big.NewInt(2), 112), big.NewInt(3))},
		{name: "only execution", da: big.NewInt(0), execution: big.NewInt(3), want: big.NewInt(3)},
		{name: "only DA", da: big.NewInt(2), execution: big.NewInt(0), want: new(big.Int).Lsh(big.NewInt(2), 112)},
		{name: "both at the maximum", da: maxPart, execution: maxPart, want: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 224), big.NewInt(1))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packed := packFeeComponents(protocol.USDGasPrice{
				ExecutionFee: (*protocol.USDPerGasUnit)(tt.execution),
				DAFee:        (*protocol.USDPerGasUnit)(tt.da),
			})
			requireSameInt(t, tt.want, packed)

			unpacked := unpackGasPrice(packed)
			requireSameInt(t, tt.execution, unpacked.ExecutionFee.ToInt())
			requireSameInt(t, tt.da, unpacked.DAFee.ToInt())
		})
	}
}

// requireSameInt compares the values of two big integers. A zero can have different internal forms.
func requireSameInt(t *testing.T, want, got *big.Int) {
	t.Helper()
	require.Zero(t, want.Cmp(got), "want %s, got %s", want, got)
}

type fakeTxm struct {
	txmgr.TxManager
	requests []txmgr.TxRequest
	err      error
}

func (f *fakeTxm) CreateTransaction(_ context.Context, r txmgr.TxRequest) (txmgr.Tx, error) {
	f.requests = append(f.requests, r)
	return txmgr.Tx{}, f.err
}

type fakeKeys struct{ err error }

func (f fakeKeys) GetNextAddress(_ context.Context, addrs ...common.Address) (common.Address, error) {
	if f.err != nil {
		return common.Address{}, f.err
	}
	return addrs[0], nil
}

func newTxmWriter(t *testing.T, client batchClient, txm *fakeTxm, keys fakeKeys, from, fq common.Address) *EVMFeeQuoterWriter {
	t.Helper()
	return NewEVMFeeQuoterWriter(logger.Test(t), client, fq, WithTxm(txm, keys, []common.Address{from}))
}

func TestEVMFeeQuoterWriterSendsUpdatePricesThroughTheTxm(t *testing.T) {
	env := pricereadertest.New(t)
	txm := &fakeTxm{}
	from, fq := common.HexToAddress("0x01"), common.HexToAddress("0xfee")
	writer := newTxmWriter(t, env.Client, txm, fakeKeys{}, from, fq)

	err := writer.UpdatePrices(t.Context(),
		[]protocol.FeeTokenPriceUpdate{
			{Address: env.USDC.Bytes(), Price: (*protocol.USDPerWholeToken)(big.NewInt(15))},
			{Address: env.Link.Bytes(), Price: (*protocol.USDPerWholeToken)(big.NewInt(1e18))},
		},
		[]protocol.GasTokenPriceUpdate{{
			ChainSelector: 5009297550715157269,
			USDGasPrice: protocol.USDGasPrice{
				ExecutionFee: (*protocol.USDPerGasUnit)(big.NewInt(3)),
				DAFee:        (*protocol.USDPerGasUnit)(big.NewInt(2)),
			},
		}},
	)
	require.NoError(t, err)

	require.Len(t, txm.requests, 1)
	req := txm.requests[0]
	require.Equal(t, from, req.FromAddress)
	require.Equal(t, fq, req.ToAddress)
	require.EqualValues(t, updatePricesBaseGas+3*updatePricesGasPerUpdate, req.FeeLimit)

	args, err := feeQuoterABI.Methods["updatePrices"].Inputs.Unpack(req.EncodedPayload[4:])
	require.NoError(t, err)
	got := *abi.ConvertType(args[0], new(fee_quoter.InternalPriceUpdates)).(*fee_quoter.InternalPriceUpdates)
	require.Len(t, got.TokenPriceUpdates, 2)
	require.Equal(t, env.USDC, got.TokenPriceUpdates[0].SourceToken)
	require.Equal(t, big.NewInt(15_000_000_000_000), got.TokenPriceUpdates[0].UsdPerToken)
	require.Equal(t, env.Link, got.TokenPriceUpdates[1].SourceToken)
	require.Equal(t, big.NewInt(1e18), got.TokenPriceUpdates[1].UsdPerToken)
	require.Len(t, got.GasPriceUpdates, 1)
	require.EqualValues(t, 5009297550715157269, got.GasPriceUpdates[0].DestChainSelector)
	unpacked := unpackGasPrice(got.GasPriceUpdates[0].UsdPerUnitGas)
	require.EqualValues(t, 3, unpacked.ExecutionFee.ToInt().Int64())
	require.EqualValues(t, 2, unpacked.DAFee.ToInt().Int64())
}

func TestEVMFeeQuoterWriterSendsNothingForAnEmptyUpdate(t *testing.T) {
	txm := &fakeTxm{}
	writer := newTxmWriter(t, nil, txm, fakeKeys{}, common.HexToAddress("0x01"), common.HexToAddress("0xfee"))
	require.NoError(t, writer.UpdatePrices(t.Context(), nil, nil))
	require.Empty(t, txm.requests)
}

func TestEVMFeeQuoterWriterSendsAGasOnlyUpdateWithoutAClient(t *testing.T) {
	txm := &fakeTxm{}
	writer := newTxmWriter(t, nil, txm, fakeKeys{}, common.HexToAddress("0x01"), common.HexToAddress("0xfee"))
	err := writer.UpdatePrices(t.Context(), nil, []protocol.GasTokenPriceUpdate{{
		ChainSelector: 1,
		USDGasPrice:   protocol.USDGasPrice{ExecutionFee: (*protocol.USDPerGasUnit)(big.NewInt(3))},
	}})
	require.NoError(t, err)
	require.Len(t, txm.requests, 1)
	require.EqualValues(t, updatePricesBaseGas+updatePricesGasPerUpdate, txm.requests[0].FeeLimit)
}

func TestEVMFeeQuoterWriterReturnsTxmAndKeyErrors(t *testing.T) {
	gas := []protocol.GasTokenPriceUpdate{{
		ChainSelector: 1,
		USDGasPrice:   protocol.USDGasPrice{ExecutionFee: (*protocol.USDPerGasUnit)(big.NewInt(3))},
	}}
	from, fq := common.HexToAddress("0x01"), common.HexToAddress("0xfee")

	txm := &fakeTxm{err: errors.New("txm down")}
	err := newTxmWriter(t, nil, txm, fakeKeys{}, from, fq).UpdatePrices(t.Context(), nil, gas)
	require.ErrorContains(t, err, "txm down")

	txm = &fakeTxm{}
	err = newTxmWriter(t, nil, txm, fakeKeys{err: errors.New("no key")}, from, fq).UpdatePrices(t.Context(), nil, gas)
	require.ErrorContains(t, err, "no key")
	require.Empty(t, txm.requests)
}

func TestEVMFeeQuoterWriterDoesNotSendWhenTheDecimalsCannotBeRead(t *testing.T) {
	txm := &fakeTxm{}
	writer := newTxmWriter(t, nil, txm, fakeKeys{}, common.HexToAddress("0x01"), common.HexToAddress("0xfee"))
	err := writer.UpdatePrices(t.Context(),
		[]protocol.FeeTokenPriceUpdate{{Address: common.HexToAddress("0x1").Bytes(), Price: (*protocol.USDPerWholeToken)(big.NewInt(1))}}, nil)
	require.Error(t, err)
	require.Empty(t, txm.requests)
}

func TestPackFeeComponentsTreatsANilFeeAsZero(t *testing.T) {
	require.EqualValues(t, 3, packFeeComponents(protocol.USDGasPrice{ExecutionFee: (*protocol.USDPerGasUnit)(big.NewInt(3))}).Int64())
	require.Zero(t, packFeeComponents(protocol.USDGasPrice{}).Sign())
	onlyDA := packFeeComponents(protocol.USDGasPrice{DAFee: (*protocol.USDPerGasUnit)(big.NewInt(2))})
	requireSameInt(t, new(big.Int).Lsh(big.NewInt(2), 112), onlyDA)
}
