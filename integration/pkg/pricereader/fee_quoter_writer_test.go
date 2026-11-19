package pricereader

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/fee_quoter"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/pricereader/pricereadertest"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-evm/pkg/assets"
	"github.com/smartcontractkit/chainlink-evm/pkg/txmgr"
	"github.com/smartcontractkit/chainlink-framework/chains/fees"
)

func TestEVMFeeQuoterWriterLogsTheUpdates(t *testing.T) {
	lggr, logs := logger.TestObserved(t, zapcore.InfoLevel)
	env := pricereadertest.New(t)
	fq := common.HexToAddress("0xfee")
	writer := newTestWriter(t, lggr, env.Client, fq)

	_, err := writer.UpdatePrices(context.Background(),
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

func TestEVMFeeQuoterWriterErrorsOnEmptyUpdate(t *testing.T) {
	writer := newTestWriter(t, logger.Test(t), nil, common.Address{})
	txID, err := writer.UpdatePrices(context.Background(), nil, nil)
	require.ErrorContains(t, err, "no token and gas price updates to be made")
	require.Empty(t, txID)
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
	writer := newTestWriter(t, logger.Test(t), env.Client, common.Address{})

	got, err := writer.tokenDecimals(context.Background(), []common.Address{env.USDC, env.Link})
	require.NoError(t, err)
	require.Equal(t, map[common.Address]uint8{env.USDC: 6, env.Link: 18}, got)
}

func TestTokenDecimalsReadsTokensInOneBatchWithoutDuplicates(t *testing.T) {
	env := pricereadertest.New(t)
	client := &countingClient{batchClient: env.Client}
	writer := newTestWriter(t, logger.Test(t), client, common.Address{})

	got, err := writer.tokenDecimals(context.Background(), []common.Address{env.USDC, env.Link, env.USDC})
	require.NoError(t, err)
	require.Equal(t, map[common.Address]uint8{env.USDC: 6, env.Link: 18}, got)
	require.EqualValues(t, 1, client.batches.Load())
}

func TestTokenDecimalsCachesDecimals(t *testing.T) {
	env := pricereadertest.New(t)
	client := &countingClient{batchClient: env.Client}
	writer := newTestWriter(t, logger.Test(t), client, common.Address{})

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

func TestTokenDecimalsUsesTheSharedCache(t *testing.T) {
	env := pricereadertest.New(t)
	client := &countingClient{batchClient: env.Client}
	cache := NewTokenMetadataCache()
	cache.setDecimals(env.USDC, 6)
	writer := newTestWriter(t, logger.Test(t), client, common.Address{}, WithTokenCache(cache))

	got, err := writer.tokenDecimals(context.Background(), []common.Address{env.USDC})
	require.NoError(t, err)
	require.Equal(t, map[common.Address]uint8{env.USDC: 6}, got)
	require.Zero(t, client.batches.Load(), "a cached token must not be read")

	_, err = writer.tokenDecimals(context.Background(), []common.Address{env.Link})
	require.NoError(t, err)
	link, ok := cache.getDecimals(env.Link)
	require.True(t, ok, "the writer must store what it reads in the shared cache")
	require.EqualValues(t, 18, link)
}

func TestReaderFillsTheSymbolOfATokenTheWriterCachedDecimalsFor(t *testing.T) {
	env := pricereadertest.New(t)
	cache := NewTokenMetadataCache()
	writer := newTestWriter(t, logger.Test(t), env.Client, common.Address{}, WithTokenCache(cache))
	reader, err := NewEVMFeeQuoterReader(env.FeeQuoter, env.Client, nil, WithReaderTokenCache(cache))
	require.NoError(t, err)

	// The writer caches the decimals of USDC only, so USDC has decimals without a symbol.
	_, err = writer.tokenDecimals(context.Background(), []common.Address{env.USDC})
	require.NoError(t, err)
	_, hasSymbol := cache.getSymbol(env.USDC)
	require.False(t, hasSymbol)

	env.Client.ResetBatches()
	state, err := reader.GetFQState(context.Background())
	require.NoError(t, err)

	require.ElementsMatch(t, []protocol.FeeToken{
		{Address: env.Link.Bytes(), Symbol: "LINK"},
		{Address: env.USDC.Bytes(), Symbol: "USDC"},
	}, state.FeeTokens)
	usdc := state.FeeTokenPrices[protocol.UnknownAddress(env.USDC.Bytes()).String()]
	require.Equal(t, big.NewInt(1e18), usdc.Price.ToInt(), "the cached decimals must be used")

	// The reader reads both symbols but only the decimals of LINK.
	selector := func(sig string) string { return hex.EncodeToString(crypto.Keccak256([]byte(sig))[:4]) }
	var decimalsCalls, symbolCalls int
	for _, batch := range env.Client.Batches() {
		for _, call := range batch {
			switch call.Selector {
			case selector("decimals()"):
				decimalsCalls++
			case selector("symbol()"):
				symbolCalls++
			}
		}
	}
	require.Equal(t, 1, decimalsCalls)
	require.Equal(t, 2, symbolCalls)

	symbol, ok := cache.getSymbol(env.USDC)
	require.True(t, ok)
	require.Equal(t, "USDC", symbol)
}

func TestTokenDecimalsWithoutTokensDoesNotNeedAClient(t *testing.T) {
	writer := newTestWriter(t, logger.Test(t), nil, common.Address{})
	got, err := writer.tokenDecimals(context.Background(), nil)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestTokenDecimalsWithoutAClientFails(t *testing.T) {
	writer := newTestWriter(t, logger.Test(t), nil, common.Address{})
	_, err := writer.tokenDecimals(context.Background(), []common.Address{common.HexToAddress("0x1")})
	require.ErrorContains(t, err, "no client")
}

func TestTokenDecimalsOmitsAnAddressThatIsNotAToken(t *testing.T) {
	lggr, logs := logger.TestObserved(t, zapcore.WarnLevel)
	env := pricereadertest.New(t)
	writer := newTestWriter(t, lggr, env.Client, common.Address{})
	notToken := common.HexToAddress("0xdead")

	got, err := writer.tokenDecimals(context.Background(), []common.Address{notToken, env.USDC})
	require.NoError(t, err)
	require.Equal(t, map[common.Address]uint8{env.USDC: 6}, got)
	_, cached := writer.tokens.getDecimals(notToken)
	require.False(t, cached, "a failed read must not be cached")
	require.Len(t, logs.FilterMessage("Failed to read token decimals").All(), 1)
}

// failingClient fails every RPC batch.
type failingClient struct{ batchClient }

func (failingClient) BatchCallContext(context.Context, []rpc.BatchElem) error {
	return errors.New("rpc down")
}

func TestTokenDecimalsLogsInsteadOfFailingWhenTheBatchFails(t *testing.T) {
	lggr, logs := logger.TestObserved(t, zapcore.WarnLevel)
	env := pricereadertest.New(t)
	writer := newTestWriter(t, lggr, failingClient{env.Client}, common.Address{})

	got, err := writer.tokenDecimals(context.Background(), []common.Address{env.USDC})
	require.NoError(t, err)
	require.Empty(t, got)
	require.Len(t, logs.FilterMessage("Failed to read token decimals").All(), 1)
}

func TestWithDecimalsDropsTokensWithoutDecimals(t *testing.T) {
	known, unknown := common.HexToAddress("0x1"), common.HexToAddress("0x2")
	writer := newTestWriter(t, logger.Test(t), nil, common.Address{})
	in := []protocol.FeeTokenPriceUpdate{{Address: known.Bytes()}, {Address: unknown.Bytes()}}
	got := writer.withDecimals(in, map[common.Address]uint8{known: 18})
	require.Equal(t, in[:1], got)
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
	require.Equal(t, mustBig(t, "1000000000000000000"), (*big.Int)(in[0].Price), "input must not change")
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

	status    commontypes.TransactionStatus
	statusErr error
	// statusFor records the transaction IDs GetTransactionStatus was asked about.
	statusFor []string
}

func (f *fakeTxm) GetTransactionStatus(_ context.Context, id string) (commontypes.TransactionStatus, error) {
	f.statusFor = append(f.statusFor, id)
	return f.status, f.statusErr
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

// testNativeDecimals is the native token decimals of the writers the tests build, as on most chains.
const testNativeDecimals = 18

func newTestWriter(t *testing.T, lggr logger.Logger, client batchClient, address common.Address, opts ...WriterOption) *EVMFeeQuoterWriter {
	t.Helper()
	writer, err := NewEVMFeeQuoterWriter(lggr, client, address, testNativeDecimals, opts...)
	require.NoError(t, err)
	return writer
}

func newTxmWriter(t *testing.T, client batchClient, txm *fakeTxm, keys fakeKeys, from, fq common.Address) *EVMFeeQuoterWriter {
	t.Helper()
	return newTestWriter(t, logger.Test(t), client, fq, WithTxm(txm, keys, []common.Address{from}))
}

func TestEVMFeeQuoterWriterSendsUpdatePricesThroughTheTxm(t *testing.T) {
	env := pricereadertest.New(t)
	txm := &fakeTxm{}
	from, fq := common.HexToAddress("0x01"), common.HexToAddress("0xfee")
	writer := newTxmWriter(t, env.Client, txm, fakeKeys{}, from, fq)

	txID, err := writer.UpdatePrices(t.Context(),
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
	require.NotEmpty(t, txID)
	require.NotNil(t, req.IdempotencyKey)
	require.Equal(t, txID, *req.IdempotencyKey, "the returned ID must be the key the tx can be looked up by")
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

func TestEVMFeeQuoterWriterErrorsForAnEmptyUpdate(t *testing.T) {
	txm := &fakeTxm{}
	writer := newTxmWriter(t, nil, txm, fakeKeys{}, common.HexToAddress("0x01"), common.HexToAddress("0xfee"))
	_, err := writer.UpdatePrices(t.Context(), nil, nil)
	require.ErrorContains(t, err, "no token and gas price updates to be made")
	require.Empty(t, txm.requests)
}

func TestEVMFeeQuoterWriterSendsAGasOnlyUpdateWithoutAClient(t *testing.T) {
	txm := &fakeTxm{}
	writer := newTxmWriter(t, nil, txm, fakeKeys{}, common.HexToAddress("0x01"), common.HexToAddress("0xfee"))
	_, err := writer.UpdatePrices(t.Context(), nil, []protocol.GasTokenPriceUpdate{{
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
	_, err := newTxmWriter(t, nil, txm, fakeKeys{}, from, fq).UpdatePrices(t.Context(), nil, gas)
	require.ErrorContains(t, err, "txm down")

	txm = &fakeTxm{}
	_, err = newTxmWriter(t, nil, txm, fakeKeys{err: errors.New("no key")}, from, fq).UpdatePrices(t.Context(), nil, gas)
	require.ErrorContains(t, err, "no key")
	require.Empty(t, txm.requests)
}

func TestEVMFeeQuoterWriterSkipsTokensWithoutDecimals(t *testing.T) {
	lggr, logs := logger.TestObserved(t, zapcore.WarnLevel)
	env := pricereadertest.New(t)
	txm := &fakeTxm{}
	notToken := common.HexToAddress("0xdead")
	writer := newTestWriter(t, lggr, env.Client, common.HexToAddress("0xfee"),
		WithTxm(txm, fakeKeys{}, []common.Address{common.HexToAddress("0x01")}))

	_, err := writer.UpdatePrices(t.Context(),
		[]protocol.FeeTokenPriceUpdate{
			{Address: notToken.Bytes(), Price: (*protocol.USDPerWholeToken)(big.NewInt(1))},
			{Address: env.USDC.Bytes(), Price: (*protocol.USDPerWholeToken)(big.NewInt(15))},
		},
		[]protocol.GasTokenPriceUpdate{{
			ChainSelector: 1,
			USDGasPrice:   protocol.USDGasPrice{ExecutionFee: (*protocol.USDPerGasUnit)(big.NewInt(3))},
		}},
	)
	require.NoError(t, err)
	require.Len(t, logs.FilterMessage("Skipping token price update, token decimals unavailable").All(), 1)

	require.Len(t, txm.requests, 1)
	args, err := feeQuoterABI.Methods["updatePrices"].Inputs.Unpack(txm.requests[0].EncodedPayload[4:])
	require.NoError(t, err)
	got := *abi.ConvertType(args[0], new(fee_quoter.InternalPriceUpdates)).(*fee_quoter.InternalPriceUpdates)
	require.Len(t, got.TokenPriceUpdates, 1)
	require.Equal(t, env.USDC, got.TokenPriceUpdates[0].SourceToken)
	require.Len(t, got.GasPriceUpdates, 1)
	require.EqualValues(t, updatePricesBaseGas+2*updatePricesGasPerUpdate, txm.requests[0].FeeLimit)
}

func TestEVMFeeQuoterWriterSendsNothingWhenNoUpdateHasDecimals(t *testing.T) {
	env := pricereadertest.New(t)
	txm := &fakeTxm{}
	writer := newTxmWriter(t, env.Client, txm, fakeKeys{}, common.HexToAddress("0x01"), common.HexToAddress("0xfee"))
	_, err := writer.UpdatePrices(t.Context(),
		[]protocol.FeeTokenPriceUpdate{{Address: common.HexToAddress("0xdead").Bytes(), Price: (*protocol.USDPerWholeToken)(big.NewInt(1))}}, nil)
	require.ErrorContains(t, err, "no gas price updates, and unable to get all token decimals")
	require.Empty(t, txm.requests)
}

func TestEVMFeeQuoterWriterFailsWithoutAClientToReadDecimals(t *testing.T) {
	txm := &fakeTxm{}
	writer := newTxmWriter(t, nil, txm, fakeKeys{}, common.HexToAddress("0x01"), common.HexToAddress("0xfee"))
	_, err := writer.UpdatePrices(t.Context(),
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

func gasOnlyUpdate() []protocol.GasTokenPriceUpdate {
	return []protocol.GasTokenPriceUpdate{{
		ChainSelector: 1,
		USDGasPrice:   protocol.USDGasPrice{ExecutionFee: (*protocol.USDPerGasUnit)(big.NewInt(3))},
	}}
}

func TestEVMFeeQuoterWriterReturnsErrorWhenNoValuesToUpdate(t *testing.T) {
	txm := &fakeTxm{}
	writer := newTxmWriter(t, nil, txm, fakeKeys{}, common.HexToAddress("0x01"), common.HexToAddress("0xfee"))
	txID, err := writer.UpdatePrices(t.Context(), nil, nil)
	require.ErrorContains(t, err, "no token and gas price updates to be made")
	require.Empty(t, txID)
	require.Empty(t, txm.requests)

	logOnly := newTestWriter(t, logger.Test(t), nil, common.HexToAddress("0xfee"))
	txID, err = logOnly.UpdatePrices(t.Context(), nil, gasOnlyUpdate())
	require.NoError(t, err)
	require.Empty(t, txID, "a writer without a TXM sends no transaction, so it has no ID")
}

func TestEVMFeeQuoterWriterReturnsNoIDWhenTheTxmFails(t *testing.T) {
	txm := &fakeTxm{err: errors.New("txm down")}
	writer := newTxmWriter(t, nil, txm, fakeKeys{}, common.HexToAddress("0x01"), common.HexToAddress("0xfee"))
	txID, err := writer.UpdatePrices(t.Context(), nil, gasOnlyUpdate())
	require.Error(t, err)
	require.Empty(t, txID)
}

func TestEVMFeeQuoterWriterUsesAFreshIDPerTransaction(t *testing.T) {
	txm := &fakeTxm{}
	writer := newTxmWriter(t, nil, txm, fakeKeys{}, common.HexToAddress("0x01"), common.HexToAddress("0xfee"))

	first, err := writer.UpdatePrices(t.Context(), nil, gasOnlyUpdate())
	require.NoError(t, err)
	second, err := writer.UpdatePrices(t.Context(), nil, gasOnlyUpdate())
	require.NoError(t, err)

	require.NotEmpty(t, first)
	require.NotEqual(t, first, second, "a reused key would make the TXM drop the second update as a duplicate")
	require.Len(t, txm.requests, 2)
	require.Equal(t, first, *txm.requests[0].IdempotencyKey)
	require.Equal(t, second, *txm.requests[1].IdempotencyKey)
}

func TestEVMFeeQuoterWriterGetTransactionStatusAsksTheTxmByID(t *testing.T) {
	txm := &fakeTxm{status: commontypes.Finalized}
	writer := newTxmWriter(t, nil, txm, fakeKeys{}, common.HexToAddress("0x01"), common.HexToAddress("0xfee"))

	txID, err := writer.UpdatePrices(t.Context(), nil, gasOnlyUpdate())
	require.NoError(t, err)

	status, err := writer.GetTransactionStatus(t.Context(), txID)
	require.NoError(t, err)
	require.Equal(t, commontypes.Finalized, status)
	require.Equal(t, []string{txID}, txm.statusFor)
}

func TestEVMFeeQuoterWriterGetTransactionStatusReturnsTxmErrors(t *testing.T) {
	txm := &fakeTxm{status: commontypes.Failed, statusErr: errors.New("lookup failed")}
	writer := newTxmWriter(t, nil, txm, fakeKeys{}, common.HexToAddress("0x01"), common.HexToAddress("0xfee"))

	_, err := writer.GetTransactionStatus(t.Context(), "id")
	require.ErrorContains(t, err, "lookup failed")
}

func TestEVMFeeQuoterWriterGetTransactionStatusWithoutATxmFails(t *testing.T) {
	writer := newTestWriter(t, logger.Test(t), nil, common.HexToAddress("0xfee"))

	status, err := writer.GetTransactionStatus(t.Context(), "id")
	require.Error(t, err)
	require.Equal(t, commontypes.Unknown, status)
}

type fakeEstimator struct {
	cost        *big.Int
	err         error
	calls       int
	feeLimit    uint64
	maxFeePrice *assets.Wei
	from        common.Address
	to          common.Address
	calldata    []byte
}

// GetMaxCost fails on a nil maxFeePrice, as the production estimators do: they compare prices against it
// without a nil check and panic once fee data is available.
func (f *fakeEstimator) GetMaxCost(_ context.Context, _ assets.Eth, calldata []byte, feeLimit uint64, maxFeePrice *assets.Wei, from, to *common.Address, _ ...fees.Opt) (*big.Int, error) {
	f.calls++
	if maxFeePrice == nil {
		return nil, errors.New("fakeEstimator: nil maxFeePrice")
	}
	if f.err != nil {
		return nil, f.err
	}
	cost := new(big.Int).Mul(f.cost, big.NewInt(int64(feeLimit)))
	f.calldata, f.feeLimit, f.maxFeePrice, f.from, f.to = calldata, feeLimit, maxFeePrice, *from, *to
	return cost, f.err
}

// testPriceMax gives each sender a distinct, non-nil cap, so a test can tell which sender's cap was passed.
func testPriceMax(sender common.Address) *assets.Wei {
	return assets.NewWeiI(1_000_000)
}

func TestEVMFeeQuoterWriterEstimatesThePriceUpdateCostWithoutSending(t *testing.T) {
	txm := &fakeTxm{}
	gasPrice := big.NewInt(10)
	est := &fakeEstimator{cost: gasPrice}
	from, fq := common.HexToAddress("0x01"), common.HexToAddress("0xfee")
	writer := newTestWriter(t, logger.Test(t), nil, fq, WithTxm(txm, fakeKeys{}, []common.Address{from}), WithFeeEstimator(est, testPriceMax))
	gasLimit := uint64(updatePricesBaseGas + updatePricesGasPerUpdate)

	cost, err := writer.EstimateUpdateCost(t.Context(), nil, gasOnlyUpdate())

	require.NoError(t, err)
	// 18 native decimals by default, so the wei cost is multiplied by 1e18 to reach 1e36 precision.
	wei := new(big.Int).Mul(gasPrice, big.NewInt(int64(gasLimit)))
	requireSameInt(t, new(big.Int).Mul(wei, pow10(18)), cost)
	require.Empty(t, txm.requests, "an estimate must not send a transaction")
	require.Equal(t, gasLimit, est.feeLimit)
	require.NotNil(t, est.maxFeePrice, "the estimator needs the sender's fee cap, not nil")
	require.Zero(t, testPriceMax(from).ToInt().Cmp(est.maxFeePrice.ToInt()))
	require.Equal(t, from, est.from)
	require.Equal(t, fq, est.to)
	require.NotEmpty(t, est.calldata)
}

func TestEVMFeeQuoterWriterEstimatesTheSameCalldataItSends(t *testing.T) {
	txm := &fakeTxm{}
	est := &fakeEstimator{cost: big.NewInt(1)}
	from, fq := common.HexToAddress("0x01"), common.HexToAddress("0xfee")
	writer := newTestWriter(t, logger.Test(t), nil, fq, WithTxm(txm, fakeKeys{}, []common.Address{from}), WithFeeEstimator(est, testPriceMax))

	_, err := writer.EstimateUpdateCost(t.Context(), nil, gasOnlyUpdate())
	require.NoError(t, err)
	estimated := est.calldata
	_, err = writer.UpdatePrices(t.Context(), nil, gasOnlyUpdate())
	require.NoError(t, err)

	require.Len(t, txm.requests, 1)
	require.Equal(t, txm.requests[0].EncodedPayload, estimated)
	require.Equal(t, txm.requests[0].FeeLimit, est.feeLimit)
}

func TestEVMFeeQuoterWriterEstimateErrorsForAnEmptyUpdate(t *testing.T) {
	est := &fakeEstimator{cost: big.NewInt(1)}
	writer := newTestWriter(t, logger.Test(t), nil, common.HexToAddress("0xfee"),
		WithTxm(&fakeTxm{}, fakeKeys{}, []common.Address{common.HexToAddress("0x01")}), WithFeeEstimator(est, testPriceMax))

	_, err := writer.EstimateUpdateCost(t.Context(), nil, nil)

	require.ErrorContains(t, err, "no token and gas price updates to be made")
}

func TestEVMFeeQuoterWriterEstimateReturnsTheEstimatorError(t *testing.T) {
	est := &fakeEstimator{err: errors.New("rpc down")}
	writer := newTestWriter(t, logger.Test(t), nil, common.HexToAddress("0xfee"),
		WithTxm(&fakeTxm{}, fakeKeys{}, []common.Address{common.HexToAddress("0x01")}), WithFeeEstimator(est, testPriceMax))

	cost, err := writer.EstimateUpdateCost(t.Context(), nil, gasOnlyUpdate())

	require.ErrorContains(t, err, "rpc down")
	require.Nil(t, cost)
}

func TestEVMFeeQuoterWriterEstimateFailsWithoutAnEstimatorOrASender(t *testing.T) {
	fq := common.HexToAddress("0xfee")
	noEstimator := newTestWriter(t, logger.Test(t), nil, fq, WithTxm(&fakeTxm{}, fakeKeys{}, []common.Address{common.HexToAddress("0x01")}))
	_, err := noEstimator.EstimateUpdateCost(t.Context(), nil, gasOnlyUpdate())
	require.ErrorContains(t, err, "no fee estimator")

	noSender := newTestWriter(t, logger.Test(t), nil, fq, WithFeeEstimator(&fakeEstimator{cost: big.NewInt(1)}, testPriceMax))
	_, err = noSender.EstimateUpdateCost(t.Context(), nil, gasOnlyUpdate())
	require.ErrorContains(t, err, "no sender address")
}

func TestEVMFeeQuoterWriterSendStillSucceedsWhenTheEstimateFails(t *testing.T) {
	txm := &fakeTxm{}
	est := &fakeEstimator{err: errors.New("rpc down")}
	writer := newTestWriter(t, logger.Test(t), nil, common.HexToAddress("0xfee"),
		WithTxm(txm, fakeKeys{}, []common.Address{common.HexToAddress("0x01")}), WithFeeEstimator(est, testPriceMax))

	txID, err := writer.UpdatePrices(t.Context(), nil, gasOnlyUpdate())

	require.NoError(t, err)
	require.NotEmpty(t, txID)
	require.Len(t, txm.requests, 1)
}

func TestEVMFeeQuoterWriterEstimateScalesTheCostByTheNativeDecimals(t *testing.T) {
	from, fq := common.HexToAddress("0x01"), common.HexToAddress("0xfee")
	gasLimit := big.NewInt(updatePricesBaseGas + updatePricesGasPerUpdate)
	for _, decimals := range []uint8{0, 8, 18, 36} {
		est := &fakeEstimator{cost: big.NewInt(7)}
		writer, err := NewEVMFeeQuoterWriter(logger.Test(t), nil, fq, decimals,
			WithTxm(&fakeTxm{}, fakeKeys{}, []common.Address{from}), WithFeeEstimator(est, testPriceMax))
		require.NoError(t, err, "decimals %d", decimals)

		cost, err := writer.EstimateUpdateCost(t.Context(), nil, gasOnlyUpdate())

		require.NoError(t, err, "decimals %d", decimals)
		smallest := new(big.Int).Mul(big.NewInt(7), gasLimit)
		requireSameInt(t, new(big.Int).Mul(smallest, pow10(uint(36-decimals))), cost)
	}
}

func TestNewEVMFeeQuoterWriterRejectsTooManyNativeDecimals(t *testing.T) {
	writer, err := NewEVMFeeQuoterWriter(logger.Test(t), nil, common.HexToAddress("0xfee"), MaxNativeTokenDecimals+1)

	require.ErrorContains(t, err, "native token decimals")
	require.Nil(t, writer)

	writer, err = NewEVMFeeQuoterWriter(logger.Test(t), nil, common.HexToAddress("0xfee"), MaxNativeTokenDecimals)
	require.NoError(t, err)
	require.NotNil(t, writer)
}

func TestEVMFeeQuoterWriterEstimatePassesTheSendersFeeCap(t *testing.T) {
	from, fq := common.HexToAddress("0x01"), common.HexToAddress("0xfee")
	est := &fakeEstimator{cost: big.NewInt(1)}
	writer := newTestWriter(t, logger.Test(t), nil, fq,
		WithTxm(&fakeTxm{}, fakeKeys{}, []common.Address{from}), WithFeeEstimator(est, testPriceMax))

	_, err := writer.EstimateUpdateCost(t.Context(), nil, gasOnlyUpdate())

	require.NoError(t, err)
	require.Equal(t, from, est.from)
	require.Zero(t, testPriceMax(from).ToInt().Cmp(est.maxFeePrice.ToInt()), "cap of the sender")
}

func TestEVMFeeQuoterWriterEstimateFailsWithoutAFeeCapAndNeverPassesNil(t *testing.T) {
	from, fq := common.HexToAddress("0x01"), common.HexToAddress("0xfee")
	noCapFunc := &fakeEstimator{cost: big.NewInt(1)}
	writer := newTestWriter(t, logger.Test(t), nil, fq,
		WithTxm(&fakeTxm{}, fakeKeys{}, []common.Address{from}), WithFeeEstimator(noCapFunc, nil))

	cost, err := writer.EstimateUpdateCost(t.Context(), nil, gasOnlyUpdate())

	require.ErrorContains(t, err, "no max fee price")
	require.Nil(t, cost)
	require.Zero(t, noCapFunc.calls, "a nil cap must be rejected before the estimator can panic on it")

	nilCap := &fakeEstimator{cost: big.NewInt(1)}
	writer = newTestWriter(t, logger.Test(t), nil, fq,
		WithTxm(&fakeTxm{}, fakeKeys{}, []common.Address{from}),
		WithFeeEstimator(nilCap, func(common.Address) *assets.Wei { return nil }))

	cost, err = writer.EstimateUpdateCost(t.Context(), nil, gasOnlyUpdate())

	require.ErrorContains(t, err, "no max fee price")
	require.Nil(t, cost)
	require.Zero(t, nilCap.calls)
}
