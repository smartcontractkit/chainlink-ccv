package pricereader_test

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/pricereader"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/pricereader/pricereadertest"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func selectorOf(signature string) string {
	return hex.EncodeToString(crypto.Keccak256([]byte(signature))[:4])
}

func newFeeQuoterReader(t *testing.T, env *pricereadertest.Env, self ...common.Address) *pricereader.EVMFeeQuoterReader {
	t.Helper()
	fq, err := pricereader.NewEVMFeeQuoterReader(env.FeeQuoter, env.Client, self)
	require.NoError(t, err)
	return fq
}

func TestGetFQState(t *testing.T) {
	env := pricereadertest.New(t)
	state, err := newFeeQuoterReader(t, env, env.Owner).GetFQState(context.Background())
	require.NoError(t, err)

	require.ElementsMatch(t, []protocol.FeeToken{
		{Address: env.Link.Bytes(), Symbol: "LINK"},
		{Address: env.USDC.Bytes(), Symbol: "USDC"},
	}, state.FeeTokens)

	oneE18 := big.NewInt(1e18)
	linkPrice := state.FeeTokenPrices[protocol.UnknownAddress(env.Link.Bytes()).String()]
	require.Equal(t, new(big.Int).Mul(big.NewInt(15), oneE18), linkPrice.Price.ToInt())
	require.False(t, linkPrice.UpdatedAt.IsZero())
	usdcPrice := state.FeeTokenPrices[protocol.UnknownAddress(env.USDC.Bytes()).String()]
	require.Equal(t, oneE18, usdcPrice.Price.ToInt())

	require.ElementsMatch(t, []protocol.ChainSelector{
		protocol.ChainSelector(pricereadertest.DestSelectors[0]),
		protocol.ChainSelector(pricereadertest.DestSelectors[1]),
	}, state.DestinationChains)
	// Only the first destination has a gas price.
	require.Len(t, state.GasPrices, 1)
	gas := state.GasPrices[protocol.ChainSelector(pricereadertest.DestSelectors[0])]
	require.Equal(t, pricereadertest.GasExecutionUSD, gas.USDGasPrice.ExecutionFee.ToInt())
	require.Equal(t, pricereadertest.GasDAUSD, gas.USDGasPrice.DAFee.ToInt())
	require.False(t, gas.UpdatedAt.IsZero())

	require.True(t, state.ServiceIsAuthorized)
}

func TestGetFQStateServiceIsAuthorized(t *testing.T) {
	env := pricereadertest.New(t)
	other := common.HexToAddress("0x1111")

	tests := []struct {
		name string
		self []common.Address
		want bool
	}{
		{name: "owner", self: []common.Address{env.Owner}, want: true},
		{name: "one of many keys", self: []common.Address{other, env.Owner}, want: true},
		{name: "other address", self: []common.Address{other}, want: false},
		{name: "no address", self: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, err := newFeeQuoterReader(t, env, tt.self...).GetFQState(context.Background())
			require.NoError(t, err)
			require.Equal(t, tt.want, state.ServiceIsAuthorized)
		})
	}

	t.Run("address set later", func(t *testing.T) {
		fq := newFeeQuoterReader(t, env)
		fq.SetServiceAddresses([]common.Address{env.Owner})
		state, err := fq.GetFQState(context.Background())
		require.NoError(t, err)
		require.True(t, state.ServiceIsAuthorized)
	})
}

func TestGetFQStatePinsAllReadsToOneBlockAndCachesTokenMetadata(t *testing.T) {
	env := pricereadertest.New(t)
	fq := newFeeQuoterReader(t, env, env.Owner)
	decimals, symbol := selectorOf("decimals()"), selectorOf("symbol()")

	_, err := fq.GetFQState(context.Background())
	require.NoError(t, err)
	batches := env.Client.Batches()
	// The structure, then the prices.
	require.Len(t, batches, 2)
	require.Len(t, batches[0], 3)
	// Token prices, 2 gas prices, and decimals and symbol of 2 tokens.
	require.Len(t, batches[1], 1+len(pricereadertest.DestSelectors)+4)
	pinned := batches[0][0].Block
	require.NotEqual(t, "latest", pinned)
	var metadataCalls int
	for _, call := range append(batches[0], batches[1]...) {
		require.Equal(t, pinned, call.Block)
		if call.Selector == decimals || call.Selector == symbol {
			metadataCalls++
		}
	}
	require.Equal(t, 4, metadataCalls)

	env.Client.ResetBatches()
	_, err = fq.GetFQState(context.Background())
	require.NoError(t, err)
	batches = env.Client.Batches()
	require.Len(t, batches, 2)
	require.Len(t, batches[1], 1+len(pricereadertest.DestSelectors))
	for _, call := range batches[1] {
		require.NotEqual(t, decimals, call.Selector)
		require.NotEqual(t, symbol, call.Selector)
	}
}

// A fee token added after the block number is read must not appear in the state of that block.
// If the structure read the latest block, the prices batch would read the new token at the old block.
func TestGetFQStateIsConsistentWhenTheHeadMovesDuringTheRead(t *testing.T) {
	env := pricereadertest.New(t)
	fq := newFeeQuoterReader(t, env, env.Owner)
	var added common.Address
	env.Client.BeforeBatch(func(index int) {
		if index == 0 { // the structure batch
			added = env.AddFeeToken(t, "NEW", 18, big.NewInt(2e18))
		}
	})

	state, err := fq.GetFQState(context.Background())
	require.NoError(t, err)
	require.Len(t, state.FeeTokens, 2, "the token added after the pinned block is not in the state")
	require.NotContains(t, state.FeeTokenPrices, protocol.UnknownAddress(added.Bytes()).String())

	env.Client.BeforeBatch(nil)
	state, err = fq.GetFQState(context.Background())
	require.NoError(t, err)
	require.Len(t, state.FeeTokens, 3)
	require.Contains(t, state.FeeTokenPrices, protocol.UnknownAddress(added.Bytes()).String())
}

func TestGetFQStateReturnsErrorWhenNoContractIsDeployed(t *testing.T) {
	env := pricereadertest.New(t)
	fq, err := pricereader.NewEVMFeeQuoterReader(common.HexToAddress("0xdead"), env.Client, nil)
	require.NoError(t, err)

	_, err = fq.GetFQState(context.Background())
	require.ErrorIs(t, err, bind.ErrNoCode)
}

func TestNewEVMFeeQuoterReaderRejectsNilClient(t *testing.T) {
	_, err := pricereader.NewEVMFeeQuoterReader(common.Address{}, nil, nil)
	require.ErrorContains(t, err, "batch client is nil")
}
