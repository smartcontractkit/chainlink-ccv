// Package pricereadertest has a simulated EVM chain with a deployed Fee Quoter for tests.
package pricereadertest

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/fee_quoter"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_2/factory_burn_mint_erc20"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
)

const chainID = 1337

var (
	// DestSelectors are the destination chains that the Fee Quoter has configured.
	DestSelectors = []uint64{5009297550715157269, 4949039107694359620}

	// LinkPrice and USDCPrice are the on-chain token prices (USD per 1e18 smallest units, 1e18 precision).
	LinkPrice = mustBig("15000000000000000000")            // $15 for a token with 18 decimals
	USDCPrice = mustBig("1000000000000000000000000000000") // $1 for a token with 6 decimals

	// GasExecutionUSD and GasDAUSD are the execution and DA parts of the packed gas price of DestSelectors[0].
	GasExecutionUSD = big.NewInt(50_000_000_000)
	GasDAUSD        = big.NewInt(7_000_000_000)
)

func mustBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid number " + s)
	}
	return v
}

// PackGasPrice packs a DA price and an execution price into one on-chain gas price.
func PackGasPrice(da, execution *big.Int) *big.Int {
	return new(big.Int).Or(new(big.Int).Lsh(da, 112), execution)
}

// Call is one element of an RPC batch.
type Call struct {
	Method string
	// Selector is the hex function selector of an eth_call, or empty.
	Selector string
	// Block is the block argument of an eth_call, or empty.
	Block string
}

// Client is a simulated chain client that supports the batch calls of the Fee Quoter reader.
// It records all batches.
type Client struct {
	*client.SimulatedBackendClient
	backend *simulated.Backend

	mu          sync.Mutex
	batches     [][]Call
	beforeBatch func(index int)
}

// BeforeBatch sets a function that runs before each batch, with the index of the batch.
func (c *Client) BeforeBatch(fn func(index int)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beforeBatch = fn
}

// Batches returns a copy of the recorded batches.
func (c *Client) Batches() [][]Call {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]Call, len(c.batches))
	copy(out, c.batches)
	return out
}

// ResetBatches removes the recorded batches.
func (c *Client) ResetBatches() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batches = nil
}

// BatchCallContext supports eth_call. An eth_call reads at its block, like a real RPC.
func (c *Client) BatchCallContext(ctx context.Context, batch []rpc.BatchElem) error {
	c.mu.Lock()
	index, beforeBatch := len(c.batches), c.beforeBatch
	c.mu.Unlock()
	if beforeBatch != nil {
		beforeBatch(index)
	}
	recorded := make([]Call, 0, len(batch))
	for i := range batch {
		call := Call{Method: batch[i].Method}
		switch batch[i].Method {
		case "eth_call":
			msg, block, err := parseCall(batch[i].Args)
			if err != nil {
				return err
			}
			if len(msg.Data) >= 4 {
				call.Selector = hex.EncodeToString(msg.Data[:4])
			}
			call.Block = "latest"
			if block != nil {
				call.Block = hexutil.EncodeBig(block)
			}
			result, ok := batch[i].Result.(*hexutil.Bytes)
			if !ok {
				return fmt.Errorf("unexpected result type %T for eth_call", batch[i].Result)
			}
			out, err := c.backend.Client().CallContract(ctx, msg, block)
			if err != nil {
				batch[i].Error = err
			} else {
				*result = out
			}
		default:
			return fmt.Errorf("unsupported method %s", batch[i].Method)
		}
		recorded = append(recorded, call)
	}
	c.mu.Lock()
	c.batches = append(c.batches, recorded)
	c.mu.Unlock()
	return nil
}

// parseCall reads the call message and the block of eth_call arguments. The block "latest" gives nil.
func parseCall(args []any) (ethereum.CallMsg, *big.Int, error) {
	if len(args) != 2 {
		return ethereum.CallMsg{}, nil, fmt.Errorf("expected 2 arguments for eth_call, got %d", len(args))
	}
	params, ok := args[0].(map[string]any)
	if !ok {
		return ethereum.CallMsg{}, nil, fmt.Errorf("unexpected params type %T for eth_call", args[0])
	}
	to, ok := params["to"].(common.Address)
	if !ok {
		return ethereum.CallMsg{}, nil, fmt.Errorf("unexpected to type %T for eth_call", params["to"])
	}
	data, ok := params["data"].(hexutil.Bytes)
	if !ok {
		return ethereum.CallMsg{}, nil, fmt.Errorf("unexpected data type %T for eth_call", params["data"])
	}
	block, ok := args[1].(string)
	if !ok {
		return ethereum.CallMsg{}, nil, fmt.Errorf("unexpected block type %T for eth_call", args[1])
	}
	msg := ethereum.CallMsg{To: &to, Data: data}
	if block == "latest" {
		return msg, nil, nil
	}
	number, err := hexutil.DecodeBig(block)
	if err != nil {
		return ethereum.CallMsg{}, nil, fmt.Errorf("invalid block %q: %w", block, err)
	}
	return msg, number, nil
}

// Env is a simulated chain with two fee tokens and a Fee Quoter.
type Env struct {
	Client     *Client
	Backend    *simulated.Backend
	Owner      common.Address
	FeeQuoter  common.Address
	Link, USDC common.Address

	auth *bind.TransactOpts
	fq   *fee_quoter.FeeQuoter
}

// AddFeeToken deploys a token and gives it a price on the Fee Quoter. The price makes it a fee token.
// The head moves forward.
func (e *Env) AddFeeToken(t *testing.T, symbol string, decimals uint8, price *big.Int) common.Address {
	t.Helper()
	token, _, _, err := factory_burn_mint_erc20.DeployFactoryBurnMintERC20(e.auth, e.Backend.Client(), symbol, symbol, decimals, big.NewInt(0), big.NewInt(0), e.Owner)
	require.NoError(t, err)
	e.Backend.Commit()
	_, err = e.fq.UpdatePrices(e.auth, fee_quoter.InternalPriceUpdates{
		TokenPriceUpdates: []fee_quoter.InternalTokenPriceUpdate{{SourceToken: token, UsdPerToken: price}},
	})
	require.NoError(t, err)
	e.Backend.Commit()
	return token
}

// New starts a simulated chain and deploys a Fee Quoter and two fee tokens (18 and 6 decimals).
// The owner is the only price updater. The Fee Quoter has prices for both tokens and for DestSelectors.
func New(t *testing.T) *Env {
	t.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	owner := crypto.PubkeyToAddress(key.PublicKey)
	backend := simulated.NewBackend(types.GenesisAlloc{owner: {Balance: new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1000))}})
	t.Cleanup(func() { _ = backend.Close() })
	auth, err := bind.NewKeyedTransactorWithChainID(key, big.NewInt(chainID))
	require.NoError(t, err)
	chain := backend.Client()

	deployToken := func(name, symbol string, decimals uint8) common.Address {
		addr, _, _, err := factory_burn_mint_erc20.DeployFactoryBurnMintERC20(auth, chain, name, symbol, decimals, big.NewInt(0), big.NewInt(0), owner)
		require.NoError(t, err)
		backend.Commit()
		return addr
	}
	link := deployToken("Link", "LINK", 18)
	usdc := deployToken("USD Coin", "USDC", 6)

	destConfigs := make([]fee_quoter.FeeQuoterDestChainConfigArgs, 0, len(DestSelectors))
	for _, selector := range DestSelectors {
		destConfigs = append(destConfigs, fee_quoter.FeeQuoterDestChainConfigArgs{
			DestChainSelector: selector,
			DestChainConfig: fee_quoter.FeeQuoterDestChainConfig{
				IsEnabled:                   true,
				MaxDataBytes:                30_000,
				MaxPerMsgGasLimit:           3_000_000,
				DestGasOverhead:             300_000,
				DestGasPerPayloadByteBase:   16,
				ChainFamilySelector:         [4]byte{0x28, 0x12, 0xd5, 0x2c},
				DefaultTokenFeeUSDCents:     50,
				DefaultTokenDestGasOverhead: 90_000,
				DefaultTxGasLimit:           200_000,
				NetworkFeeUSDCents:          10,
				LinkFeeMultiplierPercent:    90,
			},
		})
	}
	fqAddr, _, fq, err := fee_quoter.DeployFeeQuoter(
		auth,
		chain,
		fee_quoter.FeeQuoterStaticConfig{MaxFeeJuelsPerMsg: new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1e9)), LinkToken: link},
		[]common.Address{owner},
		nil,
		destConfigs,
	)
	require.NoError(t, err)
	backend.Commit()

	_, err = fq.UpdatePrices(auth, fee_quoter.InternalPriceUpdates{
		TokenPriceUpdates: []fee_quoter.InternalTokenPriceUpdate{
			{SourceToken: link, UsdPerToken: LinkPrice},
			{SourceToken: usdc, UsdPerToken: USDCPrice},
		},
		GasPriceUpdates: []fee_quoter.InternalGasPriceUpdate{
			{DestChainSelector: DestSelectors[0], UsdPerUnitGas: PackGasPrice(GasDAUSD, GasExecutionUSD)},
		},
	})
	require.NoError(t, err)
	backend.Commit()

	return &Env{
		Client:    &Client{SimulatedBackendClient: client.NewSimulatedBackendClient(t, backend, big.NewInt(chainID)), backend: backend},
		Backend:   backend,
		Owner:     owner,
		FeeQuoter: fqAddr,
		Link:      link,
		USDC:      usdc,
		auth:      auth,
		fq:        fq,
	}
}
