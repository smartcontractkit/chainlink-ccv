package evm

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/rmn_remote"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	evmclient "github.com/smartcontractkit/chainlink-evm/pkg/client"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess/headtrackerconformance"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess/rmncurseconformance"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// clientOracle implements [headtrackerconformance.Oracle] by reading the same
// EVM [evmclient.Client] the head path uses, so the conformance suite compares
// the SourceReader/HeadTracker view to the node's canonical header at each number.
type clientOracle struct{ c evmclient.Client }

func (o *clientOracle) BlockHeaderByNumber(ctx context.Context, n uint64) (*protocol.BlockHeader, error) {
	h, err := o.c.HeadByNumber(ctx, new(big.Int).SetUint64(n))
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, fmt.Errorf("nil head at block %d", n)
	}
	if h.Number < 0 {
		return nil, fmt.Errorf("invalid negative block number: %d", h.Number)
	}
	return &protocol.BlockHeader{
		Number:     uint64(h.Number),
		Hash:       protocol.Bytes32(h.Hash),
		ParentHash: protocol.Bytes32(h.ParentHash),
		Timestamp:  h.Timestamp,
	}, nil
}

// TestSourceReader_HeadTrackerConformance runs the shared head tracker suite
// against [SourceReader] using go-ethereum's simulated chain plus the
// integration [sourcereader.SimpleHeadTrackerWrapper] and [evmclient.SimulatedBackendClient].
// This is a proof-of-concept that chain-specific wiring matches [Oracle] ground truth.
func TestSourceReader_HeadTrackerConformance(t *testing.T) {
	// Simulated default chain is 1337; must match [evmclient.NewSimulatedBackendClient] chainID.
	chainID := big.NewInt(1337)
	backend := simulated.NewBackend(types.GenesisAlloc{}, simulated.WithBlockGasLimit(10_000_000))
	t.Cleanup(func() { _ = backend.Close() })

	// Enough blocks for SimpleHeadTrackerWrapper: finalized = latest - confirmation depth (15).
	for range 32 {
		_ = backend.Commit()
	}

	cl := evmclient.NewSimulatedBackendClient(t, backend, chainID)
	lggr := logger.Test(t)
	ht := sourcereader.NewSimpleHeadTrackerWrapper(cl, lggr)

	topic := onramp.OnRampCCIPMessageSent{}.Topic().Hex()
	sr, err := NewEVMSourceReader(
		cl,
		ht,
		// Plausible non-zero test addresses; constructor does not need live contracts for head reads.
		common.HexToAddress("0x0000000000000000000000000000000000000001"),
		common.HexToAddress("0x0000000000000000000000000000000000000002"),
		topic,
		protocol.ChainSelector(1),
		lggr,
		nil,
	)
	require.NoError(t, err)

	oracle := &clientOracle{c: cl}
	// [sourcereader.SimpleHeadTrackerWrapper.LatestSafeBlock] returns (nil, nil) — not an Ethereum L1 "safe" tag.
	headtrackerconformance.Run(t, nil, headtrackerconformance.Config{
		HeadTracker: sr,
		Oracle:      oracle,
		Safe:        headtrackerconformance.SafeMustBeNil,
	})
}

// evmSimRMNHarness deploys the RMN Remote contract on the same simulated chain
// as the reader and curses/uncurses via the owner key.
type evmSimRMNHarness struct {
	t   *testing.T
	b   *simulated.Backend
	c   *evmclient.SimulatedBackendClient
	chainID *big.Int
	auth  *bind.TransactOpts
	rmn   *rmn_remote.RMNRemote
	adr   common.Address
}

func newEVMSimRMNHarness(t *testing.T, b *simulated.Backend, c *evmclient.SimulatedBackendClient, key *ecdsa.PrivateKey, chainID *big.Int) *evmSimRMNHarness {
	t.Helper()
	from := crypto.PubkeyToAddress(key.PublicKey)
	auth, err := bind.NewKeyedTransactorWithChainID(key, chainID)
	require.NoError(t, err, "NewKeyedTransactorWithChainID")
	require.Equal(t, from, auth.From, "owner is deployer for curse operations")
	return &evmSimRMNHarness{
		t:   t,
		b:   b,
		c:   c,
		chainID: chainID,
		auth:  auth,
	}
}

// DeployRMN implements [rmncurseconformance.RMNCurseHarness]. Idempotent: second
// call returns the same [protocol.UnknownAddress].
func (h *evmSimRMNHarness) DeployRMN(ctx context.Context) (protocol.UnknownAddress, error) {
	if h.rmn != nil {
		return evmAddressToUnknown(h.adr), nil
	}
	h.auth.GasLimit = 10_000_000
	h.auth.Context = ctx
	const localChainSelector uint64 = 1
	// legacy IRMN not used by curse/reader tests (address(0))
	addr, tx, rmn, err := rmn_remote.DeployRMNRemote(h.auth, h.c, localChainSelector, common.Address{})
	if err != nil {
		return nil, err
	}
	_ = h.b.Commit()
	receipt, err := bind.WaitMined(ctx, h.c, tx)
	if err != nil {
		return nil, err
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return nil, fmt.Errorf("rmn remote deploy reverted, status %d", receipt.Status)
	}
	h.adr, h.rmn = addr, rmn
	return evmAddressToUnknown(h.adr), nil
}

func (h *evmSimRMNHarness) CurseRMN(ctx context.Context, subjects []protocol.Bytes16) error {
	if h.rmn == nil {
		return fmt.Errorf("DeployRMN must be called first")
	}
	conv := make([][16]byte, len(subjects))
	for i := range subjects {
		conv[i] = subjects[i]
	}
	h.auth.GasLimit = 4_000_000
	h.auth.Context = ctx
	tx, err := h.rmn.Curse0(h.auth, conv)
	if err != nil {
		return err
	}
	_ = h.b.Commit()
	receipt, err := bind.WaitMined(ctx, h.c, tx)
	if err != nil {
		return err
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("Curse0 reverted, status %d", receipt.Status)
	}
	return nil
}

func (h *evmSimRMNHarness) ClearRMNCurses(ctx context.Context) error {
	if h.rmn == nil {
		return fmt.Errorf("DeployRMN must be called first")
	}
	subs, err := h.rmn.GetCursedSubjects(&bind.CallOpts{Context: ctx})
	if err != nil {
		return err
	}
	if len(subs) == 0 {
		return nil
	}
	h.auth.GasLimit = 4_000_000
	h.auth.Context = ctx
	tx, err := h.rmn.Uncurse0(h.auth, subs)
	if err != nil {
		return err
	}
	_ = h.b.Commit()
	receipt, err := bind.WaitMined(ctx, h.c, tx)
	if err != nil {
		return err
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("Uncurse0 reverted, status %d", receipt.Status)
	}
	return nil
}

// evmAddressToUnknown encodes a 20-byte EVM [common.Address] as a chain-agnostic
// [protocol.UnknownAddress] (length 20) for the conformance API.
func evmAddressToUnknown(a common.Address) protocol.UnknownAddress {
	return protocol.UnknownAddress(append([]byte{}, a[:]...))
}

// unknownToCommon requires len(addr)==20; used when wiring the reader to the
// same RMN as the harness.
func unknownToEVMAddress(a protocol.UnknownAddress) (common.Address, error) {
	if len(a) != 20 {
		return common.Address{}, fmt.Errorf("evm: UnknownAddress must be 20 bytes, got %d", len(a))
	}
	var o common.Address
	copy(o[:], a)
	return o, nil
}

// TestSourceReader_RMNCurseReaderConformance runs [rmncurseconformance.Run]
// against a simulated chain with a real RMN Remote and [SourceReader.GetRMNCursedSubjects].
func TestSourceReader_RMNCurseReaderConformance(t *testing.T) {
	chainID := big.NewInt(1337)
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	owner := crypto.PubkeyToAddress(key.PublicKey)
	oneEth := new(big.Int).Mul(big.NewInt(1_000_000_000_000_000_000), big.NewInt(1000))
	backend := simulated.NewBackend(types.GenesisAlloc{
		owner: {Balance: oneEth},
	}, simulated.WithBlockGasLimit(10_000_000))
	t.Cleanup(func() { _ = backend.Close() })
	for range 5 {
		_ = backend.Commit()
	}
	cl := evmclient.NewSimulatedBackendClient(t, backend, chainID)
	lggr := logger.Test(t)
	ht := sourcereader.NewSimpleHeadTrackerWrapper(cl, lggr)
	topic := onramp.OnRampCCIPMessageSent{}.Topic().Hex()

	harness := newEVMSimRMNHarness(t, backend, cl, key, chainID)
	onRamp := common.HexToAddress("0x0000000000000000000000000000000000000001")

	ctx := context.Background()
	rmncurseconformance.Run(t, ctx, rmncurseconformance.Config{
		Harness: harness,
		NewReader: func(ctx context.Context, rmnAddr protocol.UnknownAddress) (chainaccess.RMNCurseReader, error) {
			rmnEVM, err := unknownToEVMAddress(rmnAddr)
			if err != nil {
				return nil, err
			}
			return NewEVMSourceReader(
				cl,
				ht,
				onRamp,
				rmnEVM,
				topic,
				protocol.ChainSelector(1),
				lggr,
				nil,
			)
		},
	})
}
