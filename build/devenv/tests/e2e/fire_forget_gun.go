package e2e

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/weth"
	routeroperations "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	onrampoperations "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	routerwrapper "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_2_0/router"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/load"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/wasp"
)

const (
	fafReceiptWorkers = 10
	fafPollInterval   = 1 * time.Second
	fafPollTimeout    = 2 * time.Minute
)

type pendingTx struct {
	txHash       common.Hash
	srcSelector  uint64
	destSelector uint64
}

var _ load.LoadGun = (*FireAndForgetEVMGun)(nil)

// FireAndForgetEVMGun submits EVM CCIP messages without waiting for tx
// confirmation. Background workers poll for receipts, parse CCIPMessageSent
// events, and push SentMessage with the block timestamp as SentTime.
type FireAndForgetEVMGun struct {
	impls              map[uint64]cciptestinterfaces.CCIP17
	evmSelector        uint64
	solSelector        uint64
	executorArgsParams any
	solReceiver        []byte

	router        *routerwrapper.Router
	onRampFilter  *onramp.OnRampFilterer
	evmBackend    evmChainBackend
	ccipSentTopic common.Hash
	wethAddr      common.Address

	// payloadSizeBytes is the arbitrary-message data payload per send. 0 (default)
	// sends an empty payload; a positive value sends that many random bytes, which
	// exercises the Solana offramp's buffered execution path for large messages.
	payloadSizeBytes int64

	userKey func() *bind.TransactOpts
	nonces  sync.Map // map[common.Address]*nonceTracker

	sentMsgCh chan load.SentMessage
	closeOnce sync.Once

	pendingCh chan pendingTx
	wg        sync.WaitGroup
}

// evmChainBackend is the subset of OnchainClient needed for tx submission and receipt polling.
type evmChainBackend interface {
	bind.ContractBackend
	bind.DeployBackend
}

// NewFireAndForgetEVMGun creates a fire-and-forget EVM load gun for
// EVM→Solana arbitrary messaging.
func NewFireAndForgetEVMGun(
	deployEnv *deployment.Environment,
	impls map[uint64]cciptestinterfaces.CCIP17,
	evmSelector uint64,
	solSelector uint64,
	solReceiver []byte,
	executorArgsParams any,
	payloadSizeBytes int64,
) (*FireAndForgetEVMGun, error) {
	evmChains := deployEnv.BlockChains.EVMChains()
	srcChain, ok := evmChains[evmSelector]
	if !ok {
		return nil, fmt.Errorf("EVM chain %d not found in CLDF environment", evmSelector)
	}

	ds := deployEnv.DataStore
	routerAddr, err := resolveContractAddr(ds, evmSelector, datastore.ContractType(routeroperations.ContractType), semver.MustParse(routeroperations.Deploy.Version()))
	if err != nil {
		return nil, fmt.Errorf("resolve router: %w", err)
	}
	r, err := routerwrapper.NewRouter(routerAddr, srcChain.Client)
	if err != nil {
		return nil, fmt.Errorf("create router wrapper: %w", err)
	}

	onRampAddr, err := resolveContractAddr(ds, evmSelector, datastore.ContractType(onrampoperations.ContractType), semver.MustParse(onrampoperations.Deploy.Version()))
	if err != nil {
		return nil, fmt.Errorf("resolve onramp: %w", err)
	}
	onRampFilter, err := onramp.NewOnRampFilterer(onRampAddr, srcChain.Client)
	if err != nil {
		return nil, fmt.Errorf("create onramp filterer: %w", err)
	}

	wethAddr, err := resolveContractAddr(ds, evmSelector, datastore.ContractType(weth.ContractType), semver.MustParse(weth.Deploy.Version()))
	if err != nil {
		return nil, fmt.Errorf("resolve weth: %w", err)
	}

	evmImpl, ok := impls[evmSelector].(interface {
		GetRoundRobinUser() func() *bind.TransactOpts
		GetUserNonce(context.Context, protocol.UnknownAddress) (uint64, error)
	})
	if !ok {
		return nil, fmt.Errorf("EVM chain %d does not support GetRoundRobinUser/GetUserNonce", evmSelector)
	}

	g := &FireAndForgetEVMGun{
		impls:              impls,
		evmSelector:        evmSelector,
		solSelector:        solSelector,
		executorArgsParams: executorArgsParams,
		solReceiver:        solReceiver,
		router:             r,
		onRampFilter:       onRampFilter,
		evmBackend:         srcChain.Client,
		ccipSentTopic:      onramp.OnRampCCIPMessageSent{}.Topic(),
		wethAddr:           wethAddr,
		userKey:            evmImpl.GetRoundRobinUser(),
		sentMsgCh:          make(chan load.SentMessage, sentMessageChannelBufferSize),
		pendingCh:          make(chan pendingTx, 10000),
		payloadSizeBytes:   payloadSizeBytes,
	}

	for range fafReceiptWorkers {
		g.wg.Add(1)
		go g.receiptWorker()
	}

	return g, nil
}

// CloseSentChannel closes the sent-message channel. Safe to call multiple times.
func (g *FireAndForgetEVMGun) CloseSentChannel() {
	g.closeOnce.Do(func() {
		// Close pendingCh first to signal no more work, then wait for workers
		// to drain remaining items before closing sentMsgCh
		close(g.pendingCh)
		g.wg.Wait()
		close(g.sentMsgCh)
	})
}

// SentMessages returns the sent-message channel for the verification pipeline.
func (g *FireAndForgetEVMGun) SentMessages() <-chan load.SentMessage {
	return g.sentMsgCh
}

// Call submits one EVM→Solana CCIP message without waiting for confirmation.
func (g *FireAndForgetEVMGun) Call(_ *wasp.Generator) *wasp.Response {
	ctx := context.Background()

	sender := g.userKey()
	nonceCounter, err := g.getOrInitNonce(ctx, sender.From, g.impls[g.evmSelector])
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("get initial nonce for %s: %w", sender.From, err).Error(), Failed: true}
	}
	nonce := nonceCounter.Add(1) - 1

	srcImpl, ok := g.impls[g.evmSelector]
	if !ok {
		return &wasp.Response{Error: fmt.Sprintf("EVM chain %d not found", g.evmSelector), Failed: true}
	}
	chainAsSource, ok := srcImpl.(cciptestinterfaces.ChainAsSource)
	if !ok {
		return &wasp.Response{Error: "impl is not ChainAsSource", Failed: true}
	}

	v3Src, ok := srcImpl.(cciptestinterfaces.MessageV3Source)
	if !ok {
		return &wasp.Response{Error: "impl is not MessageV3Source", Failed: true}
	}
	v3Dest, ok := g.impls[g.solSelector].(cciptestinterfaces.MessageV3Destination)
	if !ok {
		return &wasp.Response{Error: "Solana impl is not MessageV3Destination", Failed: true}
	}

	opts := cciptestinterfaces.MessageOptions{
		FinalityConfig:    1,
		ExecutionGasLimit: 0, // let dest chain fill via V3LoadMessageOptions
	}
	if def, hasDefaults := g.impls[g.solSelector].(cciptestinterfaces.V3DestinationLoadDefaults); hasDefaults {
		opts.ExecutionGasLimit = def.V3LoadMessageOptions().ExecutionGasLimit
	}

	extraArgs, err := v3Src.BuildV3ExtraArgs(opts, v3Dest, g.executorArgsParams, nil, nil)
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("build extra args: %w", err).Error(), Failed: true}
	}

	var data []byte
	if g.payloadSizeBytes > 0 {
		data = make([]byte, g.payloadSizeBytes)
		if _, randErr := rand.Read(data); randErr != nil {
			return &wasp.Response{Error: fmt.Errorf("generate payload: %w", randErr).Error(), Failed: true}
		}
	}

	srcMsg, err := chainAsSource.BuildChainMessage(ctx, cciptestinterfaces.MessageFields{
		Receiver: g.solReceiver,
		Data:     data,
		FeeToken: protocol.UnknownAddress(g.wethAddr.Bytes()),
	}, extraArgs)
	if err != nil {
		return &wasp.Response{Error: err.Error(), Failed: true}
	}

	evmMsg, ok := srcMsg.(routerwrapper.ClientEVM2AnyMessage)
	if !ok {
		return &wasp.Response{Error: "message is not ClientEVM2AnyMessage", Failed: true}
	}

	// skip GetFee() to avoid extra RPC call in burst tests.
	txOpts := *sender
	txOpts.Value = big.NewInt(0)
	txOpts.Nonce = new(big.Int).SetUint64(nonce)
	tx, err := g.router.CcipSend(&txOpts, g.solSelector, evmMsg)
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("ccip send: %w", err).Error(), Failed: true}
	}

	g.pendingCh <- pendingTx{
		txHash:       tx.Hash(),
		srcSelector:  g.evmSelector,
		destSelector: g.solSelector,
	}

	return &wasp.Response{Data: tx.Hash().Hex()}
}

// nonceTracker holds a per-address nonce counter and seeds it exactly once.
type nonceTracker struct {
	once sync.Once
	val  atomic.Uint64
	err  error
}

func (g *FireAndForgetEVMGun) getOrInitNonce(ctx context.Context, addr common.Address, evmImpl any) (*atomic.Uint64, error) {
	actual, _ := g.nonces.LoadOrStore(addr, &nonceTracker{})
	t := actual.(*nonceTracker)
	t.once.Do(func() {
		noncer, ok := evmImpl.(interface {
			GetUserNonce(context.Context, protocol.UnknownAddress) (uint64, error)
		})
		if !ok {
			return
		}
		n, err := noncer.GetUserNonce(ctx, protocol.UnknownAddress(addr.Bytes()))
		if err != nil {
			t.err = err
			return
		}
		t.val.Store(n)
	})
	if t.err != nil {
		return nil, t.err
	}
	return &t.val, nil
}

func (g *FireAndForgetEVMGun) receiptWorker() {
	defer g.wg.Done()

	for p := range g.pendingCh {
		g.processReceipt(p)
	}
}

func (g *FireAndForgetEVMGun) processReceipt(p pendingTx) {
	deadline := time.Now().Add(fafPollTimeout)
	for {
		if time.Now().After(deadline) {
			return
		}

		receipt, err := g.evmBackend.TransactionReceipt(context.Background(), p.txHash)
		if err != nil {
			time.Sleep(fafPollInterval)
			continue
		}

		for _, log := range receipt.Logs {
			if log == nil || len(log.Topics) == 0 || log.Topics[0] != g.ccipSentTopic {
				continue
			}

			event, parseErr := g.onRampFilter.ParseCCIPMessageSent(*log)
			if parseErr != nil {
				continue
			}

			decodedMsg, decErr := protocol.DecodeMessage(event.EncodedMessage)
			if decErr != nil {
				continue
			}

			sentTime := blockTime(context.Background(), g.evmBackend, receipt.BlockNumber)
			g.sentMsgCh <- load.SentMessage{
				SeqNo:     uint64(decodedMsg.SequenceNumber),
				MessageID: event.MessageId,
				SentTime:  sentTime,
				ChainPair: load.SrcDest{Src: p.srcSelector, Dest: p.destSelector},
			}
			return
		}

		// tx mined but no usable CCIPMessageSent event: mark as sent-but-failed
		sentTime := blockTime(context.Background(), g.evmBackend, receipt.BlockNumber)
		g.sentMsgCh <- load.SentMessage{
			SeqNo:     0,
			MessageID: ([32]byte)(p.txHash),
			SentTime:  sentTime,
			ChainPair: load.SrcDest{Src: p.srcSelector, Dest: p.destSelector},
			Failed:    true,
		}
		return
	}
}

func blockTime(ctx context.Context, backend bind.ContractBackend, blockNumber *big.Int) time.Time {
	header, err := backend.HeaderByNumber(ctx, blockNumber)
	if err != nil {
		return time.Now()
	}
	// #nosec G115 -- block timestamps are epoch seconds and well within int64 range.
	return time.Unix(int64(header.Time), 0)
}

func resolveContractAddr(ds datastore.DataStore, selector uint64, contractType datastore.ContractType, version *semver.Version) (common.Address, error) {
	refs := ds.Addresses().Filter(
		datastore.AddressRefByChainSelector(selector),
		datastore.AddressRefByType(contractType),
		datastore.AddressRefByVersion(version),
	)
	if len(refs) != 1 {
		return common.Address{}, fmt.Errorf("expected 1 %s for selector %d version %s, got %d", contractType, selector, version, len(refs))
	}
	return common.HexToAddress(refs[0].Address), nil
}
