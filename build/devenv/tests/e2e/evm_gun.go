package e2e

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/weth"
	routeroperations "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/mock_receiver_v2"
	onrampoperations "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/versioned_verifier_resolver"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	routerwrapper "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_2_0/router"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/wasp"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	ccldf "github.com/smartcontractkit/chainlink-ccv/build/devenv/cldf"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/load"
)

type NonceKey struct {
	Selector uint64
	Address  string
}

// Compile time interface conformance check.
var _ load.LoadGun = (*EVMTXGun)(nil)

type EVMTXGun struct {
	cfg                 *ccv.Cfg
	testConfig          *load.TestProfileConfig
	e                   *deployment.Environment
	selectors           []uint64
	impl                map[uint64]cciptestinterfaces.CCIP17
	sentMsgSet          map[load.SentMessage]struct{}
	srcSelectors        []uint64
	destSelectors       []uint64
	seqNosMu            sync.Mutex
	sentMsgCh           chan load.SentMessage // Channel for real-time message notifications
	closeOnce           sync.Once             // Ensure channel is closed only once
	nonce               sync.Map              // map[NonceKey]*uint64
	messageProfiles     []load.MessageProfileConfig
	userSelector        map[uint64]func() *bind.TransactOpts
	executorArgsParams  any // optional, passed to BuildV3ExtraArgs
	tokenReceiverParams any // optional, passed to BuildV3ExtraArgs
	tokenArgsParams     any // optional, passed to BuildV3ExtraArgs

	// fireAndForget submits EVM txs without waiting for confirmation; background
	// workers poll receipts and push SentMessage with block-timestamp SentTime.
	fireAndForget bool
	router        map[uint64]*routerwrapper.Router
	onRampFilter  map[uint64]*onramp.OnRampFilterer
	evmBackend    map[uint64]evmChainBackend
	ccipSentTopic common.Hash
	pendingCh     chan pendingTx
	fafWg         sync.WaitGroup
}

// CloseSentChannel closes the sent messages channel to signal no more messages will be sent.
func (m *EVMTXGun) CloseSentChannel() {
	m.closeOnce.Do(func() {
		if m.fireAndForget {
			// Close pendingCh first to signal no more work, then wait for workers
			// to drain remaining items before closing sentMsgCh.
			close(m.pendingCh)
			m.fafWg.Wait()
		}
		close(m.sentMsgCh)
	})
}

// SentMessages returns the sent message channel for the verification pipeline.
func (m *EVMTXGun) SentMessages() <-chan load.SentMessage {
	return m.sentMsgCh
}

func NewEVMTransactionGun(cfg *ccv.Cfg, e *deployment.Environment, selectors []uint64, impls map[uint64]cciptestinterfaces.CCIP17, srcSelectors, destSelectors []uint64) (*EVMTXGun, error) {
	userSelector := make(map[uint64]func() *bind.TransactOpts)
	for _, chain := range srcSelectors {
		evmImpl, ok := impls[chain].(evm.EVMOptions)
		if !ok {
			return nil, fmt.Errorf("selector %d does not implement EVMOptions", chain)
		}
		userSelector[chain] = evmImpl.GetRoundRobinUser()
	}
	return &EVMTXGun{
		cfg:           cfg,
		e:             e,
		selectors:     selectors,
		impl:          impls,
		sentMsgSet:    make(map[load.SentMessage]struct{}),
		sentMsgCh:     make(chan load.SentMessage, load.SentMessageChannelBufferSize),
		srcSelectors:  srcSelectors,
		destSelectors: destSelectors,
		userSelector:  userSelector,
	}, nil
}

// EVMTXGunOption configures an EVMTXGun at construction time.
type EVMTXGunOption func(*EVMTXGun)

// WithExecutorArgsParams sets the executorArgsParams passed to BuildV3ExtraArgs.
// Params are forwarded to the destination chain's MessageV3Destination.GetExecutorArgs implementation (applied for all destinations used by this gun).
func WithExecutorArgsParams(params any) EVMTXGunOption {
	return func(g *EVMTXGun) {
		g.executorArgsParams = params
	}
}

// WithTokenReceiverParams sets the tokenReceiverParams passed to BuildV3ExtraArgs.
// Params are forwarded to the destination chain's MessageV3Destination.GetTokenReceiver implementation (applied for all destinations used by this gun).
func WithTokenReceiverParams(params any) EVMTXGunOption {
	return func(g *EVMTXGun) {
		g.tokenReceiverParams = params
	}
}

// WithTokenArgsParams sets the tokenArgsParams passed to BuildV3ExtraArgs.
// Params are forwarded to the destination chain's MessageV3Destination.GetTokenArgs implementation (applied for all destinations used by this gun).
func WithTokenArgsParams(params any) EVMTXGunOption {
	return func(g *EVMTXGun) {
		g.tokenArgsParams = params
	}
}

// WithFireAndForget enables fire-and-forget mode: EVM txs are submitted without
// waiting for confirmation, and background receipt workers push SentMessage with
// the block timestamp as SentTime. Requires an EVM chain as source.
func WithFireAndForget() EVMTXGunOption {
	return func(g *EVMTXGun) {
		g.fireAndForget = true
	}
}

func NewEVMTransactionGunFromTestConfig(cfg *ccv.Cfg, testProfile *load.TestProfileConfig, messageProfiles []load.MessageProfileConfig, e *deployment.Environment, impls map[uint64]cciptestinterfaces.CCIP17, opts ...EVMTXGunOption) (*EVMTXGun, error) {
	selectors := make([]uint64, 0, len(testProfile.ChainsAsSource)+len(testProfile.ChainsAsDest))
	srcSelectors := make([]uint64, 0, len(testProfile.ChainsAsSource))
	destSelectors := make([]uint64, 0, len(testProfile.ChainsAsDest))
	for _, chain := range testProfile.ChainsAsSource {
		chainSelector, _ := strconv.ParseUint(chain.Selector, 10, 64)
		selectors = append(selectors, chainSelector)
		srcSelectors = append(srcSelectors, chainSelector)
	}
	for _, chain := range testProfile.ChainsAsDest {
		chainSelector, _ := strconv.ParseUint(chain.Selector, 10, 64)
		selectors = append(selectors, chainSelector)
		destSelectors = append(destSelectors, chainSelector)
	}

	userSelector := make(map[uint64]func() *bind.TransactOpts)
	for _, chain := range srcSelectors {
		if evmImpl, ok := impls[chain].(evm.EVMOptions); ok {
			userSelector[chain] = evmImpl.GetRoundRobinUser()
		}
	}

	g := &EVMTXGun{
		cfg:             cfg,
		testConfig:      testProfile,
		e:               e,
		selectors:       selectors,
		impl:            impls,
		sentMsgSet:      make(map[load.SentMessage]struct{}),
		sentMsgCh:       make(chan load.SentMessage, load.SentMessageChannelBufferSize),
		srcSelectors:    srcSelectors,
		destSelectors:   destSelectors,
		messageProfiles: messageProfiles,
		userSelector:    userSelector,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(g)
		}
	}

	if g.fireAndForget {
		if err := g.initFireAndForget(e, srcSelectors); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// initFireAndForget resolves per-source EVM infra (router, onramp filter, backend)
// needed for direct CcipSend submission and receipt polling, then starts workers.
func (g *EVMTXGun) initFireAndForget(e *deployment.Environment, srcSelectors []uint64) error {
	evmChains := e.BlockChains.EVMChains()
	g.router = make(map[uint64]*routerwrapper.Router, len(srcSelectors))
	g.onRampFilter = make(map[uint64]*onramp.OnRampFilterer, len(srcSelectors))
	g.evmBackend = make(map[uint64]evmChainBackend, len(srcSelectors))
	g.pendingCh = make(chan pendingTx, 10000)
	g.ccipSentTopic = onramp.OnRampCCIPMessageSent{}.Topic()

	for _, selector := range srcSelectors {
		srcChain, ok := evmChains[selector]
		if !ok {
			return fmt.Errorf("EVM chain %d not found in CLDF environment", selector)
		}

		routerAddr, err := evm.ResolveContractAddr(e.DataStore, selector, datastore.ContractType(routeroperations.ContractType), semver.MustParse(routeroperations.Deploy.Version()))
		if err != nil {
			return fmt.Errorf("resolve router for %d: %w", selector, err)
		}
		r, err := routerwrapper.NewRouter(routerAddr, srcChain.Client)
		if err != nil {
			return fmt.Errorf("create router wrapper for %d: %w", selector, err)
		}
		g.router[selector] = r

		onRampAddr, err := evm.ResolveContractAddr(e.DataStore, selector, datastore.ContractType(onrampoperations.ContractType), semver.MustParse(onrampoperations.Deploy.Version()))
		if err != nil {
			return fmt.Errorf("resolve onramp for %d: %w", selector, err)
		}
		onRampFilter, err := onramp.NewOnRampFilterer(onRampAddr, srcChain.Client)
		if err != nil {
			return fmt.Errorf("create onramp filterer for %d: %w", selector, err)
		}
		g.onRampFilter[selector] = onRampFilter

		g.evmBackend[selector] = srcChain.Client
	}

	for range load.FAFReceiptWorkers {
		g.fafWg.Add(1)
		go g.receiptWorker()
	}
	return nil
}

func (m *EVMTXGun) initNonce(key NonceKey, userAddress common.Address) error {
	if _, loaded := m.nonce.Load(key); loaded {
		return nil
	}

	var evmImpl evm.EVMOptions
	evmImpl, ok := m.impl[key.Selector].(evm.EVMOptions)
	if !ok {
		return fmt.Errorf("impl is not EVMOptions")
	}

	n, err := evmImpl.GetUserNonce(context.Background(), protocol.UnknownAddress(userAddress.Bytes()))
	if err != nil {
		return fmt.Errorf("failed to get pending nonce for selector %d: %w", key.Selector, err)
	}
	// Allocate a pointer so the stored value can be incremented atomically across
	// goroutines without replacing the map entry. LoadOrStore ensures exactly one
	// pointer wins even if multiple goroutines race through initialization.
	ptr := new(uint64)
	*ptr = n
	m.nonce.LoadOrStore(key, ptr)
	return nil
}

// Call implements example gun call, assertions on response bodies should be done here.
func (m *EVMTXGun) Call(_ *wasp.Generator) *wasp.Response {
	ctx := context.Background()
	sentTime := time.Now()
	srcSelector, err := m.SelectSourceSelector()
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("failed to select source selector: %w", err).Error(), Failed: true}
	}
	destSelector, err := m.SelectDestSelector(srcSelector)
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("failed to select dest selector: %w", err).Error(), Failed: true}
	}

	dest, err := m.resolveDestLoadInfo(destSelector)
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("failed to resolve destination: %w", err).Error(), Failed: true}
	}

	fields, opts, err := m.selectMessageProfile(srcSelector, dest)
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("failed to select message profile: %w", err).Error(), Failed: true}
	}

	sender := m.userSelector[srcSelector]()
	nonceKey := NonceKey{Selector: srcSelector, Address: sender.From.String()}

	if err := m.initNonce(nonceKey, sender.From); err != nil {
		return &wasp.Response{Error: err.Error(), Failed: true}
	}

	nonceVal, ok := m.nonce.Load(nonceKey)
	if !ok {
		return &wasp.Response{Error: fmt.Sprintf("nonce not initialized for key %+v", nonceKey), Failed: true}
	}
	noncePtr := nonceVal.(*uint64)
	// Atomically claim the next nonce. AddUint64 returns the new value, so
	// subtracting 1 gives us the nonce we own exclusively for this send.
	currentNonce := atomic.AddUint64(noncePtr, 1) - 1

	b := ccldf.NewDefaultCLDFBundle(m.e)
	m.e.OperationsBundle = b

	c, ok := m.impl[srcSelector]
	if !ok {
		return &wasp.Response{Error: fmt.Sprintf("selector %d was not found in impls", srcSelector), Failed: true}
	}

	chainAsSource, ok := c.(cciptestinterfaces.ChainAsSource)
	if !ok {
		return &wasp.Response{Error: "impl is not ChainAsSource", Failed: true}
	}

	// encoding is decided based on dest
	extraArgs, err := m.buildExtraArgs(srcSelector, dest, opts)
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("failed to build extra args: %w", err).Error(), Failed: true}
	}

	srcMessage, err := chainAsSource.BuildChainMessage(ctx, fields, extraArgs)
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("failed to build message: %w", err).Error(), Failed: true}
	}

	if m.fireAndForget {
		evmMsg, ok := srcMessage.(routerwrapper.ClientEVM2AnyMessage)
		if !ok {
			return &wasp.Response{Error: "message is not ClientEVM2AnyMessage", Failed: true}
		}
		// skip GetFee() to avoid extra RPC call in burst tests.
		txOpts := *sender
		txOpts.Value = big.NewInt(0)
		txOpts.Nonce = new(big.Int).SetUint64(currentNonce)
		tx, err := m.router[srcSelector].CcipSend(&txOpts, destSelector, evmMsg)
		if err != nil {
			return &wasp.Response{Error: fmt.Errorf("ccip send: %w", err).Error(), Failed: true}
		}
		m.pendingCh <- pendingTx{
			txHash:       tx.Hash(),
			srcSelector:  srcSelector,
			destSelector: destSelector,
		}
		return &wasp.Response{Data: tx.Hash().Hex()}
	}

	// WETH fees need msgValue=0; DisableTokenAmountValidation sets msgValue=fee and reverts.
	sentEvent, _, err := chainAsSource.SendChainMessage(ctx, destSelector, srcMessage, evm.SendOptions{
		Nonce:  &currentNonce,
		Sender: sender,
	})
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("failed to send message: %w", err).Error(), Failed: true}
	}

	// Record the actual sequence number from the sent event
	m.seqNosMu.Lock()
	m.sentMsgSet[load.SentMessage{SeqNo: uint64(sentEvent.Message.SequenceNumber), MessageID: sentEvent.MessageID, SentTime: sentTime, ChainPair: load.SrcDest{Src: srcSelector, Dest: destSelector}}] = struct{}{}
	m.seqNosMu.Unlock()

	// Push to channel for verification
	m.sentMsgCh <- load.SentMessage{SeqNo: uint64(sentEvent.Message.SequenceNumber), MessageID: sentEvent.MessageID, SentTime: sentTime, ChainPair: load.SrcDest{Src: srcSelector, Dest: destSelector}}

	return &wasp.Response{Data: "ok"}
}

// SelectSourceSelectorByRatio selects an element from m.srcSelectors according to the source ratio in the chain_profiles.
func (m *EVMTXGun) SelectSourceSelector() (uint64, error) {
	if m.testConfig == nil {
		return m.srcSelectors[0], nil
	}
	return load.GetSelectorByRatio(
		m.testConfig.ChainsAsSource,
	)
}

// SelectDestSelectorByRatio selects an element from m.destSelectors according to the dest ratio in the chain_profiles.
func (m *EVMTXGun) SelectDestSelector(excludeSelector uint64) (uint64, error) {
	if m.testConfig == nil {
		return m.destSelectors[0], nil
	}
	choices := make([]load.ChainProfileConfig, 0, len(m.testConfig.ChainsAsDest))
	for _, chain := range m.testConfig.ChainsAsDest {
		if chain.Selector != strconv.FormatUint(excludeSelector, 10) {
			choices = append(choices, chain)
		}
	}
	return load.GetSelectorByRatio(choices)
}

// destLoadInfo determines destination routing: receiver and whether to use EVM or AltVM extra-args.
type destLoadInfo struct {
	selector        uint64
	receiver        protocol.UnknownAddress
	hasMockReceiver bool
}

// resolveDestLoadInfo resolves receiver + encoding shape.
func (m *EVMTXGun) resolveDestLoadInfo(destSelector uint64) (destLoadInfo, error) {
	mockReceiverRef, err := m.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			destSelector,
			datastore.ContractType(mock_receiver_v2.ContractType),
			semver.MustParse(mock_receiver_v2.Deploy.Version()),
			devenvcommon.DefaultReceiverQualifier))
	if err == nil {
		return destLoadInfo{
			selector:        destSelector,
			receiver:        protocol.UnknownAddress(common.HexToAddress(mockReceiverRef.Address).Bytes()),
			hasMockReceiver: true,
		}, nil
	}

	destImpl, ok := m.impl[destSelector]
	if !ok {
		return destLoadInfo{}, fmt.Errorf("destination chain %d not found in impls", destSelector)
	}
	receiver, err := destImpl.GetEOAReceiverAddress()
	if err != nil {
		return destLoadInfo{}, fmt.Errorf("could not get EOA receiver for dest %d: %w", destSelector, err)
	}
	return destLoadInfo{
		selector:        destSelector,
		receiver:        receiver,
		hasMockReceiver: false,
	}, nil
}

// buildExtraArgs picks encoding based on destination shape.
// V3 destinations without mock_receiver use BuildV3ExtraArgs; execution limits come
// from the destination via V3DestinationLoadDefaults when the profile leaves them unset.
func (m *EVMTXGun) buildExtraArgs(srcSelector uint64, dest destLoadInfo, opts cciptestinterfaces.MessageOptions) (cciptestinterfaces.GenericExtraArgs, error) {
	if dest.hasMockReceiver {
		return evm.SerializeEVMExtraArgs(3, opts)
	}

	v3Src, ok := m.impl[srcSelector].(cciptestinterfaces.MessageV3Source)
	if !ok {
		return nil, fmt.Errorf("source chain %d does not implement MessageV3Source", srcSelector)
	}
	v3Dest, ok := m.impl[dest.selector].(cciptestinterfaces.MessageV3Destination)
	if !ok {
		return nil, fmt.Errorf("destination chain %d does not implement MessageV3Destination", dest.selector)
	}

	v3Opts := opts
	if v3Opts.ExecutionGasLimit == 0 {
		if def, ok := m.impl[dest.selector].(cciptestinterfaces.V3DestinationLoadDefaults); ok {
			v3Opts.ExecutionGasLimit = def.V3LoadMessageOptions().ExecutionGasLimit
		}
	}

	// Receiver is in MessageFields; optional extra-args params are passed through to BuildV3ExtraArgs.
	return v3Src.BuildV3ExtraArgs(v3Opts, v3Dest, m.executorArgsParams, m.tokenReceiverParams, m.tokenArgsParams)
}

// selectMessageProfile builds message options for load sends and applies defaults when no profile is configured.
func (m *EVMTXGun) selectMessageProfile(srcSelector uint64, dest destLoadInfo) (cciptestinterfaces.MessageFields, cciptestinterfaces.MessageOptions, error) {
	receiver := dest.receiver

	wethContract, err := m.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			srcSelector,
			datastore.ContractType(weth.ContractType),
			semver.MustParse(weth.Deploy.Version()),
			""))
	if err != nil {
		return cciptestinterfaces.MessageFields{}, cciptestinterfaces.MessageOptions{}, fmt.Errorf("could not find WETH address in datastore: %w", err)
	}

	committeeVerifierProxyRef, err := m.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			srcSelector,
			datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType),
			versioned_verifier_resolver.Version,
			devenvcommon.DefaultCommitteeVerifierQualifier))
	if err != nil {
		return cciptestinterfaces.MessageFields{}, cciptestinterfaces.MessageOptions{}, fmt.Errorf("could not find committee verifier proxy address in datastore: %w", err)
	}

	// generate a random finality between 0 (chain default finality) and 1 (custom finality)
	finality, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return cciptestinterfaces.MessageFields{}, cciptestinterfaces.MessageOptions{}, fmt.Errorf("failed to generate finality: %w", err)
	}
	if m.testConfig == nil || m.testConfig.Messages == nil {
		return cciptestinterfaces.MessageFields{
				Receiver: receiver,
				Data:     []byte{},
				FeeToken: protocol.UnknownAddress(common.HexToAddress(wethContract.Address).Bytes()),
			}, cciptestinterfaces.MessageOptions{
				FinalityConfig: protocol.Finality(finality.Int64()),
				CCVs: []protocol.CCV{
					{
						CCVAddress: common.HexToAddress(committeeVerifierProxyRef.Address).Bytes(),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
			},
			nil
	}
	messageProfile, err := load.GetMessageByRatio(m.testConfig.Messages, m.messageProfiles)
	if err != nil {
		return cciptestinterfaces.MessageFields{}, cciptestinterfaces.MessageOptions{}, fmt.Errorf("failed to get message profile: %w", err)
	}
	fields := cciptestinterfaces.MessageFields{
		Receiver: receiver,
		Data:     []byte{},
		FeeToken: protocol.UnknownAddress(common.HexToAddress(wethContract.Address).Bytes()),
	}
	opts := cciptestinterfaces.MessageOptions{
		FinalityConfig: protocol.Finality(messageProfile.Finality),
	}

	if messageProfile.HasData {
		data := make([]byte, load.MessageDataSizeBytes(messageProfile, load.AvgMsgDataSize))
		_, err2 := rand.Read(data)
		if err2 != nil {
			return cciptestinterfaces.MessageFields{}, cciptestinterfaces.MessageOptions{}, fmt.Errorf("failed to generate data: %w", err2)
		}
		fields.Data = data
	}
	if messageProfile.HasToken {
		// token transfers not yet supported in staging, skip for now
		return fields, opts, nil
		// fields.TokenAmount = cciptestinterfaces.TokenAmount{
		// 	Amount:       big.NewInt(1),
		// 	TokenAddress: protocol.UnknownAddress(wethContract.Address),
		// }
	}
	return fields, opts, nil
}

// evmChainBackend is the subset of OnchainClient needed for tx submission and receipt polling.
type evmChainBackend interface {
	bind.ContractBackend
	bind.DeployBackend
}

// pendingTx is a submitted-but-unconfirmed fire-and-forget tx awaiting receipt processing.
type pendingTx struct {
	txHash       common.Hash
	srcSelector  uint64
	destSelector uint64
}

func (g *EVMTXGun) receiptWorker() {
	defer g.fafWg.Done()

	for p := range g.pendingCh {
		func() {
			defer func() {
				if r := recover(); r != nil {
					g.sendFailed(p, time.Now())
				}
			}()
			g.processReceipt(p)
		}()
	}
}

func (g *EVMTXGun) processReceipt(p pendingTx) {
	ctx, cancel := context.WithTimeout(context.Background(), load.FAFPollTimeout)
	defer cancel()

	backend := g.evmBackend[p.srcSelector]
	onRampFilter := g.onRampFilter[p.srcSelector]

	ticker := time.NewTicker(load.FAFPollInterval)
	defer ticker.Stop()

	for {
		receipt, err := backend.TransactionReceipt(ctx, p.txHash)
		if err != nil {
			select {
			case <-ctx.Done():
				g.sendFailed(p, time.Now())
				return
			case <-ticker.C:
				continue
			}
		}

		for _, log := range receipt.Logs {
			if log == nil || len(log.Topics) == 0 || log.Topics[0] != g.ccipSentTopic {
				continue
			}

			event, parseErr := onRampFilter.ParseCCIPMessageSent(*log)
			if parseErr != nil {
				continue
			}

			decodedMsg, decErr := protocol.DecodeMessage(event.EncodedMessage)
			if decErr != nil {
				continue
			}

			sentTime := evm.BlockTime(ctx, backend, receipt.BlockNumber)
			g.sentMsgCh <- load.SentMessage{
				SeqNo:     uint64(decodedMsg.SequenceNumber),
				MessageID: event.MessageId,
				SentTime:  sentTime,
				ChainPair: load.SrcDest{Src: p.srcSelector, Dest: p.destSelector},
			}
			return
		}

		// tx mined but no usable CCIPMessageSent event: mark as sent-but-failed
		g.sendFailed(p, evm.BlockTime(ctx, backend, receipt.BlockNumber))
		return
	}
}

// sendFailed pushes a SentMessage with Failed=true to the sentMsgCh.
func (g *EVMTXGun) sendFailed(p pendingTx, sentTime time.Time) {
	g.sentMsgCh <- load.SentMessage{
		SeqNo:     0,
		MessageID: ([32]byte)(p.txHash),
		SentTime:  sentTime,
		ChainPair: load.SrcDest{Src: p.srcSelector, Dest: p.destSelector},
		Failed:    true,
	}
}
