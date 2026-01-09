package e2e

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/weth"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/wasp"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/load"
)

const sentMessageChannelBufferSize = 1000

type SrcDest struct {
	Src  uint64
	Dest uint64
}

// SentMessage represents a message that was sent and needs verification.
type SentMessage struct {
	SeqNo     uint64
	MessageID [32]byte
	SentTime  time.Time
	ChainPair SrcDest
}

type EVMTXGun struct {
	cfg           *ccv.Cfg
	testConfig    *load.TestProfileConfig
	e             *deployment.Environment
	selectors     []uint64
	impl          map[uint64]cciptestinterfaces.CCIP17
	sentMsgSet    map[SentMessage]struct{}
	srcSelectors  []uint64
	destSelectors []uint64
	seqNosMu      sync.Mutex
	sentMsgCh     chan SentMessage // Channel for real-time message notifications
	closeOnce     sync.Once        // Ensure channel is closed only once
	nonceMu       sync.Mutex
	nonce         map[uint64]*atomic.Uint64
}

// CloseSentChannel closes the sent messages channel to signal no more messages will be sent.
func (m *EVMTXGun) CloseSentChannel() {
	m.closeOnce.Do(func() {
		close(m.sentMsgCh)
	})
}

func NewEVMTransactionGun(cfg *ccv.Cfg, e *deployment.Environment, selectors []uint64, impls map[uint64]cciptestinterfaces.CCIP17, srcSelectors, destSelectors []uint64) *EVMTXGun {
	return &EVMTXGun{
		cfg:           cfg,
		e:             e,
		selectors:     selectors,
		impl:          impls,
		sentMsgSet:    make(map[SentMessage]struct{}),
		sentMsgCh:     make(chan SentMessage, sentMessageChannelBufferSize),
		nonce:         make(map[uint64]*atomic.Uint64),
		srcSelectors:  srcSelectors,
		destSelectors: destSelectors,
	}
}

func NewEVMTransactionGunFromTestConfig(cfg *ccv.Cfg, testConfig *load.TestProfileConfig, e *deployment.Environment, impls map[uint64]cciptestinterfaces.CCIP17) *EVMTXGun {
	selectors := make([]uint64, 0)
	srcSelectors := make([]uint64, 0, len(testConfig.ChainsAsSource))
	destSelectors := make([]uint64, 0, len(testConfig.ChainsAsDest))
	for _, chain := range testConfig.ChainsAsSource {
		chainSelector, _ := strconv.ParseUint(chain.Selector, 10, 64)
		selectors = append(selectors, chainSelector)
		srcSelectors = append(srcSelectors, chainSelector)
	}
	for _, chain := range testConfig.ChainsAsDest {
		chainSelector, _ := strconv.ParseUint(chain.Selector, 10, 64)
		selectors = append(selectors, chainSelector)
		destSelectors = append(destSelectors, chainSelector)
	}
	return &EVMTXGun{
		cfg:           cfg,
		testConfig:    testConfig,
		e:             e,
		selectors:     selectors,
		impl:          impls,
		sentMsgSet:    make(map[SentMessage]struct{}),
		sentMsgCh:     make(chan SentMessage, sentMessageChannelBufferSize),
		nonce:         make(map[uint64]*atomic.Uint64),
		srcSelectors:  srcSelectors,
		destSelectors: destSelectors,
	}
}

func (m *EVMTXGun) initNonce(chainSelector uint64) error {
	m.nonceMu.Lock()
	defer m.nonceMu.Unlock()

	if m.nonce[chainSelector] != nil {
		return nil
	}

	n, err := m.impl[chainSelector].GetUserNonce(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get pending nonce for selector %d: %w", chainSelector, err)
	}

	m.nonce[chainSelector] = &atomic.Uint64{}
	m.nonce[chainSelector].Store(n)
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

	fields, opts, err := m.selectMessageProfile(srcSelector, destSelector)
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("failed to select message profile: %w", err).Error(), Failed: true}
	}

	if err := m.initNonce(srcSelector); err != nil {
		return &wasp.Response{Error: err.Error(), Failed: true}
	}

	b := ccv.NewDefaultCLDFBundle(m.e)
	m.e.OperationsBundle = b

	c, ok := m.impl[srcSelector]
	if !ok {
		return &wasp.Response{Error: "impl is not CCIP17EVM", Failed: true}
	}

	sentEvent, err := c.SendMessageWithNonce(ctx, destSelector, fields, opts, m.nonce[srcSelector], true)
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("failed to send message: %w", err).Error(), Failed: true}
	}

	// Record the actual sequence number from the sent event
	m.seqNosMu.Lock()
	m.sentMsgSet[SentMessage{SeqNo: uint64(sentEvent.Message.SequenceNumber), MessageID: sentEvent.MessageID, SentTime: sentTime, ChainPair: SrcDest{Src: srcSelector, Dest: destSelector}}] = struct{}{}
	m.seqNosMu.Unlock()

	// Push to channel for verification
	m.sentMsgCh <- SentMessage{SeqNo: uint64(sentEvent.Message.SequenceNumber), MessageID: sentEvent.MessageID, SentTime: sentTime, ChainPair: SrcDest{Src: srcSelector, Dest: destSelector}}

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

func (m *EVMTXGun) selectMessageProfile(srcSelector, destSelector uint64) (cciptestinterfaces.MessageFields, cciptestinterfaces.MessageOptions, error) {
	mockReceiverRef, err := m.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			destSelector,
			datastore.ContractType(mock_receiver.ContractType),
			semver.MustParse(mock_receiver.Deploy.Version()),
			evm.DefaultReceiverQualifier))
	if err != nil {
		return cciptestinterfaces.MessageFields{}, cciptestinterfaces.MessageOptions{}, fmt.Errorf("could not find mock receiver address in datastore: %w", err)
	}

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
			datastore.ContractType(committee_verifier.ResolverType),
			semver.MustParse(committee_verifier.Deploy.Version()),
			evm.DefaultCommitteeVerifierQualifier))
	if err != nil {
		return cciptestinterfaces.MessageFields{}, cciptestinterfaces.MessageOptions{}, fmt.Errorf("could not find committee verifier proxy address in datastore: %w", err)
	}

	fields := cciptestinterfaces.MessageFields{
		Receiver: protocol.UnknownAddress(common.HexToAddress(mockReceiverRef.Address).Bytes()),
		Data:     []byte{},
		FeeToken: protocol.UnknownAddress(common.HexToAddress(wethContract.Address).Bytes()),
	}
	opts := cciptestinterfaces.MessageOptions{
		Version:        3,
		FinalityConfig: uint16(1),
		CCVs: []protocol.CCV{
			{
				CCVAddress: common.HexToAddress(committeeVerifierProxyRef.Address).Bytes(),
				Args:       []byte{},
				ArgsLen:    0,
			},
		},
	}
	return fields, opts, nil
}
