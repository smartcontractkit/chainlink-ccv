package e2e

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/weth"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	cldfevm "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/wasp"

	chainsel "github.com/smartcontractkit/chain-selectors"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
)

const sentMessageChannelBufferSize = 1000

// SentMessage represents a message that was sent and needs verification.
type SentMessage struct {
	SeqNo     uint64
	MessageID [32]byte
	SentTime  time.Time
}

type EVMTXGun struct {
	cfg        *ccv.Cfg
	e          *deployment.Environment
	selectors  []uint64
	impl       map[uint64]cciptestinterfaces.CCIP17ProductConfiguration
	src        cldfevm.Chain
	dest       cldfevm.Chain
	sentSeqNos []uint64
	sentTimes  map[uint64]time.Time
	msgIDs     map[uint64][32]byte
	seqNosMu   sync.Mutex
	sentMsgCh  chan SentMessage // Channel for real-time message notifications
	closeOnce  sync.Once        // Ensure channel is closed only once
	nonceMu    sync.Mutex
	nonce      *atomic.Int64
	nonceErr   error
}

// CloseSentChannel closes the sent messages channel to signal no more messages will be sent.
func (m *EVMTXGun) CloseSentChannel() {
	m.closeOnce.Do(func() {
		close(m.sentMsgCh)
	})
}

func NewEVMTransactionGun(cfg *ccv.Cfg, e *deployment.Environment, selectors []uint64, impls map[uint64]cciptestinterfaces.CCIP17ProductConfiguration, s, d cldfevm.Chain) *EVMTXGun {
	return &EVMTXGun{
		cfg:        cfg,
		e:          e,
		selectors:  selectors,
		impl:       impls,
		src:        s,
		dest:       d,
		sentSeqNos: make([]uint64, 0),
		sentTimes:  make(map[uint64]time.Time),
		msgIDs:     make(map[uint64][32]byte),
		sentMsgCh:  make(chan SentMessage, sentMessageChannelBufferSize),
	}
}

func (m *EVMTXGun) initNonce() error {
	m.nonceMu.Lock()
	defer m.nonceMu.Unlock()

	if m.nonce != nil {
		return nil
	}
	if m.nonceErr != nil {
		return m.nonceErr
	}

	nonce, err := m.src.Client.PendingNonceAt(context.Background(), m.src.DeployerKey.From)
	if err != nil {
		m.nonceErr = fmt.Errorf("failed to get pending nonce: %w", err)
		return m.nonceErr
	}
	m.nonce = &atomic.Int64{}
	m.nonce.Store(int64(nonce))
	return nil
}

// Call implements example gun call, assertions on response bodies should be done here.
func (m *EVMTXGun) Call(_ *wasp.Generator) *wasp.Response {
	if err := m.initNonce(); err != nil {
		return &wasp.Response{Error: err.Error(), Failed: true}
	}

	b := ccv.NewDefaultCLDFBundle(m.e)
	m.e.OperationsBundle = b
	ctx := context.Background()

	chainIDs := make([]string, 0)
	for _, bc := range m.cfg.Blockchains {
		chainIDs = append(chainIDs, bc.ChainID)
	}

	srcChain, err := chainsel.GetChainDetailsByChainIDAndFamily(chainIDs[0], chainsel.FamilyEVM)
	if err != nil {
		return &wasp.Response{Error: err.Error(), Failed: true}
	}
	dstChain, err := chainsel.GetChainDetailsByChainIDAndFamily(chainIDs[1], chainsel.FamilyEVM)
	if err != nil {
		return &wasp.Response{Error: err.Error(), Failed: true}
	}

	c, ok := m.impl[dstChain.ChainSelector].(*evm.CCIP17EVM)
	if !ok {
		return &wasp.Response{Error: "impl is not CCIP17EVM", Failed: true}
	}

	sentTime := time.Now()

	mockReceiverRef, err := m.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			dstChain.ChainSelector,
			datastore.ContractType(mock_receiver.ContractType),
			semver.MustParse(mock_receiver.Deploy.Version()),
			evm.DefaultReceiverQualifier))
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("could not find mock receiver address in datastore: %w", err).Error(), Failed: true}
	}
	committeeVerifierProxyRef, err := m.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			srcChain.ChainSelector,
			datastore.ContractType(committee_verifier.ResolverType),
			semver.MustParse(committee_verifier.Deploy.Version()),
			evm.DefaultCommitteeVerifierQualifier))
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("could not find committee verifier proxy address in datastore: %w", err).Error(), Failed: true}
	}

	wethContract, err := m.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			srcChain.ChainSelector,
			datastore.ContractType(weth.ContractType),
			semver.MustParse(weth.Deploy.Version()),
			""))
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("could not find WETH address in datastore: %w", err).Error(), Failed: true}
	}

	sentEvent, err := c.SendMessageWithNonce(ctx, dstChain.ChainSelector, cciptestinterfaces.MessageFields{
		Receiver: protocol.UnknownAddress(common.HexToAddress(mockReceiverRef.Address).Bytes()),
		Data:     []byte{},
		FeeToken: protocol.UnknownAddress(common.HexToAddress(wethContract.Address).Bytes()),
	}, cciptestinterfaces.MessageOptions{
		Version:        3,
		FinalityConfig: uint16(1),
		CCVs: []protocol.CCV{
			{
				CCVAddress: common.HexToAddress(committeeVerifierProxyRef.Address).Bytes(),
				Args:       []byte{},
				ArgsLen:    0,
			},
		},
	}, m.nonce, true)
	if err != nil {
		return &wasp.Response{Error: fmt.Errorf("failed to send message: %w", err).Error(), Failed: true}
	}

	// Record the actual sequence number from the sent event
	m.seqNosMu.Lock()
	m.sentSeqNos = append(m.sentSeqNos, uint64(sentEvent.Message.SequenceNumber))
	m.sentTimes[uint64(sentEvent.Message.SequenceNumber)] = sentTime
	m.msgIDs[uint64(sentEvent.Message.SequenceNumber)] = sentEvent.MessageID
	m.seqNosMu.Unlock()

	// Push to channel for verification
	m.sentMsgCh <- SentMessage{SeqNo: uint64(sentEvent.Message.SequenceNumber), MessageID: sentEvent.MessageID, SentTime: sentTime}

	return &wasp.Response{Data: "ok"}
}
