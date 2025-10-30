package ccv_evm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/link"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/weth"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/token_admin_registry"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/changesets"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/burn_mint_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/fee_quoter"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/sequences/tokens"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/erc20"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"

	chainsel "github.com/smartcontractkit/chain-selectors"
	routeroperations "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	offrampoperations "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/offramp"
	onrampoperations "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/onramp"
	routerwrapper "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_2_0/router"
	tokenscore "github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	changesetscore "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
)

const (
	// These qualifiers are used to distinguish between multiple deployments of the committee verifier proxy and mock receiver
	// on the same chain.
	// In the smoke test deployments these are the qualifiers that are used by default.
	DefaultCommitteeVerifierQualifier = "default"
	DefaultReceiverQualifier          = "default"

	SecondaryCommitteeVerifierQualifier = "secondary"
	SecondaryReceiverQualifier          = "secondary"

	TertiaryCommitteeVerifierQualifier = "tertiary"
	TertiaryReceiverQualifier          = "tertiary"

	QuaternaryReceiverQualifier = "quaternary"

	CommitteeVerifierGasForVerification = 500_000
)

var (
	ccipMessageSentTopic = onramp.OnRampCCIPMessageSent{}.Topic()

	// this is a hacky way to be able to programmatically generate the individual verifier
	// signing addresses for each qualifier.
	nodesPerCommittee = map[string]int{
		DefaultCommitteeVerifierQualifier:   2,
		SecondaryCommitteeVerifierQualifier: 2,
		TertiaryCommitteeVerifierQualifier:  2,
	}
)

type CCIP17EVM struct {
	e                      *deployment.Environment
	logger                 zerolog.Logger
	chainDetailsBySelector map[uint64]chainsel.ChainDetails
	ethClients             map[uint64]*ethclient.Client
	onRampBySelector       map[uint64]*onramp.OnRamp
	offRampBySelector      map[uint64]*offramp.OffRamp
}

// NewCCIP17EVM creates new smart-contracts wrappers with utility functions for CCIP17EVM implementation.
func NewCCIP17EVM(ctx context.Context, logger zerolog.Logger, e *deployment.Environment, chainIDs, wsURLs []string) (*CCIP17EVM, error) {
	if len(chainIDs) != len(wsURLs) {
		return nil, fmt.Errorf("len(chainIDs) != len(wsURLs) ; %d != %d", len(chainIDs), len(wsURLs))
	}

	gas := &GasSettings{
		FeeCapMultiplier: 2,
		TipCapMultiplier: 2,
	}
	var (
		chainDetailsBySelector = make(map[uint64]chainsel.ChainDetails)
		ethClients             = make(map[uint64]*ethclient.Client)
		onRampBySelector       = make(map[uint64]*onramp.OnRamp)
		offRampBySelector      = make(map[uint64]*offramp.OffRamp)
	)
	for i := range chainIDs {
		chainDetails, err := chainsel.GetChainDetailsByChainIDAndFamily(chainIDs[i], chainsel.FamilyEVM)
		if err != nil {
			return nil, fmt.Errorf("get chain details for chain %s: %w", chainIDs[i], err)
		}

		chainDetailsBySelector[chainDetails.ChainSelector] = chainDetails

		client, _, _, err := ETHClient(ctx, wsURLs[i], gas)
		if err != nil {
			return nil, fmt.Errorf("create eth client for chain %s: %w", chainIDs[i], err)
		}
		ethClients[chainDetails.ChainSelector] = client

		onRampAddressRef, err := e.DataStore.Addresses().Get(datastore.NewAddressRefKey(
			chainDetails.ChainSelector,
			datastore.ContractType(onrampoperations.ContractType),
			semver.MustParse(onrampoperations.Deploy.Version()),
			"",
		))
		if err != nil {
			return nil, fmt.Errorf("get on ramp address for chain %d (id %s) from datastore: %w", chainDetails.ChainSelector, chainIDs[i], err)
		}
		offRampAddressRef, err := e.DataStore.Addresses().Get(datastore.NewAddressRefKey(
			chainDetails.ChainSelector,
			datastore.ContractType(offrampoperations.ContractType),
			semver.MustParse(offrampoperations.Deploy.Version()),
			"",
		))
		if err != nil {
			return nil, fmt.Errorf("get off ramp address for chain %d (id %s) from datastore: %w", chainDetails.ChainSelector, chainIDs[i], err)
		}
		onRamp, err := onramp.NewOnRamp(common.HexToAddress(onRampAddressRef.Address), client)
		if err != nil {
			return nil, fmt.Errorf("create on ramp wrapper for chain %d (id %s): %w", chainDetails.ChainSelector, chainIDs[i], err)
		}
		offRamp, err := offramp.NewOffRamp(common.HexToAddress(offRampAddressRef.Address), client)
		if err != nil {
			return nil, fmt.Errorf("create off ramp wrapper for chain %d (id %s): %w", chainDetails.ChainSelector, chainIDs[i], err)
		}

		onRampBySelector[chainDetails.ChainSelector] = onRamp
		offRampBySelector[chainDetails.ChainSelector] = offRamp
	}

	return &CCIP17EVM{
		e:                      e,
		logger:                 logger,
		chainDetailsBySelector: chainDetailsBySelector,
		ethClients:             ethClients,
		onRampBySelector:       onRampBySelector,
		offRampBySelector:      offRampBySelector,
	}, nil
}

// fetchAllSentEventsBySelector fetch all CCIPMessageSent events from on ramp contract.
func (m *CCIP17EVM) fetchAllSentEventsBySelector(ctx context.Context, from, to uint64) ([]*onramp.OnRampCCIPMessageSent, error) {
	l := m.logger
	onRamp, ok := m.onRampBySelector[from]
	if !ok {
		return nil, fmt.Errorf("no on ramp for selector %d", from)
	}
	filter, err := onRamp.FilterCCIPMessageSent(&bind.FilterOpts{
		Context: ctx,
	}, []uint64{to}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create filter: %w", err)
	}
	defer func() {
		if err := filter.Close(); err != nil {
			l.Warn().Err(err).Msg("Failed to close filter")
		}
	}()

	var events []*onramp.OnRampCCIPMessageSent

	for filter.Next() {
		event := filter.Event
		events = append(events, event)

		l.Info().
			Any("TxHash", event.Raw.TxHash.Hex()).
			Any("SeqNo", event.SequenceNumber).
			Str("MsgID", hexutil.Encode(event.MessageId[:])).
			Msg("Found CCIPMessageSent event")
	}

	if err := filter.Error(); err != nil {
		return nil, fmt.Errorf("filter error: %w", err)
	}

	l.Info().Int("count", len(events)).Msg("Total CCIPMessageSent events found")
	return events, nil
}

// fetchAllExecEventsBySelector fetch all ExecutionStateChanged events from off ramp contract.
func (m *CCIP17EVM) fetchAllExecEventsBySelector(ctx context.Context, from, to uint64) ([]*offramp.OffRampExecutionStateChanged, error) {
	l := m.logger
	offRamp, ok := m.offRampBySelector[from]
	if !ok {
		return nil, fmt.Errorf("no off ramp for selector %d", from)
	}
	filter, err := offRamp.FilterExecutionStateChanged(&bind.FilterOpts{
		Context: ctx,
	}, []uint64{to}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create filter: %w", err)
	}
	defer func() {
		if err := filter.Close(); err != nil {
			l.Warn().Err(err).Msg("Failed to close filter")
		}
	}()

	var events []*offramp.OffRampExecutionStateChanged

	for filter.Next() {
		event := filter.Event
		events = append(events, event)

		l.Info().
			Any("State", event.State).
			Any("TxHash", event.Raw.TxHash.Hex()).
			Any("SeqNo", event.SequenceNumber).
			Str("MsgID", hexutil.Encode(event.MessageId[:])).
			Str("Error", hexutil.Encode(filter.Event.ReturnData)).
			Msg("Found ExecutionStateChanged event")
	}

	if err := filter.Error(); err != nil {
		return nil, fmt.Errorf("filter error: %w", err)
	}

	l.Info().Int("count", len(events)).Msg("Total ExecutionStateChanged events found for selector and sequence")
	return events, nil
}

func (m *CCIP17EVM) GetExpectedNextSequenceNumber(ctx context.Context, from, to uint64) (uint64, error) {
	p, ok := m.onRampBySelector[from]
	if !ok {
		return 0, fmt.Errorf("failed to assert onRamp by selector")
	}
	return p.GetExpectedNextSequenceNumber(&bind.CallOpts{Context: ctx}, to)
}

// WaitOneSentEventBySeqNo wait and fetch strictly one CCIPMessageSent event by selector and sequence number and selector.
func (m *CCIP17EVM) WaitOneSentEventBySeqNo(ctx context.Context, from, to, seq uint64, timeout time.Duration) (cciptestinterfaces.MessageSentEvent, error) {
	l := m.logger
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	onRamp, ok := m.onRampBySelector[from]
	if !ok {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("no onRamp for selector %d", from)
	}

	l.Info().Msg("Awaiting CCIPMessageSent event")

	for {
		select {
		case <-ctx.Done():
			return cciptestinterfaces.MessageSentEvent{}, ctx.Err()
		case <-ticker.C:
			filter, err := onRamp.FilterCCIPMessageSent(&bind.FilterOpts{}, []uint64{to}, []uint64{seq}, nil)
			if err != nil {
				l.Warn().Err(err).Msg("Failed to create filter")
				continue
			}
			var eventFound *onramp.OnRampCCIPMessageSent
			eventCount := 0

			for filter.Next() {
				eventCount++
				if eventCount > 1 {
					if err := filter.Close(); err != nil {
						l.Warn().Err(err).Msg("Failed to close filter")
					}
					return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("received multiple events for the same sequence number and selector")
				}
				eventFound = filter.Event
				l.Info().
					Any("TxHash", filter.Event.Raw.TxHash.Hex()).
					Any("SeqNo", filter.Event.SequenceNumber).
					Str("MsgID", hexutil.Encode(filter.Event.MessageId[:])).
					Msg("Received CCIPMessageSent event")
			}
			if err := filter.Error(); err != nil {
				l.Warn().Err(err).Msg("Filter error")
			}
			if err := filter.Close(); err != nil {
				l.Warn().Err(err).Msg("Failed to close filter")
			}
			if eventFound != nil {
				message, err := protocol.DecodeMessage(eventFound.EncodedMessage)
				if err != nil {
					return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to decode message: %w", err)
				}
				ev := cciptestinterfaces.MessageSentEvent{
					MessageID:      eventFound.MessageId,
					SequenceNumber: eventFound.SequenceNumber,
					Message:        message,
					ReceiptIssuers: make([]protocol.UnknownAddress, 0, len(eventFound.Receipts)),
					VerifierBlobs:  eventFound.VerifierBlobs,
				}
				for _, receipt := range eventFound.Receipts {
					ev.ReceiptIssuers = append(ev.ReceiptIssuers, protocol.UnknownAddress(receipt.Issuer.Bytes()))
				}
				return ev, nil
			}
		}
	}
}

// WaitOneExecEventBySeqNo wait and fetch strictly one ExecutionStateChanged event by sequence number and selector.
func (m *CCIP17EVM) WaitOneExecEventBySeqNo(ctx context.Context, from, to, seq uint64, timeout time.Duration) (cciptestinterfaces.ExecutionStateChangedEvent, error) {
	l := m.logger
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	offRamp, ok := m.offRampBySelector[to]
	if !ok {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("no off ramp for selector %d", to)
	}

	l.Info().Msg("Awaiting ExecutionStateChanged event")

	for {
		select {
		case <-ctx.Done():
			return cciptestinterfaces.ExecutionStateChangedEvent{}, ctx.Err()
		case <-ticker.C:
			filter, err := offRamp.FilterExecutionStateChanged(&bind.FilterOpts{}, []uint64{from}, []uint64{seq}, nil)
			if err != nil {
				l.Warn().Err(err).Msg("Failed to create filter")
				continue
			}

			var eventFound *offramp.OffRampExecutionStateChanged
			eventCount := 0

			for filter.Next() {
				eventCount++
				if eventCount > 1 {
					if err := filter.Close(); err != nil {
						l.Warn().Err(err).Msg("Failed to close filter")
					}
					return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("received multiple events for the same sequence number and selector")
				}

				eventFound = filter.Event
				l.Info().
					Any("State", filter.Event.State).
					Any("TxHash", filter.Event.Raw.TxHash.Hex()).
					Any("SeqNo", filter.Event.SequenceNumber).
					Str("MsgID", hexutil.Encode(filter.Event.MessageId[:])).
					Msg("Received ExecutionStateChanged event")
			}

			if err := filter.Error(); err != nil {
				l.Warn().Err(err).Msg("Filter error")
			}

			if err := filter.Close(); err != nil {
				l.Warn().Err(err).Msg("Failed to close filter")
			}

			if eventFound != nil {
				return cciptestinterfaces.ExecutionStateChangedEvent{
					MessageID:      eventFound.MessageId,
					SequenceNumber: eventFound.SequenceNumber,
					State:          cciptestinterfaces.MessageExecutionState(eventFound.State),
					ReturnData:     eventFound.ReturnData,
				}, nil
			}
		}
	}
}

func (m *CCIP17EVM) GetEOAReceiverAddress(chainSelector uint64) (protocol.UnknownAddress, error) {
	_, ok := m.e.BlockChains.EVMChains()[chainSelector]
	if !ok {
		return protocol.UnknownAddress{}, fmt.Errorf("chain %d not found in environment chains %v", chainSelector, m.e.BlockChains.EVMChains())
	}

	// returns the same address for each chain for now - we might need to extend this in the future if we'd ever
	// need to access any funds on the EOA itself.
	return protocol.UnknownAddress(common.HexToAddress("0x3Aa5ebB10DC797CAC828524e59A333d0A371443d").Bytes()), nil
}

func (m *CCIP17EVM) GetTokenBalance(ctx context.Context, chainSelector uint64, address, tokenAddress protocol.UnknownAddress) (*big.Int, error) {
	chain, ok := m.e.BlockChains.EVMChains()[chainSelector]
	if !ok {
		return nil, fmt.Errorf("chain %d not found in environment chains %v", chainSelector, m.e.BlockChains.EVMChains())
	}
	tkn, err := erc20.NewERC20(common.HexToAddress(tokenAddress.String()), chain.Client)
	if err != nil {
		return nil, fmt.Errorf("failed to create erc20 wrapper: %w", err)
	}
	balance, err := tkn.BalanceOf(&bind.CallOpts{Context: ctx}, common.HexToAddress(address.String()))
	if err != nil {
		return nil, fmt.Errorf("failed to get balance: %w", err)
	}
	return balance, nil
}

// ensureERC20HasBalanceAndAllowance ensures that the given owner has at least `amount`
// balance of `token` and that `spender` has at least `amount` allowance.
func (m *CCIP17EVM) ensureERC20HasBalanceAndAllowance(
	ctx context.Context,
	chain evm.Chain,
	auth *bind.TransactOpts,
	token, owner, spender common.Address,
	amount *big.Int,
) (bool, error) {
	tkn, err := erc20.NewERC20(token, chain.Client)
	if err != nil {
		return false, fmt.Errorf("failed to create erc20 wrapper: %w", err)
	}
	balance, err := tkn.BalanceOf(&bind.CallOpts{Context: ctx}, owner)
	if err != nil {
		return false, fmt.Errorf("failed to get balance: %w", err)
	}
	if balance.Cmp(amount) < 0 {
		return false, fmt.Errorf("insufficient balance: have %s, need %s", balance.String(), amount.String())
	}
	allowance, err := tkn.Allowance(&bind.CallOpts{Context: ctx}, owner, spender)
	if err != nil {
		return false, fmt.Errorf("failed to get allowance: %w", err)
	}
	if allowance.Cmp(amount) < 0 {
		l := m.logger
		l.Info().
			Str("Token", token.Hex()).
			Str("Spender", spender.Hex()).
			Str("Owner", owner.Hex()).
			Str("Amount", amount.String()).
			Msg("Insufficient allowance, approving")
		tx, err := tkn.Approve(&bind.TransactOpts{
			Context: ctx,
			From:    auth.From,
			Signer:  auth.Signer,
		}, spender, amount)
		if err != nil {
			return false, fmt.Errorf("failed to approve spending of %s for %s: %w", amount.String(), spender.Hex(), err)
		}
		l.Info().Str("TxHash", tx.Hash().Hex()).Msg("Waiting for approve transaction to be mined")
		receipt, err := bind.WaitMined(ctx, chain.Client, tx.Hash())
		if err != nil {
			return false, fmt.Errorf("failed to wait for approve transaction to be mined: %w", err)
		}
		if receipt.Status != types.ReceiptStatusSuccessful {
			return false, fmt.Errorf("approve transaction failed: %s", receipt.TxHash.Hex())
		}
		l.Info().Msg("Approval successful")
	}
	return true, nil
}

func (m *CCIP17EVM) haveEnoughTransferTokens(ctx context.Context, chain evm.Chain, auth *bind.TransactOpts, routerAddress, token common.Address, amount *big.Int) (hasEnough bool, err error) {
	// Transfer token is a vanilla ERC20; check owner's balance and router's allowance.
	return m.ensureERC20HasBalanceAndAllowance(ctx, chain, auth, token, chain.DeployerKey.From, routerAddress, amount)
}

func (m *CCIP17EVM) haveEnoughFeeTokens(ctx context.Context, chain evm.Chain, auth *bind.TransactOpts, routerAddress, feeToken common.Address, amount *big.Int) (hasEnough bool, msgValue *big.Int, err error) {
	wrappedNativeRef, err := m.e.DataStore.Addresses().Get(datastore.NewAddressRefKey(chain.Selector, datastore.ContractType(weth.ContractType), semver.MustParse(weth.Deploy.Version()), ""))
	if err != nil {
		return false, nil, fmt.Errorf("failed to get wrapped native address: %w", err)
	}
	linkRef, err := m.e.DataStore.Addresses().Get(datastore.NewAddressRefKey(chain.Selector, datastore.ContractType(link.ContractType), semver.MustParse(link.Deploy.Version()), ""))
	if err != nil {
		return false, nil, fmt.Errorf("failed to get link address: %w", err)
	}
	wrappedNative := common.HexToAddress(wrappedNativeRef.Address)
	link := common.HexToAddress(linkRef.Address)
	// TODO: should check if fee token is enabled somehow? Check feeQuoter contract?
	switch feeToken {
	case common.Address{}:
		// if no fee token is specified, pure native token is used, so this is just a BalanceAt check.
		balance, err := chain.Client.BalanceAt(ctx, chain.DeployerKey.From, nil)
		if err != nil {
			return false, nil, fmt.Errorf("failed to get balance: %w", err)
		}
		// msg.Value is equal to amount in the native token case
		return balance.Cmp(amount) >= 0, amount, nil
	case wrappedNative, link:
		ok, err := m.ensureERC20HasBalanceAndAllowance(ctx, chain, auth, feeToken, chain.DeployerKey.From, routerAddress, amount)
		if err != nil {
			return false, nil, err
		}
		if !ok {
			return false, nil, nil
		}
		return true, big.NewInt(0), nil
	default:
		return false, nil, fmt.Errorf("unsupported fee token: %s", feeToken.String())
	}
}

func (m *CCIP17EVM) SendMessage(ctx context.Context, src, dest uint64, fields cciptestinterfaces.MessageFields, opts cciptestinterfaces.MessageOptions) (cciptestinterfaces.MessageSentEvent, error) {
	l := m.logger
	chains := m.e.BlockChains.EVMChains()
	if chains == nil {
		return cciptestinterfaces.MessageSentEvent{}, errors.New("no EVM chains found")
	}

	srcChain, ok := chains[src]
	if !ok {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("source chain %d not found in environment chains %v", src, chains)
	}

	destFamily, err := chainsel.GetSelectorFamily(dest)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get destination family: %w", err)
	}

	routerRef, err := m.e.DataStore.Addresses().Get(datastore.NewAddressRefKey(srcChain.Selector, datastore.ContractType(routeroperations.ContractType), semver.MustParse("1.2.0"), ""))
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get router address: %w", err)
	}

	routerAddress := common.HexToAddress(routerRef.Address)
	rout, err := routerwrapper.NewRouter(routerAddress, srcChain.Client)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("create router wrapper: %w", err)
	}

	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		m.e.Logger,
		operations.NewMemoryReporter(),
	)

	tokenAmounts := make([]routeroperations.EVMTokenAmount, 0, len(fields.TokenAmounts))
	for _, tokenAmount := range fields.TokenAmounts {
		tokenAmounts = append(tokenAmounts, routeroperations.EVMTokenAmount{
			Token:  common.HexToAddress(tokenAmount.TokenAddress.String()),
			Amount: tokenAmount.Amount,
		})
	}
	if len(tokenAmounts) > 1 {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("only one token amount is supported")
	}

	extraArgs := serializeExtraArgs(opts, destFamily)
	msg := routerwrapper.ClientEVM2AnyMessage{
		Receiver:     common.LeftPadBytes(common.HexToAddress(fields.Receiver.String()).Bytes(), 32),
		Data:         fields.Data,
		TokenAmounts: tokenAmounts,
		FeeToken:     common.HexToAddress(fields.FeeToken.String()),
		ExtraArgs:    extraArgs,
	}
	fee, err := rout.GetFee(
		&bind.CallOpts{
			Context: ctx,
		}, dest,
		msg,
	)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get fee: %w", err)
	}

	haveEnoughFeeTokens, msgValue, err := m.haveEnoughFeeTokens(ctx, srcChain, srcChain.DeployerKey, routerAddress, common.HexToAddress(fields.FeeToken.String()), fee)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to check if have enough tokens: %w", err)
	}
	if !haveEnoughFeeTokens {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("not enough tokens to send message, feeToken: %s, fee: %s, msgValue: %s", fields.FeeToken.String(), fee.String(), msgValue.String())
	}

	if len(tokenAmounts) > 0 {
		haveEnoughTransferTokens, err := m.haveEnoughTransferTokens(ctx, srcChain, srcChain.DeployerKey, routerAddress, common.HexToAddress(tokenAmounts[0].Token.String()), tokenAmounts[0].Amount)
		if err != nil {
			return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to check if have enough tokens: %w", err)
		}
		if !haveEnoughTransferTokens {
			return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("not enough tokens to send in a message, token: %s, amount: %s", tokenAmounts[0].Token.String(), tokenAmounts[0].Amount.String())
		}
	}

	l.Info().
		Str("FeeToken", fields.FeeToken.String()).
		Str("Amount", fee.String()).
		Str("MsgValue", msgValue.String()).
		Msg("Have enough tokens to send message")

	ccipSendArgs := routeroperations.CCIPSendArgs{
		Value:             msgValue,
		DestChainSelector: dest,
		EVM2AnyMessage:    msg,
	}

	// Send CCIP message with value
	sendReport, err := operations.ExecuteOperation(bundle, routeroperations.CCIPSend, srcChain, contract.FunctionInput[routeroperations.CCIPSendArgs]{
		ChainSelector: src,
		Address:       routerAddress,
		Args:          ccipSendArgs,
	})
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to send CCIP message: %w, extraArgs: %x", err, extraArgs)
	}

	// get the receipt so that we can log the message ID.
	receipt, err := srcChain.Client.TransactionReceipt(ctx, common.HexToHash(sendReport.Output.ExecInfo.Hash))
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	var messageSentEvent *onramp.OnRampCCIPMessageSent
	for _, log := range receipt.Logs {
		if log.Topics[0] == ccipMessageSentTopic {
			var err error
			messageSentEvent, err = m.onRampBySelector[src].ParseCCIPMessageSent(*log)
			if err != nil {
				// Don't fail the entire test just because of this but do log a warning.
				l.Warn().Err(err).Msg("Failed to parse CCIPMessageSent event")
				continue
			}
			break
		}
	}
	dcc, err := m.onRampBySelector[src].GetDestChainConfig(&bind.CallOpts{
		Context: ctx,
	}, dest)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to get dest chain config: %w", err)
	}

	message, err := protocol.DecodeMessage(messageSentEvent.EncodedMessage)
	if err != nil {
		// Fail here - indicates a bug in the decoder which is critical.
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to decode message: %w", err)
	}
	result := cciptestinterfaces.MessageSentEvent{
		MessageID:      messageSentEvent.MessageId,
		SequenceNumber: messageSentEvent.SequenceNumber,
		Message:        message,
		ReceiptIssuers: make([]protocol.UnknownAddress, 0, len(messageSentEvent.Receipts)),
		VerifierBlobs:  messageSentEvent.VerifierBlobs,
	}
	for _, receipt := range messageSentEvent.Receipts {
		result.ReceiptIssuers = append(result.ReceiptIssuers, protocol.UnknownAddress(receipt.Issuer.Bytes()))
	}

	l.Info().
		Bool("Executed", sendReport.Output.Executed()).
		Uint64("SrcChainSelector", sendReport.Output.ChainSelector).
		Uint64("DestChainSelector", dest).
		Str("SrcRouter", sendReport.Output.Tx.To).
		Str("MessageID", hexutil.Encode(result.MessageID[:])).
		Any("DefaultCCVs", dcc.DefaultCCVs).
		Any("LaneMandatedCCVs", dcc.LaneMandatedCCVs).
		Any("DefaultExecutor", dcc.DefaultExecutor).
		Any("OffRamp", hexutil.Encode(dcc.OffRamp)).
		Int("NumReceipts", len(result.ReceiptIssuers)).
		Int("NumVerifierBlobs", len(result.VerifierBlobs)).
		Any("ReceiptIssuers", result.ReceiptIssuers).
		Uint64("SeqNo", result.SequenceNumber).
		Msg("CCIP message sent")

	return result, nil
}

func serializeExtraArgs(opts cciptestinterfaces.MessageOptions, destFamily string) []byte {
	switch destFamily {
	case chainsel.FamilyEVM:
		switch opts.Version {
		case 1: // EVMExtraArgsV1
			return serializeExtraArgsV1(opts)
		case 2: // GenericExtraArgsV2
			return serializeExtraArgsV2(opts)
		case 3: // EVMExtraArgsV3
			return serializeExtraArgsV3(opts)
		default:
			panic(fmt.Sprintf("unsupported message extra args version: %d", opts.Version))
		}
	case chainsel.FamilySolana:
		switch opts.Version {
		case 1: // SVMExtraArgsV1
			return serializeExtraArgsSVMV1(opts)
		default:
			panic(fmt.Sprintf("unsupported message extra args version for family %s: %d", destFamily, opts.Version))
		}
	default:
		panic(fmt.Sprintf("unsupported destination family: %s", destFamily))
	}
}

func serializeExtraArgsV1(opts cciptestinterfaces.MessageOptions) []byte {
	evmExtraArgsV1Type, err := abi.NewType("tuple", "EVMExtraArgsV1", []abi.ArgumentMarshaling{
		{Name: "gasLimit", Type: "uint256"},
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create EVMExtraArgsV1 tuple type: %v", err))
	}

	arguments := abi.Arguments{
		{
			Type: evmExtraArgsV1Type,
			Name: "extraArgs",
		},
	}

	type EVMExtraArgsV1 struct {
		GasLimit *big.Int
	}

	packed, err := arguments.Pack(EVMExtraArgsV1{GasLimit: big.NewInt(int64(opts.GasLimit))})
	if err != nil {
		panic(fmt.Sprintf("failed to pack extraArgs: %v", err))
	}

	selector, _ := hexutil.Decode("0x97a657c9")
	return append(selector, packed...)
}

func serializeExtraArgsV2(opts cciptestinterfaces.MessageOptions) []byte {
	genericExtraArgsV2Type, err := abi.NewType("tuple", "GenericExtraArgsV2", []abi.ArgumentMarshaling{
		{Name: "gasLimit", Type: "uint256"},
		{Name: "allowOutOfOrderExecution", Type: "bool"},
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create GenericExtraArgsV2 tuple type: %v", err))
	}

	arguments := abi.Arguments{
		{
			Type: genericExtraArgsV2Type,
			Name: "extraArgs",
		},
	}

	type GenericExtraArgsV2 struct {
		GasLimit                 *big.Int
		AllowOutOfOrderExecution bool
	}

	packed, err := arguments.Pack(GenericExtraArgsV2{
		GasLimit:                 big.NewInt(int64(opts.GasLimit)),
		AllowOutOfOrderExecution: opts.OutOfOrderExecution,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to pack extraArgs: %v", err))
	}

	selector, _ := hexutil.Decode("0x181dcf10")
	return append(selector, packed...)
}

func serializeExtraArgsV3(opts cciptestinterfaces.MessageOptions) []byte {
	extraArgs, err := NewV3ExtraArgs(
		opts.FinalityConfig,
		opts.Executor.String(),
		opts.ExecutorArgs,
		opts.TokenArgs,
		opts.CCVs,
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create V3 extra args: %v", err))
	}
	return extraArgs
}

func serializeExtraArgsSVMV1(_ cciptestinterfaces.MessageOptions) []byte {
	// // Extra args tag for chains that use the Solana VM.
	// bytes4 public constant SVM_EXTRA_ARGS_V1_TAG = 0x1f3b3aba;

	// struct SVMExtraArgsV1 {
	//   uint32 computeUnits;
	//   uint64 accountIsWritableBitmap;
	//   bool allowOutOfOrderExecution;
	//   bytes32 tokenReceiver;
	//   // Additional accounts needed for execution of CCIP receiver. Must be empty if message.receiver is zero.
	//   // Token transfer related accounts are specified in the token pool lookup table on SVM.
	//   bytes32[] accounts;
	// }
	return nil // TODO: implement when solana ported to 1.7 tests.
}

func (m *CCIP17EVM) ExposeMetrics(
	ctx context.Context,
	source, dest uint64,
	chainIDs []string,
	wsURLs []string,
) ([]string, *prometheus.Registry, error) {
	msgSentTotal.Reset()
	msgExecTotal.Reset()
	srcDstLatency.Reset()

	reg := prometheus.NewRegistry()
	reg.MustRegister(msgSentTotal, msgExecTotal, srcDstLatency)

	lp := NewLokiPusher()
	tp := NewTempoPusher()
	c, err := NewCCIP17EVM(ctx, m.logger, m.e, chainIDs, wsURLs)
	if err != nil {
		return nil, nil, err
	}
	err = ProcessLaneEvents(ctx, c, lp, tp, &LaneStreamConfig{
		FromSelector:      source,
		ToSelector:        dest,
		AggregatorAddress: "localhost:50051",
		AggregatorSince:   0,
	})
	if err != nil {
		return nil, nil, err
	}
	err = ProcessLaneEvents(ctx, c, lp, tp, &LaneStreamConfig{
		FromSelector:      dest,
		ToSelector:        source,
		AggregatorAddress: "localhost:50051",
		AggregatorSince:   0,
	})
	if err != nil {
		return nil, nil, err
	}
	return []string{}, reg, nil
}

func (m *CCIP17EVM) DeployLocalNetwork(ctx context.Context, bc *blockchain.Input) (*blockchain.Output, error) {
	l := m.logger
	l.Info().Msg("Deploying EVM networks")
	out, err := blockchain.NewBlockchainNetwork(bc)
	if err != nil {
		return nil, fmt.Errorf("failed to create blockchain network: %w", err)
	}
	return out, nil
}

func (m *CCIP17EVM) ConfigureNodes(ctx context.Context, bc *blockchain.Input) (string, error) {
	l := m.logger
	l.Info().Msg("Configuring CL nodes")
	name := fmt.Sprintf("node-evm-%s", uuid.New().String()[0:5])
	finality := 1
	return fmt.Sprintf(`
       [[EVM]]
       LogPollInterval = '1s'
       BlockBackfillDepth = 100
       ChainID = '%s'
       MinIncomingConfirmations = 1
       MinContractPayment = '0.0000001 link'
       FinalityDepth = %d

       [[EVM.Nodes]]
       Name = '%s'
       WsUrl = '%s'
       HttpUrl = '%s'`,
		bc.ChainID,
		finality,
		name,
		bc.Out.Nodes[0].InternalWSUrl,
		bc.Out.Nodes[0].InternalHTTPUrl,
	), nil
}

// getCommitteeSignatureConfig returns the committee signature configuration for a given qualifier.
// The signer addresses are programmatically generated in an identical to fashion to what is done in
// NewEnvironment to avoid hardcoding hard-to-determine addresses in the code.
func getCommitteeSignatureConfig(qualifier string) committee_verifier.SetSignatureConfigArgs {
	numNodes, ok := nodesPerCommittee[qualifier]
	if !ok {
		panic(fmt.Sprintf("couldn't find verifier indexes for qualifier: %s", qualifier))
	}
	signerAddresses := make([]common.Address, 0, numNodes)
	for i := range numNodes {
		privKeyString := cciptestinterfaces.XXXNewVerifierPrivateKey(qualifier, i)
		privateKeyBytes, err := commit.ReadPrivateKeyFromString(privKeyString)
		if err != nil {
			panic(fmt.Sprintf("failed to read private key: %v", err))
		}
		signer, err := commit.NewECDSAMessageSigner(privateKeyBytes)
		if err != nil {
			panic(fmt.Sprintf("failed to create ECDSA message signer: %v", err))
		}
		signerAddresses = append(signerAddresses, common.HexToAddress(signer.GetSignerAddress().String()))
	}
	return committee_verifier.SetSignatureConfigArgs{
		Threshold: uint8(numNodes), //nolint:gosec
		Signers:   signerAddresses,
	}
}

func (m *CCIP17EVM) DeployContractsForSelector(ctx context.Context, env *deployment.Environment, selector uint64) (datastore.DataStore, error) {
	l := m.logger
	l.Info().Msg("Configuring contracts for selector")
	l.Info().Any("Selector", selector).Msg("Deploying for chain selectors")
	runningDS := datastore.NewMemoryDataStore()

	l.Info().Uint64("Selector", selector).Msg("Configuring per-chain contracts bundle")
	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		env.Logger,
		operations.NewMemoryReporter(),
	)
	env.OperationsBundle = bundle

	usdPerLink, ok := new(big.Int).SetString("15000000000000000000", 10) // $15
	if !ok {
		return nil, errors.New("failed to parse USDPerLINK")
	}
	usdPerWeth, ok := new(big.Int).SetString("2000000000000000000000", 10) // $2000
	if !ok {
		return nil, errors.New("failed to parse USDPerWETH")
	}

	chain, ok := env.BlockChains.EVMChains()[selector]
	if !ok {
		return nil, fmt.Errorf("evm chain not found for selector %d", selector)
	}

	mcmsReaderRegistry := changesetscore.NewMCMSReaderRegistry() // TODO: Integrate actual registry if MCMS support is required.
	out, err := changesets.DeployChainContracts(mcmsReaderRegistry).Apply(*env, changesetscore.WithMCMS[changesets.DeployChainContractsCfg]{
		Cfg: changesets.DeployChainContractsCfg{
			ChainSel: selector,
			Params: sequences.ContractParams{
				// TODO: Router contract implementation is missing
				RMNRemote: sequences.RMNRemoteParams{
					Version: semver.MustParse(rmn_remote.Deploy.Version()),
				},
				OffRamp: sequences.OffRampParams{
					Version: semver.MustParse(offrampoperations.Deploy.Version()),
				},
				// Deploy multiple committee verifiers in order to test different receiver
				// configurations.
				CommitteeVerifier: []sequences.CommitteeVerifierParams{
					{
						Version: semver.MustParse(committee_verifier.Deploy.Version()),
						// TODO: add mocked contract here
						FeeAggregator:       common.HexToAddress("0x01"),
						SignatureConfigArgs: getCommitteeSignatureConfig(DefaultCommitteeVerifierQualifier),
						Qualifier:           DefaultCommitteeVerifierQualifier,
					},
					// TODO: deploy the offchain verifiers that correspond to these contracts.
					{
						Version: semver.MustParse(committee_verifier.Deploy.Version()),
						// TODO: add mocked contract here
						FeeAggregator:       common.HexToAddress("0x01"),
						SignatureConfigArgs: getCommitteeSignatureConfig(SecondaryCommitteeVerifierQualifier),
						Qualifier:           SecondaryCommitteeVerifierQualifier,
					},
					{
						Version: semver.MustParse(committee_verifier.Deploy.Version()),
						// TODO: add mocked contract here
						FeeAggregator:       common.HexToAddress("0x01"),
						SignatureConfigArgs: getCommitteeSignatureConfig(TertiaryCommitteeVerifierQualifier),
						Qualifier:           TertiaryCommitteeVerifierQualifier,
					},
				},
				OnRamp: sequences.OnRampParams{
					Version:       semver.MustParse(onrampoperations.Deploy.Version()),
					FeeAggregator: common.HexToAddress("0x01"),
				},
				Executor: sequences.ExecutorParams{
					Version:       semver.MustParse(executor.Deploy.Version()),
					MaxCCVsPerMsg: 10,
				},
				FeeQuoter: sequences.FeeQuoterParams{
					Version: semver.MustParse(fee_quoter.Deploy.Version()),
					// expose in TOML config
					MaxFeeJuelsPerMsg:              big.NewInt(2e18),
					LINKPremiumMultiplierWeiPerEth: 9e17, // 0.9 ETH
					WETHPremiumMultiplierWeiPerEth: 1e18, // 1.0 ETH
					USDPerLINK:                     usdPerLink,
					USDPerWETH:                     usdPerWeth,
				},
				MockReceivers: []sequences.MockReceiverParams{
					{
						// single required verifier (default), no optional verifiers, no optional threshold
						Version: semver.MustParse(mock_receiver.Deploy.Version()),
						RequiredVerifiers: []datastore.AddressRef{
							{
								Type:          datastore.ContractType(committee_verifier.ProxyType),
								Version:       semver.MustParse(committee_verifier.Deploy.Version()),
								ChainSelector: selector,
								Qualifier:     DefaultCommitteeVerifierQualifier,
							},
						},
						Qualifier: DefaultReceiverQualifier,
					},
					{
						// single required verifier (secondary), no optional verifiers, no optional threshold
						Version: semver.MustParse(mock_receiver.Deploy.Version()),
						RequiredVerifiers: []datastore.AddressRef{
							{
								Type:          datastore.ContractType(committee_verifier.ProxyType),
								Version:       semver.MustParse(committee_verifier.Deploy.Version()),
								ChainSelector: selector,
								Qualifier:     SecondaryCommitteeVerifierQualifier,
							},
						},
						Qualifier: SecondaryReceiverQualifier,
					},
					{
						// single required verifier (secondary), single optional verifier (tertiary), optional threshold=1
						// this means that the message should only be executed after the required and optional verifiers have signed.
						// optional threshold being 1, with one optional, means that it must be retrieved.
						Version: semver.MustParse(mock_receiver.Deploy.Version()),
						RequiredVerifiers: []datastore.AddressRef{
							{
								Type:          datastore.ContractType(committee_verifier.ProxyType),
								Version:       semver.MustParse(committee_verifier.Deploy.Version()),
								ChainSelector: selector,
								Qualifier:     SecondaryCommitteeVerifierQualifier,
							},
						},
						OptionalVerifiers: []datastore.AddressRef{
							{
								Type:          datastore.ContractType(committee_verifier.ProxyType),
								Version:       semver.MustParse(committee_verifier.Deploy.Version()),
								ChainSelector: selector,
								Qualifier:     TertiaryCommitteeVerifierQualifier,
							},
						},
						OptionalThreshold: 1,
						Qualifier:         TertiaryReceiverQualifier,
					},
					{
						Version: semver.MustParse(mock_receiver.Deploy.Version()),
						RequiredVerifiers: []datastore.AddressRef{
							{
								Type:          datastore.ContractType(committee_verifier.ProxyType),
								Version:       semver.MustParse(committee_verifier.Deploy.Version()),
								ChainSelector: selector,
								Qualifier:     DefaultCommitteeVerifierQualifier,
							},
						},
						OptionalVerifiers: []datastore.AddressRef{
							{
								Type:          datastore.ContractType(committee_verifier.ProxyType),
								Version:       semver.MustParse(committee_verifier.Deploy.Version()),
								ChainSelector: selector,
								Qualifier:     SecondaryCommitteeVerifierQualifier,
							},
							{
								Type:          datastore.ContractType(committee_verifier.ProxyType),
								Version:       semver.MustParse(committee_verifier.Deploy.Version()),
								ChainSelector: selector,
								Qualifier:     TertiaryCommitteeVerifierQualifier,
							},
						},
						OptionalThreshold: 1,
						Qualifier:         QuaternaryReceiverQualifier,
					},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	err = runningDS.Merge(out.DataStore.Seal())
	if err != nil {
		return nil, err
	}
	env.DataStore = runningDS.Seal()

	// Deploy token & token pool, minting funds to the chain's deployer key.
	maxSupply, ok := big.NewInt(0).SetString("100000000000000000000000000000", 10) // 100 billion tokens
	if !ok {
		return nil, errors.New("failed to parse max supply")
	}
	deployerBalance, ok := big.NewInt(0).SetString("1000000000000000000000000000", 10) // 1 billion tokens
	if !ok {
		return nil, errors.New("failed to parse deployer balance")
	}
	out, err = changesets.DeployBurnMintTokenAndPool(mcmsReaderRegistry).Apply(*env, changesetscore.WithMCMS[changesets.DeployBurnMintTokenAndPoolCfg]{
		Cfg: changesets.DeployBurnMintTokenAndPoolCfg{
			Accounts: map[common.Address]*big.Int{
				chain.DeployerKey.From: deployerBalance,
			},
			TokenInfo: tokens.TokenInfo{
				Name:      "Test Token",
				Decimals:  18,
				MaxSupply: maxSupply,
			},
			DeployTokenPoolCfg: changesets.DeployTokenPoolCfg{
				ChainSel:           selector,
				TokenPoolType:      datastore.ContractType(burn_mint_token_pool.ContractType),
				TokenPoolVersion:   semver.MustParse("1.7.0"),
				TokenSymbol:        "TEST",
				LocalTokenDecimals: 18,
				Router: datastore.AddressRef{
					Type:    datastore.ContractType(routeroperations.ContractType),
					Version: semver.MustParse("1.2.0"),
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	err = runningDS.Merge(out.DataStore.Seal())
	if err != nil {
		return nil, err
	}
	env.DataStore = runningDS.Seal()

	return runningDS.Seal(), nil
}

func (m *CCIP17EVM) ConnectContractsWithSelectors(ctx context.Context, e *deployment.Environment, selector uint64, remoteSelectors []uint64) error {
	l := m.logger
	l.Info().Uint64("FromSelector", selector).Any("ToSelectors", remoteSelectors).Msg("Connecting contracts with selectors")
	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)
	e.OperationsBundle = bundle

	remoteChains := make(map[uint64]changesets.RemoteChainConfig)

	for _, rs := range remoteSelectors {
		remoteChains[rs] = changesets.RemoteChainConfig{
			AllowTrafficFrom: true,
			CCIPMessageSource: datastore.AddressRef{
				Type:    datastore.ContractType(onrampoperations.ContractType),
				Version: semver.MustParse(onrampoperations.Deploy.Version()),
			},
			CCIPMessageDest: datastore.AddressRef{
				Type:    datastore.ContractType(offrampoperations.ContractType),
				Version: semver.MustParse(offrampoperations.Deploy.Version()),
			},
			DefaultInboundCCVs: []datastore.AddressRef{
				{
					Type:          datastore.ContractType(committee_verifier.ProxyType),
					Version:       semver.MustParse(committee_verifier.Deploy.Version()),
					ChainSelector: selector,
					Qualifier:     DefaultCommitteeVerifierQualifier,
				},
			},
			// LaneMandatedInboundCCVs: []datastore.AddressRef{},
			DefaultOutboundCCVs: []datastore.AddressRef{
				{
					Type:          datastore.ContractType(committee_verifier.ProxyType),
					Version:       semver.MustParse(committee_verifier.Deploy.Version()),
					ChainSelector: selector,
					Qualifier:     DefaultCommitteeVerifierQualifier,
				},
			},
			// LaneMandatedOutboundCCVs: []datastore.AddressRef{},
			DefaultExecutor: datastore.AddressRef{
				Type:    datastore.ContractType(executor.ContractType),
				Version: semver.MustParse(executor.Deploy.Version()),
			},
			CommitteeVerifierDestChainConfig: sequences.CommitteeVerifierDestChainConfig{
				AllowlistEnabled:   false,
				GasForVerification: CommitteeVerifierGasForVerification,
			},
			FeeQuoterDestChainConfig: fee_quoter.DestChainConfig{
				IsEnabled:                   true,
				MaxDataBytes:                30_000,
				MaxPerMsgGasLimit:           3_000_000,
				DestGasOverhead:             300_000,
				DefaultTokenFeeUSDCents:     25,
				DestGasPerPayloadByteBase:   16,
				DefaultTokenDestGasOverhead: 90_000,
				DefaultTxGasLimit:           200_000,
				NetworkFeeUSDCents:          10,
				ChainFamilySelector:         [4]byte{0x28, 0x12, 0xd5, 0x2c}, // EVM
			},
		}
	}

	mcmsReaderRegistry := changesetscore.NewMCMSReaderRegistry() // TODO: Integrate actual registry if MCMS support is required.
	_, err := changesets.ConfigureChainForLanes(mcmsReaderRegistry).Apply(*e, changesetscore.WithMCMS[changesets.ConfigureChainForLanesCfg]{
		Cfg: changesets.ConfigureChainForLanesCfg{
			ChainSel:     selector,
			RemoteChains: remoteChains,
			CommitteeVerifiers: []datastore.AddressRef{
				{
					Type:          datastore.ContractType(committee_verifier.ContractType),
					Version:       semver.MustParse(committee_verifier.Deploy.Version()),
					ChainSelector: selector,
					Qualifier:     DefaultCommitteeVerifierQualifier,
				},
				{
					Type:          datastore.ContractType(committee_verifier.ContractType),
					Version:       semver.MustParse(committee_verifier.Deploy.Version()),
					ChainSelector: selector,
					Qualifier:     SecondaryCommitteeVerifierQualifier,
				},
				{
					Type:          datastore.ContractType(committee_verifier.ContractType),
					Version:       semver.MustParse(committee_verifier.Deploy.Version()),
					ChainSelector: selector,
					Qualifier:     TertiaryCommitteeVerifierQualifier,
				},
			},
		},
	})
	if err != nil {
		return err
	}

	// Configure TEST token for transfer
	tokenAdapterRegistry := tokenscore.NewTokenAdapterRegistry()
	tokenAdapterRegistry.RegisterTokenAdapter("evm", semver.MustParse("1.7.0"), &adapters.TokenAdapter{})
	tokensRemoteChains := make(map[uint64]tokenscore.RemoteChainConfig[*datastore.AddressRef, datastore.AddressRef])
	for _, rs := range remoteSelectors {
		tokensRemoteChains[rs] = tokenscore.RemoteChainConfig[*datastore.AddressRef, datastore.AddressRef]{
			RemotePool: &datastore.AddressRef{
				Type:    datastore.ContractType(burn_mint_token_pool.ContractType),
				Version: semver.MustParse("1.7.0"),
			},
			InboundRateLimiterConfig: tokenscore.RateLimiterConfig{
				IsEnabled: false,
				Capacity:  big.NewInt(0),
				Rate:      big.NewInt(0),
			},
			OutboundRateLimiterConfig: tokenscore.RateLimiterConfig{
				IsEnabled: false,
				Capacity:  big.NewInt(0),
				Rate:      big.NewInt(0),
			},
			OutboundCCVs: []datastore.AddressRef{
				{
					Type:      datastore.ContractType(committee_verifier.ProxyType),
					Version:   semver.MustParse("1.7.0"),
					Qualifier: DefaultCommitteeVerifierQualifier,
				},
			},
			InboundCCVs: []datastore.AddressRef{
				{
					Type:      datastore.ContractType(committee_verifier.ProxyType),
					Version:   semver.MustParse("1.7.0"),
					Qualifier: DefaultCommitteeVerifierQualifier,
				},
			},
		}
	}
	_, err = tokenscore.ConfigureTokensForTransfers(tokenAdapterRegistry, mcmsReaderRegistry).Apply(*e, tokenscore.ConfigureTokensForTransfersConfig{
		Tokens: []tokenscore.TokenTransferConfig{
			{
				ChainSelector: selector,
				TokenPoolRef: datastore.AddressRef{
					Type:    datastore.ContractType(burn_mint_token_pool.ContractType),
					Version: semver.MustParse("1.7.0"),
				},
				RegistryRef: datastore.AddressRef{
					Type:    datastore.ContractType(token_admin_registry.ContractType),
					Version: semver.MustParse("1.5.0"),
				},
				RemoteChains: tokensRemoteChains,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to configure tokens for transfers: %w", err)
	}

	return nil
}

func (m *CCIP17EVM) FundNodes(ctx context.Context, ns []*simple_node_set.Input, bc *blockchain.Input, linkAmount, nativeAmount *big.Int) error {
	l := m.logger
	l.Info().Msg("Funding CL nodes with ETH and LINK")
	nodeClients, err := clclient.New(ns[0].Out.CLNodes)
	if err != nil {
		return fmt.Errorf("connecting to CL nodes: %w", err)
	}
	ethKeyAddressesSrc := make([]string, 0)
	for i, nc := range nodeClients {
		addrSrc, err := nc.ReadPrimaryETHKey(bc.ChainID)
		if err != nil {
			return fmt.Errorf("getting primary ETH key from OCR node %d (src chain): %w", i, err)
		}
		ethKeyAddressesSrc = append(ethKeyAddressesSrc, addrSrc.Attributes.Address)
		l.Info().
			Int("Idx", i).
			Str("ETHKeySrc", addrSrc.Attributes.Address).
			Msg("Node info")
	}
	clientSrc, _, _, err := ETHClient(ctx, bc.Out.Nodes[0].ExternalWSUrl, &GasSettings{
		FeeCapMultiplier: 2,
		TipCapMultiplier: 2,
	})
	if err != nil {
		return fmt.Errorf("could not create basic eth client: %w", err)
	}
	for _, addr := range ethKeyAddressesSrc {
		a, _ := nativeAmount.Float64()
		if err := FundNodeEIP1559(ctx, clientSrc, getNetworkPrivateKey(), addr, a); err != nil {
			return fmt.Errorf("failed to fund CL nodes on src chain: %w", err)
		}
	}
	return nil
}

// GetContractAddrForSelector get contract address by type and chain selector.
func GetContractAddrForSelector(addresses []string, selector uint64, contractType datastore.ContractType) (common.Address, error) {
	var contractAddr common.Address
	for _, addr := range addresses {
		var refs []datastore.AddressRef
		err := json.Unmarshal([]byte(addr), &refs)
		if err != nil {
			return common.Address{}, err
		}
		for _, ref := range refs {
			if ref.ChainSelector == selector && ref.Type == contractType {
				contractAddr = common.HexToAddress(ref.Address)
			}
		}
	}
	return contractAddr, nil
}
