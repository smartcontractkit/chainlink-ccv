package canton

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	ledgerv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2"
	ledgerv2admin "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2/admin"
	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/go-daml/pkg/types"

	"github.com/smartcontractkit/chainlink-canton/bindings"
	"github.com/smartcontractkit/chainlink-canton/bindings/ccip/ccipreceiver"
	"github.com/smartcontractkit/chainlink-canton/bindings/ccip/perpartyrouter"
	"github.com/smartcontractkit/chainlink-canton/contracts"
	"github.com/smartcontractkit/chainlink-canton/deployment/dependencies"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/per_party_router_factory"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/receiver"
	"github.com/smartcontractkit/chainlink-canton/deployment/utils/operations/contract"

	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// DeployPerPartyRouter uses the PerPartyRouterFactory to create a new PerPartyRouter instance for the given party.
// It returns the address of the newly created PerPartyRouter instance. If a router already exists for the party, it returns the existing router's address.
func (c *Chain) DeployPerPartyRouter(ctx context.Context, partyId string) (contracts.InstanceAddress, error) {
	deps := dependencies.CantonDeps{
		Chain:                c.chain,
		CommandServiceClient: c.helper.commandClient,
		StateServiceClient:   c.helper.stateServiceClient,
		Party:                partyId,
	}

	// Create PerPartyRouter (ignore error if it exists already)
	cantonPerPartyRouterFactoryRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(per_party_router_factory.ContractType),
			per_party_router_factory.Version,
			"",
		),
	)
	if err != nil {
		return contracts.InstanceAddress{}, fmt.Errorf("failed to get canton per party router factory address ref: %w", err)
	}
	c.logger.Debug().Str("CantonPerPartyRouterFactory", cantonPerPartyRouterFactoryRef.Address).Msg("Resolved per-party router factory address")
	cantonPerPartyRouterFactory := contracts.HexToInstanceAddress(cantonPerPartyRouterFactoryRef.Address)

	// Fixed instance ID for the router, this makes the InstanceAddress deterministic.
	routerInstanceID := contracts.InstanceID("test-router")
	// Ignore errors, since the router might already exist if this function is called multiple times for the same party. In that case we just want to return the existing router's address.
	_, _ = operations.ExecuteOperation(c.e.OperationsBundle, per_party_router_factory.CreateRouter, deps, contract.ChoiceInput[perpartyrouter.CreateRouter]{
		ChainSelector:   c.chainDetails.ChainSelector,
		InstanceAddress: cantonPerPartyRouterFactory,
		ActAs:           []string{partyId},
		Args: perpartyrouter.CreateRouter{
			PartyOwner: types.PARTY(partyId),
			InstanceId: types.TEXT(routerInstanceID.String()),
		},
	})
	routerAddress := routerInstanceID.RawInstanceAddress(types.PARTY(partyId)).InstanceAddress()

	return routerAddress, nil
}

func (c *Chain) DeployCCIPReceiver(ctx context.Context, partyId string) (contracts.InstanceAddress, error) {
	deps := dependencies.CantonDeps{
		Chain:                c.chain,
		CommandServiceClient: c.helper.commandClient,
		StateServiceClient:   c.helper.stateServiceClient,
		Party:                partyId,
	}

	// Upload the necessary Dar
	receiverDar, err := contracts.GetDar(contracts.CCIPReceiver, contracts.CurrentVersion)
	if err != nil {
		return contracts.InstanceAddress{}, fmt.Errorf("failed to get receiver dar: %w", err)
	}
	_, err = c.helper.pkgMgmtClient.UploadDarFile(ctx, &ledgerv2admin.UploadDarFileRequest{
		DarFile:       receiverDar,
		VettingChange: ledgerv2admin.UploadDarFileRequest_VETTING_CHANGE_VET_ALL_PACKAGES,
	})
	if err != nil {
		return contracts.InstanceAddress{}, fmt.Errorf("failed to upload receiver dar file: %w", err)
	}

	// Deploy receiver contract
	out, err := operations.ExecuteOperation(c.e.OperationsBundle, receiver.Deploy, deps, contract.DeployInput[ccipreceiver.CCIPReceiver]{
		ChainSelector: c.chainDetails.ChainSelector,
		Qualifier:     nil,
		ActAs:         []string{c.helper.partyID},
		Template: ccipreceiver.CCIPReceiver{
			Owner:        types.PARTY(c.helper.partyID),
			RequiredCCVs: nil,
		},
		OwnerParty: types.PARTY(c.helper.partyID),
	})
	if err != nil {
		return contracts.InstanceAddress{}, fmt.Errorf("failed to deploy receiver contract: %w", err)
	}
	receiverAddress := contracts.HexToInstanceAddress(out.Output.Address)

	return receiverAddress, nil
}

// ManuallyExecuteMessage implements cciptestinterfaces.CCIP17.
func (c *Chain) ManuallyExecuteMessage(ctx context.Context, message protocol.Message, gasLimit uint64, verifiers []protocol.UnknownAddress, verifierResults [][]byte) (cciptestinterfaces.ExecutionStateChangedEvent, error) {
	// Ensure that the message receiver is the party we're executing with
	executingParty := c.helper.partyID
	if contracts.HashedPartyFromString(executingParty) != contracts.BytesToHashedParty(message.Receiver.Bytes()) {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("message receiver %s does not match executing party %s (%s)", hex.EncodeToString(message.Receiver), contracts.HashedPartyFromString(executingParty).String(), executingParty)
	}

	// Deploy PerPartyRouter for the receiver party
	routerAddress, err := c.DeployPerPartyRouter(ctx, executingParty)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to deploy per-party router: %w", err)
	}
	c.logger.Debug().Str("RouterAddress", routerAddress.String()).Msg("Deployed PerPartyRouter")

	// Deploy CCIPReceiver contract
	receiverAddress, err := c.DeployCCIPReceiver(ctx, executingParty)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to deploy CCIPReceiver contract: %w", err)
	}
	c.logger.Debug().Str("ReceiverAddress", receiverAddress.String()).Msg("Deployed CCIPReceiver")

	// Get disclosures for execution // TODO replace with EDS
	ccvs := make([]contracts.InstanceAddress, len(verifiers))
	for i, verifier := range verifiers {
		ccvs[i] = contracts.HexToInstanceAddress(verifier.String())
	}
	disclosures, err := c.GetDisclosuresForExecution(ctx, ccvs)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get disclosures for execution: %w", err)
	}

	// Resolve all necessary contracts
	routerCid, err := contract.FindActiveContractIDByInstanceAddress(ctx, c.helper.stateServiceClient, c.helper.partyID, perpartyrouter.PerPartyRouter{}.GetTemplateID(), routerAddress)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get router contract ID: %w", err)
	}
	c.logger.Debug().Str("InstanceAddress", routerAddress.String()).Str("ContractId", routerCid).Msg("Resolved PerPartyRouter contract")

	receiverCid, err := contract.FindActiveContractIDByInstanceAddress(ctx, c.helper.stateServiceClient, c.helper.partyID, ccipreceiver.CCIPReceiver{}.GetTemplateID(), receiverAddress)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get receiver contract ID: %w", err)
	}
	c.logger.Debug().Str("InstanceAddress", receiverAddress.String()).Str("ContractId", receiverCid).Msg("Resolved CCIPReceiver contract")

	// Execute message
	encodedMessage, err := message.Encode()
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to encode message: %w", err)
	}
	c.logger.Debug().
		Str("EncodedMessage", hex.EncodeToString(encodedMessage)).
		Str("VerifierResults", hex.EncodeToString(verifierResults[0])).
		Str("Receiver", hex.EncodeToString(message.Receiver)).
		Msg("Executing message...")

	disclosedContracts := []*ledgerv2.DisclosedContract{
		disclosures.OffRamp,
		disclosures.GlobalConfig,
		disclosures.TokenAdminRegistry,
		disclosures.RMNRemote,
	}

	ccvElements := make([]*ledgerv2.Value, len(verifiers))
	for i, verifier := range disclosures.Verifiers {
		ccvElements[i] = &ledgerv2.Value{
			Sum: &ledgerv2.Value_Record{Record: &ledgerv2.Record{Fields: []*ledgerv2.RecordField{
				{Label: "ccvCid", Value: &ledgerv2.Value{Sum: &ledgerv2.Value_ContractId{ContractId: verifier.GetContractId()}}},
				{Label: "verifierResults", Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: hex.EncodeToString(verifierResults[i])}}},
			}}},
		}
		disclosedContracts = append(disclosedContracts, verifier)
	}

	res, err := c.helper.commandClient.SubmitAndWaitForTransaction(ctx, &ledgerv2.SubmitAndWaitForTransactionRequest{
		Commands: &ledgerv2.Commands{
			CommandId: uuid.New().String(),
			Commands: []*ledgerv2.Command{{
				Command: &ledgerv2.Command_Exercise{Exercise: &ledgerv2.ExerciseCommand{
					TemplateId: &ledgerv2.Identifier{PackageId: "#ccip-receiver", ModuleName: "CCIP.CCIPReceiver", EntityName: "CCIPReceiver"},
					ContractId: receiverCid,
					Choice:     "Execute",
					ChoiceArgument: &ledgerv2.Value{Sum: &ledgerv2.Value_Record{Record: &ledgerv2.Record{Fields: []*ledgerv2.RecordField{
						{Label: "routerCid", Value: &ledgerv2.Value{Sum: &ledgerv2.Value_ContractId{ContractId: routerCid}}},
						{Label: "offRampCid", Value: &ledgerv2.Value{Sum: &ledgerv2.Value_ContractId{ContractId: disclosures.OffRamp.GetContractId()}}},
						{Label: "globalConfigCid", Value: &ledgerv2.Value{Sum: &ledgerv2.Value_ContractId{ContractId: disclosures.GlobalConfig.GetContractId()}}},
						{Label: "tokenAdminRegistryCid", Value: &ledgerv2.Value{Sum: &ledgerv2.Value_ContractId{ContractId: disclosures.TokenAdminRegistry.GetContractId()}}},
						{Label: "rmnRemoteCid", Value: &ledgerv2.Value{Sum: &ledgerv2.Value_ContractId{ContractId: disclosures.RMNRemote.GetContractId()}}},
						{Label: "encodedMessage", Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Text{Text: hex.EncodeToString(encodedMessage)}}},
						{Label: "tokenTransfer", Value: &ledgerv2.Value{Sum: &ledgerv2.Value_Optional{Optional: &ledgerv2.Optional{Value: nil}}}},
						{Label: "ccvInputs", Value: &ledgerv2.Value{Sum: &ledgerv2.Value_List{List: &ledgerv2.List{Elements: ccvElements}}}},
						{Label: "additionalRequiredCCVs", Value: &ledgerv2.Value{Sum: &ledgerv2.Value_List{List: &ledgerv2.List{Elements: nil}}}},
					}}}},
				}},
			}},
			ActAs:              []string{executingParty},
			DisclosedContracts: disclosedContracts,
		},
	})
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to execute message: %w", err)
	}
	c.logger.Debug().Str("UpdateID", res.GetTransaction().GetUpdateId()).Msg("Executed message")

	// Get Update
	updateRes, err := c.helper.updatesClient.GetUpdateById(ctx, &ledgerv2.GetUpdateByIdRequest{
		UpdateId: res.GetTransaction().GetUpdateId(),
		UpdateFormat: &ledgerv2.UpdateFormat{
			IncludeTransactions: &ledgerv2.TransactionFormat{
				TransactionShape: ledgerv2.TransactionShape_TRANSACTION_SHAPE_ACS_DELTA,
				EventFormat: &ledgerv2.EventFormat{
					FiltersByParty: map[string]*ledgerv2.Filters{
						c.helper.partyID: {
							Cumulative: []*ledgerv2.CumulativeFilter{
								{
									IdentifierFilter: &ledgerv2.CumulativeFilter_WildcardFilter{
										WildcardFilter: &ledgerv2.WildcardFilter{
											IncludeCreatedEventBlob: false,
										},
									},
								},
							},
						},
					},
					Verbose: true,
				},
			},
		},
	})
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to get update by UpdateId %q: %w", res.GetTransaction().GetUpdateId(), err)
	}

	// Get ExecutionStateChangedEvent from events
	expectedTemplateID := perpartyrouter.ExecutionStateChanged{}.GetTemplateID()
	for _, event := range updateRes.GetTransaction().GetEvents() {
		//nolint:nestif // need to check if all of these are nil
		if createdEvent := event.GetCreated(); createdEvent != nil {
			if templateId := createdEvent.GetTemplateId(); templateId != nil {
				gotTemplateId := fmt.Sprintf("#%s:%s:%s", createdEvent.GetPackageName(), templateId.GetModuleName(), templateId.GetEntityName())
				if gotTemplateId == expectedTemplateID {
					// Found the event, parse it
					c.logger.Debug().Int64("Offset", createdEvent.GetOffset()).Str("ContractId", createdEvent.GetContractId()).Msg("Found ExecutionStateChanged event")
					parsedEvent, err := parseExecutionStateChangedEvent(createdEvent)
					if err != nil {
						return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to parse ExecutionStateChanged event: %w", err)
					}
					return parsedEvent, nil
				}
			}
		}
	}

	// No event found in the update, return an error
	return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("no ExecutionStateChanged event found in update %s", res.GetTransaction().GetUpdateId())
}

// parseExecutionStateChangedEvent parses a perpartyrouter.ExecutionStateChanged event from a Daml CreatedEvent and converts it to cciptestinterfaces.ExecutionStateChangedEvent.
func parseExecutionStateChangedEvent(event *ledgerv2.CreatedEvent) (cciptestinterfaces.ExecutionStateChangedEvent, error) {
	executionStateChanged, err := bindings.UnmarshalCreatedEvent[perpartyrouter.ExecutionStateChanged](event)
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to unmarshal ExecutionStateChanged event: %w", err)
	}

	// Source chain selector
	sourceChainSelectorFloat, ok := new(big.Float).SetString(string(executionStateChanged.Event.SourceChainSelector))
	if !ok {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to parse source chain selector numeric, input: %s", string(executionStateChanged.Event.SourceChainSelector))
	}
	sourceChainSelector, _ := sourceChainSelectorFloat.Int(nil)
	// Message ID
	messageId, err := hex.DecodeString(string(executionStateChanged.Event.MessageId))
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to decode message ID %q: %w", string(executionStateChanged.Event.MessageId), err)
	}
	// Message number
	sequenceNumberFloat, ok := new(big.Float).SetString(string(executionStateChanged.Event.SequenceNumber))
	if !ok {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to parse sequence number numeric, input: %s", string(executionStateChanged.Event.SequenceNumber))
	}
	sequenceNumber, _ := sequenceNumberFloat.Int(nil)
	// Execution state
	var executionState cciptestinterfaces.MessageExecutionState
	switch executionStateChanged.Event.State {
	case perpartyrouter.MessageExecutionStateUNTOUCHED:
		executionState = cciptestinterfaces.ExecutionStateUntouched
	case perpartyrouter.MessageExecutionStateIN_PROGRESS:
		executionState = cciptestinterfaces.ExecutionStateInProgress
	case perpartyrouter.MessageExecutionStateSUCCESS:
		executionState = cciptestinterfaces.ExecutionStateSuccess
	case perpartyrouter.MessageExecutionStateFAILURE:
		executionState = cciptestinterfaces.ExecutionStateFailure
	default:
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("unknown execution state %q", executionStateChanged.Event.State)
	}
	// Return data
	returnData, err := hex.DecodeString(string(executionStateChanged.Event.ReturnData))
	if err != nil {
		return cciptestinterfaces.ExecutionStateChangedEvent{}, fmt.Errorf("failed to decode return data %q: %w", string(executionStateChanged.Event.ReturnData), err)
	}
	return cciptestinterfaces.ExecutionStateChangedEvent{
		SourceChainSelector: protocol.ChainSelector(sourceChainSelector.Uint64()),
		MessageID:           [32]byte(messageId),
		MessageNumber:       sequenceNumber.Uint64(),
		State:               executionState,
		ReturnData:          returnData,
	}, nil
}
