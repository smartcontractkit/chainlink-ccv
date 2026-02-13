package canton

import (
	"context"
	"fmt"

	ledgerv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2"

	"github.com/smartcontractkit/chainlink-canton/bindings/ccip/ccvs"
	"github.com/smartcontractkit/chainlink-canton/bindings/ccip/common"
	offramp2 "github.com/smartcontractkit/chainlink-canton/bindings/ccip/offramp"
	"github.com/smartcontractkit/chainlink-canton/bindings/ccip/rmn"
	"github.com/smartcontractkit/chainlink-canton/bindings/ccip/tokenadminregistry"
	"github.com/smartcontractkit/chainlink-canton/contracts"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/global_config"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/offramp"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/rmn_remote"
	"github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/token_admin_registry"
	"github.com/smartcontractkit/chainlink-canton/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// TODO this will be replaced by EDS once available

type ExecutionDisclosures struct {
	OffRamp            *ledgerv2.DisclosedContract
	GlobalConfig       *ledgerv2.DisclosedContract
	TokenAdminRegistry *ledgerv2.DisclosedContract
	RMNRemote          *ledgerv2.DisclosedContract
	Verifiers          []*ledgerv2.DisclosedContract
}

// GetDisclosuresForExecution returns all the necessary disclosed contracts to execute a message on Canton
func (c *Chain) GetDisclosuresForExecution(ctx context.Context, verifiers []contracts.InstanceAddress) (*ExecutionDisclosures, error) {
	var disclosures ExecutionDisclosures

	// OffRamp
	offRampRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(offramp.ContractType),
			offramp.Version,
			"",
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get offramp address ref: %w", err)
	}
	offRampAddress := contracts.HexToInstanceAddress(offRampRef.Address)
	activeOffRamp, err := contract.FindActiveContractByInstanceAddress(ctx, c.helper.stateServiceClient, c.helper.partyID, offramp2.OffRamp{}.GetTemplateID(), offRampAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get offramp contract ID: %w", err)
	}
	disclosures.OffRamp = convertToDisclosedContract(activeOffRamp)
	c.logger.Debug().Str("OffRampAddress", offRampAddress.String()).Str("OffRampCID", activeOffRamp.GetCreatedEvent().GetContractId()).Msg("Resolved OffRamp contract")

	// GlobalConfig
	globalConfigRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(global_config.ContractType),
			global_config.Version,
			"",
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get global config address ref: %w", err)
	}
	globalConfigAddress := contracts.HexToInstanceAddress(globalConfigRef.Address)
	activeGlobalConfig, err := contract.FindActiveContractByInstanceAddress(ctx, c.helper.stateServiceClient, c.helper.partyID, common.GlobalConfig{}.GetTemplateID(), globalConfigAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get global config contract ID: %w", err)
	}
	disclosures.GlobalConfig = convertToDisclosedContract(activeGlobalConfig)
	c.logger.Debug().Str("GlobalConfigAddress", globalConfigAddress.String()).Str("GlobalConfigCID", activeGlobalConfig.GetCreatedEvent().GetContractId()).Msg("Resolved GlobalConfig contract")

	// Token Admin Registry
	tokenAdminRegistryRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(token_admin_registry.ContractType),
			token_admin_registry.Version,
			"",
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get token admin registry address ref: %w", err)
	}
	tokenAdminRegistryAddress := contracts.HexToInstanceAddress(tokenAdminRegistryRef.Address)
	activeTokenAdminRegistry, err := contract.FindActiveContractByInstanceAddress(ctx, c.helper.stateServiceClient, c.helper.partyID, tokenadminregistry.TokenAdminRegistry{}.GetTemplateID(), tokenAdminRegistryAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get token admin registry contract ID: %w", err)
	}
	disclosures.TokenAdminRegistry = convertToDisclosedContract(activeTokenAdminRegistry)
	c.logger.Debug().Str("TokenAdminRegistryAddress", tokenAdminRegistryAddress.String()).Str("TokenAdminRegistryCID", activeTokenAdminRegistry.GetCreatedEvent().GetContractId()).Msg("Resolved TokenAdminRegistry contract")

	// RMN Remote
	rmnRemoteRef, err := c.e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			c.chainDetails.ChainSelector,
			datastore.ContractType(rmn_remote.ContractType),
			rmn_remote.Version,
			"",
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get rmn remote address ref: %w", err)
	}
	rmnRemoteAddress := contracts.HexToInstanceAddress(rmnRemoteRef.Address)
	activeRMNRemote, err := contract.FindActiveContractByInstanceAddress(ctx, c.helper.stateServiceClient, c.helper.partyID, rmn.RMNRemote{}.GetTemplateID(), rmnRemoteAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get rmn remote contract ID: %w", err)
	}
	c.logger.Debug().Str("RMNRemoteAddress", rmnRemoteAddress.String()).Str("RMNRemoteCID", activeRMNRemote.GetCreatedEvent().GetContractId()).Msg("Resolved RMNRemote contract")

	// Verifiers
	disclosures.Verifiers = make([]*ledgerv2.DisclosedContract, len(verifiers))
	for i, verifierAddr := range verifiers {
		activeVerifier, err := contract.FindActiveContractByInstanceAddress(ctx, c.helper.stateServiceClient, c.helper.partyID, ccvs.CommitteeVerifier{}.GetTemplateID(), verifierAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get committee verifier contract ID for address %s: %w", verifierAddr.String(), err)
		}
		disclosures.Verifiers[i] = convertToDisclosedContract(activeVerifier)
		c.logger.Debug().Str("CCVAddress", verifierAddr.String()).Str("CCVCID", activeVerifier.GetCreatedEvent().GetContractId()).Msg("Resolved CCV contract")
	}

	return &disclosures, nil
}

func convertToDisclosedContract(contract *ledgerv2.ActiveContract) *ledgerv2.DisclosedContract {
	if contract == nil {
		return nil
	}

	return &ledgerv2.DisclosedContract{
		TemplateId:       contract.GetCreatedEvent().GetTemplateId(),
		ContractId:       contract.GetCreatedEvent().GetContractId(),
		CreatedEventBlob: contract.GetCreatedEvent().GetCreatedEventBlob(),
		SynchronizerId:   contract.GetSynchronizerId(),
	}
}
