package canton

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	apiv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2"
	"github.com/smartcontractkit/chainlink-canton/contracts"
	"github.com/smartcontractkit/go-daml/pkg/types"
)

// findLatestActiveContractByInstanceAddress is a tolerant variant of
// chainlink-canton's contract.FindActiveContractByInstanceAddress.
//
// The upstream helper hard-fails if multiple active contracts match the same InstanceAddress.
// In devenv/test runs we can end up with multiple active contracts (e.g. multiple PerPartyRouter
// contracts for the same instance address). In that case we pick the newest by CreatedAt.
//
// The returned ActiveContract includes the CreatedEventBlob required for explicit disclosures.
func findLatestActiveContractByInstanceAddress(
	ctx context.Context,
	stateService apiv2.StateServiceClient,
	party, templateId string,
	instanceAddress contracts.InstanceAddress,
) (*apiv2.ActiveContract, error) {
	ledgerEndResp, err := stateService.GetLedgerEnd(ctx, &apiv2.GetLedgerEndRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ledger end: %w", err)
	}

	packageID, moduleName, entityName, err := parseTemplateIDFromString(templateId)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template ID: %w", err)
	}

	activeContractsResp, err := stateService.GetActiveContracts(ctx, &apiv2.GetActiveContractsRequest{
		ActiveAtOffset: ledgerEndResp.GetOffset(),
		EventFormat: &apiv2.EventFormat{
			FiltersByParty: map[string]*apiv2.Filters{
				party: {
					Cumulative: []*apiv2.CumulativeFilter{
						{
							IdentifierFilter: &apiv2.CumulativeFilter_TemplateFilter{
								TemplateFilter: &apiv2.TemplateFilter{
									TemplateId: &apiv2.Identifier{
										PackageId:  packageID,
										ModuleName: moduleName,
										EntityName: entityName,
									},
									IncludeCreatedEventBlob: true,
								},
							},
						},
					},
				},
			},
			Verbose: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get active contracts: %w", err)
	}
	defer activeContractsResp.CloseSend()

	var matches []*apiv2.ActiveContract
	for {
		activeContractResp, err := activeContractsResp.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to receive active contracts: %w", err)
		}

		c, ok := activeContractResp.GetContractEntry().(*apiv2.GetActiveContractsResponse_ActiveContract)
		if !ok {
			continue
		}

		createArguments := c.ActiveContract.GetCreatedEvent().GetCreateArguments()
		if createArguments == nil {
			continue
		}

		var contractInstanceId string
		for _, field := range createArguments.GetFields() {
			if field.GetLabel() == "instanceId" {
				contractInstanceId = field.GetValue().GetText()
				break
			}
		}
		if contractInstanceId == "" {
			continue
		}

		// Get signatory of contract and compute instance address, then compare with the provided instance address
		signatories := c.ActiveContract.GetCreatedEvent().GetSignatories()
		if len(signatories) != 1 {
			continue
		}
		gotAddress := contracts.InstanceID(contractInstanceId).RawInstanceAddress(types.PARTY(signatories[0])).InstanceAddress()
		if gotAddress != instanceAddress {
			continue
		}

		matches = append(matches, c.ActiveContract)
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no active contract found for InstanceAddress %s", instanceAddress.String())
	}

	// Choose the newest by CreatedAt.
	slices.SortFunc(matches, func(a, b *apiv2.ActiveContract) int {
		return a.GetCreatedEvent().GetCreatedAt().AsTime().Compare(b.GetCreatedEvent().GetCreatedAt().AsTime())
	})
	return matches[len(matches)-1], nil
}

func findLatestActiveContractIDByInstanceAddress(
	ctx context.Context,
	stateService apiv2.StateServiceClient,
	party, templateId string,
	instanceAddress contracts.InstanceAddress,
) (string, error) {
	active, err := findLatestActiveContractByInstanceAddress(ctx, stateService, party, templateId, instanceAddress)
	if err != nil {
		return "", err
	}
	return active.GetCreatedEvent().GetContractId(), nil
}

// parseTemplateIDFromString parses a template ID string like "#package:Module:Entity" into its components.
// This mirrors the parsing logic in chainlink-canton's contract utilities.
func parseTemplateIDFromString(templateID string) (packageID, moduleName, entityName string, err error) {
	if !strings.HasPrefix(templateID, "#") {
		return "", "", "", fmt.Errorf("template ID must start with #")
	}
	parts := strings.Split(templateID, ":")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("template ID must have format #package:module:entity, got: %s", templateID)
	}
	return parts[0], parts[1], parts[2], nil
}
