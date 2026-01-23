package canton

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	ledgerv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Factory struct {
	lggr   logger.Logger
	helper *blockchain.Helper
	config map[string]commit.CantonConfig
}

func NewFactory(lggr logger.Logger, helper *blockchain.Helper, config map[string]commit.CantonConfig) *Factory {
	return &Factory{
		lggr:   lggr,
		helper: helper,
		config: config,
	}
}

func (f *Factory) GetSourceReader(ctx context.Context, chainSelector protocol.ChainSelector) (chainaccess.SourceReader, error) {
	strSelector := strconv.FormatUint(uint64(chainSelector), 10)
	cantonConfig, ok := f.config[strSelector]
	if !ok {
		return nil, fmt.Errorf("canton config not found for chain %d", chainSelector)
	}

	netData, err := f.helper.GetNetworkSpecificData(chainSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to get network specific data for chain %d: %w", chainSelector, err)
	}
	if netData == nil || netData.CantonEndpoints == nil {
		return nil, fmt.Errorf("canton endpoints not found for chain %d", chainSelector)
	}

	templateID, err := parseTemplateID(cantonConfig.CCIPMessageSentTemplateID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template ID: %w", err)
	}

	return NewSourceReader(
		netData.CantonEndpoints.GRPCLedgerAPIURL,
		netData.CantonEndpoints.JWT,
		cantonConfig.CCIPOwnerParty,
		templateID,
	)
}

func parseTemplateID(id string) (*ledgerv2.Identifier, error) {
	parts := strings.Split(id, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid template ID format, expected packageId:moduleName:entityName, got: %s", id)
	}
	return &ledgerv2.Identifier{
		PackageId:   parts[0],
		ModuleName:  parts[1],
		EntityName:  parts[2],
	}, nil
}
