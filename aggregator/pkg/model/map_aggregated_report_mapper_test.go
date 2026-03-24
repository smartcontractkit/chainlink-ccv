package model_test

import (
	"context"
	"testing"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/quorum"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/testutil"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestMapAggregatedReportToVerifierResultProto_DestinationVerifierRules(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	sourceVerifierAddress, destVerifierAddress := testutil.GenerateVerifierAddresses(t)
	signer := testutil.NewSignerFixture(t, "n1")

	exportCommittee := testutil.NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer.Signer)
	testutil.UpdateCommitteeQuorumWithThreshold(exportCommittee, sourceVerifierAddress, 1, signer.Signer)

	blockedCommittee := &model.Committee{}
	testutil.UpdateCommitteeQuorumWithThreshold(blockedCommittee, sourceVerifierAddress, 1, signer.Signer)
	blockedCommittee.DestinationVerifiers = map[model.DestinationSelector]string{
		"999": ethcommon.BytesToAddress(destVerifierAddress).Hex(),
	}
	require.NoError(t, (&model.AggregatorConfig{Committee: blockedCommittee}).ValidateCommitteeConfig())

	exportCfg := &model.AggregatorConfig{Committee: exportCommittee}
	validator := quorum.NewQuorumValidator(exportCfg, logger.Sugared(logger.Test(t)))
	message := testutil.NewProtocolMessage(t)

	tests := []struct {
		name          string
		ccvOpts       []testutil.MessageWithCCVNodeDataOption
		committee     *model.Committee
		wantErr       string
		wantNilDestMD bool
	}{
		{
			name: "non_message_discovery_missing_destination_returns_error",
			ccvOpts: []testutil.MessageWithCCVNodeDataOption{
				testutil.WithSignatureFrom(t, signer),
			},
			committee: blockedCommittee,
			wantErr:   "destination verifier address not found",
		},
		{
			name: "message_discovery_missing_destination_maps_with_nil_dest_metadata",
			ccvOpts: []testutil.MessageWithCCVNodeDataOption{
				testutil.WithCcvVersion(protocol.MessageDiscoveryVersion),
				testutil.WithSignatureFrom(t, signer),
			},
			committee:     blockedCommittee,
			wantNilDestMD: true,
		},
		{
			name: "non_message_discovery_with_destination_sets_dest_metadata",
			ccvOpts: []testutil.MessageWithCCVNodeDataOption{
				testutil.WithSignatureFrom(t, signer),
			},
			committee: exportCommittee,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			protoMsg, _ := testutil.NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, tt.ccvOpts...)
			record, err := model.CommitVerificationRecordFromProto(protoMsg)
			require.NoError(t, err)
			sigResult, err := validator.ValidateSignature(ctx, record)
			require.NoError(t, err)
			record.SignerIdentifier = sigResult.Signer

			report := &model.CommitAggregatedReport{
				Verifications: []*model.CommitVerificationRecord{record},
				WrittenAt:     time.Unix(1, 0).UTC(),
			}
			got, err := model.MapAggregatedReportToVerifierResultProto(report, tt.committee)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			require.NotNil(t, got.Metadata)
			if tt.wantNilDestMD {
				require.Empty(t, got.Metadata.VerifierDestAddress)
			} else {
				require.NotEmpty(t, got.Metadata.VerifierDestAddress)
			}
		})
	}
}
