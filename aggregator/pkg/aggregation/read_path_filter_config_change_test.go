package aggregation

import (
	"slices"
	"testing"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/quorum"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/postgres"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/testutil"
	committee "github.com/smartcontractkit/chainlink-ccv/committee/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func setupTestPostgresStorage(t *testing.T) (*postgres.DatabaseStorage, func()) {
	t.Helper()
	ds, cleanup := testutil.SetupTestPostgresDB(t)
	err := postgres.RunMigrations(ds, "postgres")
	require.NoError(t, err)
	storage := postgres.NewDatabaseStorage(ds, 10, 10*time.Second, logger.Sugared(logger.Test(t)))
	return storage, cleanup
}

type configChangeTestCase struct {
	name                  string
	initialSignerNames    []string
	initialThreshold      uint8
	configSignerNames     []string
	configThreshold       uint8
	expectedSignerNames   []string
	expectSkipAggregation bool
}

func TestConfigChange_ReadPathFiltering(t *testing.T) {
	t.Parallel()

	storage, cleanup := setupTestPostgresStorage(t)
	defer cleanup()

	tests := []configChangeTestCase{
		{
			name:                  "HappyPath_NoConfigChange_AllSignersValid",
			initialSignerNames:    []string{"node1", "node2", "node3"},
			initialThreshold:      2,
			configSignerNames:     []string{"node1", "node2", "node3"},
			configThreshold:       2,
			expectedSignerNames:   []string{"node1", "node2", "node3"},
			expectSkipAggregation: true,
		},
		{
			name:                  "RemovedSigner_ReadPathFiltersOutRemovedSigner",
			initialSignerNames:    []string{"node1", "node2", "node3"},
			initialThreshold:      2,
			configSignerNames:     []string{"node2", "node3"},
			configThreshold:       2,
			expectedSignerNames:   []string{"node2", "node3"},
			expectSkipAggregation: true,
		},
		{
			name:                  "RemovedSigner_LowerThreshold_ReadPathFiltersOutRemovedSigner",
			initialSignerNames:    []string{"node1", "node2", "node3"},
			initialThreshold:      2,
			configSignerNames:     []string{"node2", "node3"},
			configThreshold:       1,
			expectedSignerNames:   []string{"node2", "node3"},
			expectSkipAggregation: true,
		},
		{
			name:                  "AddedSigner_AllOriginalSignersStillValid",
			initialSignerNames:    []string{"node1", "node2"},
			initialThreshold:      2,
			configSignerNames:     []string{"node1", "node2", "node3"},
			configThreshold:       2,
			expectedSignerNames:   []string{"node1", "node2"},
			expectSkipAggregation: true,
		},
		{
			name:                  "AddedSigner_HigherThreshold_AllOriginalSignersStillValid_WillNeedNewSignerToMeetThreshold",
			initialSignerNames:    []string{"node1", "node2"},
			initialThreshold:      2,
			configSignerNames:     []string{"node1", "node2", "node3"},
			configThreshold:       3,
			expectedSignerNames:   nil,
			expectSkipAggregation: false,
		},
		{
			name:                  "AllSignersRemoved_NoValidSignatures",
			initialSignerNames:    []string{"node1", "node2"},
			initialThreshold:      2,
			configSignerNames:     []string{"node3", "node4"},
			configThreshold:       2,
			expectedSignerNames:   nil,
			expectSkipAggregation: false,
		},
		{
			name:                  "ThresholdRaised_NoSignerChange_InvalidConfig_AllStillValid_WillNeedNewSignerToMeetThreshold",
			initialSignerNames:    []string{"node1", "node2"},
			initialThreshold:      2,
			configSignerNames:     []string{"node1", "node2"},
			configThreshold:       3,
			expectedSignerNames:   nil,
			expectSkipAggregation: false,
		},
		{
			name:                  "RemovedSigner_OnlyOneRemains_OneValid_WillNeedNewSignerToMeetThreshold",
			initialSignerNames:    []string{"node1", "node2"},
			initialThreshold:      2,
			configSignerNames:     []string{"node2", "node3"},
			configThreshold:       2,
			expectedSignerNames:   nil,
			expectSkipAggregation: false,
		},
		{
			name:                  "MultipleRemoved_StillMeetThreshold_TwoValid",
			initialSignerNames:    []string{"node1", "node2", "node3", "node4"},
			initialThreshold:      2,
			configSignerNames:     []string{"node3", "node4"},
			configThreshold:       2,
			expectedSignerNames:   []string{"node3", "node4"},
			expectSkipAggregation: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			sourceVerifierAddr, destVerifierAddr := testutil.GenerateVerifierAddresses(t)

			allSignerNames := collectUniqueNames(tc.initialSignerNames, tc.configSignerNames)
			signersByName := make(map[string]*testutil.SignerFixture, len(allSignerNames))
			for _, name := range allSignerNames {
				signersByName[name] = testutil.NewSignerFixture(t, name)
			}

			initialSigners := resolveSigners(signersByName, tc.initialSignerNames)
			committeeObj := testutil.NewCommitteeFixture(sourceVerifierAddr, destVerifierAddr, toModelSigners(initialSigners)...)
			testutil.UpdateCommitteeQuorumWithThreshold(committeeObj, sourceVerifierAddr, tc.initialThreshold, toModelSigners(initialSigners)...)

			aggConfig := &model.AggregatorConfig{Committee: committeeObj}
			validator := quorum.NewQuorumValidator(aggConfig, logger.Sugared(logger.Test(t)))

			message := testutil.NewProtocolMessage(t)

			records := make([]*model.CommitVerificationRecord, 0, len(initialSigners))
			var messageID model.MessageID
			for _, signer := range initialSigners {
				protoMsg, msgID := testutil.NewMessageWithCCVNodeData(t, message, sourceVerifierAddr, testutil.WithSignatureFrom(t, signer))
				record, err := model.CommitVerificationRecordFromProto(protoMsg)
				require.NoError(t, err)

				sigResult, err := validator.ValidateSignature(ctx, record)
				require.NoError(t, err)
				record.SignerIdentifier = sigResult.Signer

				aggKey, err := validator.DeriveAggregationKey(ctx, record)
				require.NoError(t, err)

				err = storage.SaveCommitVerification(ctx, record, aggKey)
				require.NoError(t, err)

				records = append(records, record)
				messageID = msgID[:]
			}

			initialAggregatedReport := &model.CommitAggregatedReport{
				MessageID:     messageID,
				Verifications: records,
			}
			err := storage.SubmitAggregatedReport(ctx, initialAggregatedReport)
			require.NoError(t, err)

			configSigners := resolveSigners(signersByName, tc.configSignerNames)
			testutil.UpdateCommitteeQuorumWithThreshold(committeeObj, sourceVerifierAddr, tc.configThreshold, toModelSigners(configSigners)...)

			agg := &CommitReportAggregator{
				aggregatedStore: storage,
				quorum:          validator,
				l:               logger.Sugared(logger.Test(t)),
			}
			skipAggregation := agg.shouldSkipAggregationDueToExistingQuorum(ctx, messageID)
			require.Equal(t, tc.expectSkipAggregation, skipAggregation,
				"shouldSkipAggregationDueToExistingQuorum mismatch")

			report, err := storage.GetCommitAggregatedReportByMessageID(ctx, messageID)
			require.NoError(t, err)
			require.NotNil(t, report)
			require.Len(t, report.Verifications, len(tc.initialSignerNames),
				"raw report in storage should still contain all initial verifications")

			if len(tc.expectedSignerNames) == 0 {
				_, mapErr := model.MapAggregatedReportToVerifierResultProto(report, committeeObj)
				require.Error(t, mapErr, "expected error when valid signatures do not meet quorum threshold")
				return
			}

			proto, err := model.MapAggregatedReportToVerifierResultProto(report, committeeObj)
			require.NoError(t, err)
			require.NotNil(t, proto)

			ccvData := proto.CcvData
			require.True(t, len(ccvData) > committee.VerifierVersionLength,
				"ccvData should contain version prefix + encoded signatures")

			sigData := ccvData[committee.VerifierVersionLength:]
			rs, ss, err := protocol.DecodeSignatures(sigData)
			require.NoError(t, err)
			require.Len(t, rs, len(tc.expectedSignerNames),
				"read path should include only signatures from current committee members")
			require.Len(t, ss, len(tc.expectedSignerNames))

			var msgID protocol.Bytes32
			copy(msgID[:], messageID)
			hash, err := committee.NewSignableHash(msgID, ccvData)
			require.NoError(t, err)
			recoveredAddresses, err := protocol.RecoverECDSASigners(hash, rs, ss)
			require.NoError(t, err)
			require.Len(t, recoveredAddresses, len(tc.expectedSignerNames))

			expectedSigners := resolveSigners(signersByName, tc.expectedSignerNames)
			for _, signer := range expectedSigners {
				addr := ethcommon.HexToAddress(signer.Signer.Address)
				require.True(t, slices.Contains(recoveredAddresses, addr),
					"expected signer %s not found in recovered addresses", addr.Hex())
			}
		})
	}
}

func TestConfigChange_MultipleReportRows_UsesLatestReport(t *testing.T) {
	t.Parallel()

	storage, cleanup := setupTestPostgresStorage(t)
	defer cleanup()

	tests := []struct {
		name                                           string
		firstReportSignerNames                         []string
		secondReportSignerNames                        []string
		initialThreshold                               uint8
		configSignerNames                              []string
		configThreshold                                uint8
		expectedSignerNames                            []string
		expectSkipAggregation                          bool
		expectedLatestestAggregatedReportVerifications int
	}{
		{
			name:                    "race produces two rows, signer removed, latest report used for quorum check",
			firstReportSignerNames:  []string{"node1", "node2"},
			secondReportSignerNames: []string{"node1", "node2", "node3"},
			initialThreshold:        2,
			configSignerNames:       []string{"node2", "node3"},
			configThreshold:         2,
			expectedSignerNames:     []string{"node2", "node3"},
			expectSkipAggregation:   true,
			expectedLatestestAggregatedReportVerifications: 3,
		},
		{
			name:                    "race produces two rows, signer removed and threshold raised, latest still insufficient",
			firstReportSignerNames:  []string{"node1", "node2"},
			secondReportSignerNames: []string{"node1", "node2", "node3"},
			initialThreshold:        2,
			configSignerNames:       []string{"node2", "node3", "node4"},
			configThreshold:         3,
			expectedSignerNames:     nil,
			expectSkipAggregation:   false,
			expectedLatestestAggregatedReportVerifications: 3,
		},
		{
			name:                    "race produces two rows, all signers in latest replaced, read path filters all",
			firstReportSignerNames:  []string{"node1"},
			secondReportSignerNames: []string{"node1", "node2"},
			initialThreshold:        1,
			configSignerNames:       []string{"node3", "node4"},
			configThreshold:         1,
			expectedSignerNames:     nil,
			expectSkipAggregation:   false,
			expectedLatestestAggregatedReportVerifications: 2,
		},
		{
			name:                    "race produces two rows, all signers in latest replaced, read path filters all but one",
			firstReportSignerNames:  []string{"node3", "node4"},
			secondReportSignerNames: []string{"node1", "node2"},
			initialThreshold:        1,
			configSignerNames:       []string{"node1", "node3"},
			configThreshold:         1,
			expectedSignerNames:     []string{"node1"},
			expectSkipAggregation:   true,
			expectedLatestestAggregatedReportVerifications: 2,
		},
		{
			name:                    "race produces two rows, all signers in latest replaced with one new signer, quorum not met, expected to not skip aggregation",
			firstReportSignerNames:  []string{"node1", "node2"},
			secondReportSignerNames: []string{"node3"},
			initialThreshold:        1,
			configSignerNames:       []string{"node1", "node2", "node3"},
			configThreshold:         2,
			expectedSignerNames:     nil,
			expectSkipAggregation:   false,
			expectedLatestestAggregatedReportVerifications: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			sourceVerifierAddr, destVerifierAddr := testutil.GenerateVerifierAddresses(t)

			allNames := collectUniqueNames(
				collectUniqueNames(tc.firstReportSignerNames, tc.secondReportSignerNames),
				tc.configSignerNames,
			)
			signersByName := make(map[string]*testutil.SignerFixture, len(allNames))
			for _, name := range allNames {
				signersByName[name] = testutil.NewSignerFixture(t, name)
			}

			initialSignerNames := collectUniqueNames(tc.firstReportSignerNames, tc.secondReportSignerNames)
			initialSigners := resolveSigners(signersByName, initialSignerNames)
			committeeObj := testutil.NewCommitteeFixture(sourceVerifierAddr, destVerifierAddr, toModelSigners(initialSigners)...)
			testutil.UpdateCommitteeQuorumWithThreshold(committeeObj, sourceVerifierAddr, tc.initialThreshold, toModelSigners(initialSigners)...)

			aggConfig := &model.AggregatorConfig{Committee: committeeObj}
			validator := quorum.NewQuorumValidator(aggConfig, logger.Sugared(logger.Test(t)))

			message := testutil.NewProtocolMessage(t)

			allRecordsByName := make(map[string]*model.CommitVerificationRecord, len(initialSignerNames))
			var messageID model.MessageID
			for _, name := range initialSignerNames {
				signer := signersByName[name]
				protoMsg, msgID := testutil.NewMessageWithCCVNodeData(t, message, sourceVerifierAddr, testutil.WithSignatureFrom(t, signer))
				record, err := model.CommitVerificationRecordFromProto(protoMsg)
				require.NoError(t, err)

				sigResult, err := validator.ValidateSignature(ctx, record)
				require.NoError(t, err)
				record.SignerIdentifier = sigResult.Signer

				aggKey, err := validator.DeriveAggregationKey(ctx, record)
				require.NoError(t, err)

				err = storage.SaveCommitVerification(ctx, record, aggKey)
				require.NoError(t, err)

				allRecordsByName[name] = record
				messageID = msgID[:]
			}

			firstRecords := make([]*model.CommitVerificationRecord, 0, len(tc.firstReportSignerNames))
			for _, name := range tc.firstReportSignerNames {
				firstRecords = append(firstRecords, allRecordsByName[name])
			}
			err := storage.SubmitAggregatedReport(ctx, &model.CommitAggregatedReport{
				MessageID:     messageID,
				Verifications: firstRecords,
			})
			require.NoError(t, err)

			secondRecords := make([]*model.CommitVerificationRecord, 0, len(tc.secondReportSignerNames))
			for _, name := range tc.secondReportSignerNames {
				secondRecords = append(secondRecords, allRecordsByName[name])
			}
			err = storage.SubmitAggregatedReport(ctx, &model.CommitAggregatedReport{
				MessageID:     messageID,
				Verifications: secondRecords,
			})
			require.NoError(t, err)

			configSigners := resolveSigners(signersByName, tc.configSignerNames)
			testutil.UpdateCommitteeQuorumWithThreshold(committeeObj, sourceVerifierAddr, tc.configThreshold, toModelSigners(configSigners)...)

			agg := &CommitReportAggregator{
				aggregatedStore: storage,
				quorum:          validator,
				l:               logger.Sugared(logger.Test(t)),
			}
			skipAggregation := agg.shouldSkipAggregationDueToExistingQuorum(ctx, messageID)
			require.Equal(t, tc.expectSkipAggregation, skipAggregation,
				"shouldSkipAggregationDueToExistingQuorum mismatch")

			report, err := storage.GetCommitAggregatedReportByMessageID(ctx, messageID)
			require.NoError(t, err)
			require.NotNil(t, report)
			require.Len(t, report.Verifications, tc.expectedLatestestAggregatedReportVerifications,
				"GetCommitAggregatedReportByMessageID should return only the latest report's verifications")

			if len(tc.expectedSignerNames) == 0 {
				_, mapErr := model.MapAggregatedReportToVerifierResultProto(report, committeeObj)
				require.Error(t, mapErr, "expected error when valid signatures do not meet quorum threshold")
				return
			}

			proto, err := model.MapAggregatedReportToVerifierResultProto(report, committeeObj)
			require.NoError(t, err)
			require.NotNil(t, proto)

			ccvData := proto.CcvData
			require.True(t, len(ccvData) > committee.VerifierVersionLength,
				"ccvData should contain version prefix + encoded signatures")

			sigData := ccvData[committee.VerifierVersionLength:]
			rs, ss, err := protocol.DecodeSignatures(sigData)
			require.NoError(t, err)
			require.Len(t, rs, len(tc.expectedSignerNames),
				"read path should include only signatures from current committee members")
			require.Len(t, ss, len(tc.expectedSignerNames))

			var msgID protocol.Bytes32
			copy(msgID[:], messageID)
			hash, err := committee.NewSignableHash(msgID, ccvData)
			require.NoError(t, err)
			recoveredAddresses, err := protocol.RecoverECDSASigners(hash, rs, ss)
			require.NoError(t, err)
			require.Len(t, recoveredAddresses, len(tc.expectedSignerNames))

			expectedSigners := resolveSigners(signersByName, tc.expectedSignerNames)
			for _, signer := range expectedSigners {
				addr := ethcommon.HexToAddress(signer.Signer.Address)
				require.True(t, slices.Contains(recoveredAddresses, addr),
					"expected signer %s not found in recovered addresses", addr.Hex())
			}
		})
	}
}

func collectUniqueNames(a, b []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, lists := range [][]string{a, b} {
		for _, name := range lists {
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				result = append(result, name)
			}
		}
	}
	return result
}

func resolveSigners(signersByName map[string]*testutil.SignerFixture, names []string) []*testutil.SignerFixture {
	result := make([]*testutil.SignerFixture, len(names))
	for i, name := range names {
		result[i] = signersByName[name]
	}
	return result
}

func toModelSigners(signers []*testutil.SignerFixture) []model.Signer {
	result := make([]model.Signer, len(signers))
	for i, s := range signers {
		result[i] = s.Signer
	}
	return result
}
