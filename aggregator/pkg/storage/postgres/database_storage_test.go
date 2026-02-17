package postgres

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/testutil"
	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

func assertCommitVerificationRecordEqual(t *testing.T, expected, actual *model.CommitVerificationRecord, msgPrefix string) {
	require.Equal(t, expected.MessageID, actual.MessageID, "%s: MessageID mismatch", msgPrefix)
	require.Positive(t, actual.GetTimestamp(), "%s: Timestamp should be set", msgPrefix)
	require.Equal(t, expected.CCVVersion, actual.CCVVersion, "%s: CCVVersion mismatch", msgPrefix)
	require.Equal(t, expected.Signature, actual.Signature, "%s: Signature mismatch", msgPrefix)

	if expected.Message != nil && actual.Message != nil {
		require.Equal(t, expected.Message.Version, actual.Message.Version, "%s: Message.Version mismatch", msgPrefix)
		require.Equal(t, expected.Message.SourceChainSelector, actual.Message.SourceChainSelector, "%s: Message.SourceChainSelector mismatch", msgPrefix)
		require.Equal(t, expected.Message.DestChainSelector, actual.Message.DestChainSelector, "%s: Message.DestChainSelector mismatch", msgPrefix)
		require.Equal(t, expected.Message.SequenceNumber, actual.Message.SequenceNumber, "%s: Message.SequenceNumber mismatch", msgPrefix)
		require.Equal(t, expected.Message.OnRampAddress, actual.Message.OnRampAddress, "%s: Message.OnRampAddress mismatch", msgPrefix)
		require.Equal(t, expected.Message.OffRampAddress, actual.Message.OffRampAddress, "%s: Message.OffRampAddress mismatch", msgPrefix)
		require.Equal(t, expected.Message.Sender, actual.Message.Sender, "%s: Message.Sender mismatch", msgPrefix)
		require.Equal(t, expected.Message.Receiver, actual.Message.Receiver, "%s: Message.Receiver mismatch", msgPrefix)
		require.Equal(t, expected.Message.Data, actual.Message.Data, "%s: Message.Data mismatch", msgPrefix)
	}

	if expected.SignerIdentifier != nil && actual.SignerIdentifier != nil {
		require.Equal(t, expected.SignerIdentifier.Identifier, actual.SignerIdentifier.Identifier, "%s: SignerIdentifier.Identifier mismatch", msgPrefix)
	}

	require.Equal(t, len(expected.MessageCCVAddresses), len(actual.MessageCCVAddresses), "%s: MessageCCVAddresses length mismatch", msgPrefix)
	for i, expectedAddr := range expected.MessageCCVAddresses {
		require.Equal(t, expectedAddr, actual.MessageCCVAddresses[i], "%s: MessageCCVAddresses[%d] mismatch", msgPrefix, i)
	}

	require.Equal(t, expected.MessageExecutorAddress, actual.MessageExecutorAddress, "%s: MessageExecutorAddress mismatch", msgPrefix)
}

type testFixture struct {
	key    *ecdsa.PrivateKey
	Signer model.Signer
}

func newTestSigner(t *testing.T) *testFixture {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	signerAddress := crypto.PubkeyToAddress(privateKey.PublicKey)

	signer := model.Signer{
		Address: signerAddress.Hex(),
	}
	return &testFixture{
		Signer: signer,
		key:    privateKey,
	}
}

func createTestProtocolMessage() *protocol.Message {
	return &protocol.Message{
		Version:              1,
		SourceChainSelector:  1,
		DestChainSelector:    2,
		SequenceNumber:       123,
		OnRampAddressLength:  20,
		OnRampAddress:        make([]byte, 20),
		OffRampAddressLength: 20,
		OffRampAddress:       make([]byte, 20),
		Finality:             10,
		SenderLength:         20,
		Sender:               make([]byte, 20),
		ReceiverLength:       20,
		Receiver:             make([]byte, 20),
		DestBlobLength:       10,
		DestBlob:             make([]byte, 10),
		TokenTransferLength:  0,
		TokenTransfer:        nil,
		DataLength:           8,
		Data:                 []byte("testdata"),
	}
}

func createTestMessageWithCCV(t *testing.T, message *protocol.Message, signer *testFixture) *committeepb.CommitteeVerifierNodeResult {
	ccvVersion := []byte{0x01, 0x02, 0x03, 0x04}
	ccvAddresses := [][]byte{{0x02, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}}
	executorAddress := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14}

	// Compute the CCV and executor hash
	ccvAddrs := make([]protocol.UnknownAddress, len(ccvAddresses))
	for i, addr := range ccvAddresses {
		ccvAddrs[i] = protocol.UnknownAddress(addr)
	}
	executorAddr := protocol.UnknownAddress(executorAddress)
	ccvAndExecutorHash, err := protocol.ComputeCCVAndExecutorHash(ccvAddrs, executorAddr)
	require.NoError(t, err)

	// Create proto message with CCV data and the computed hash
	msgWithCCV := &committeepb.CommitteeVerifierNodeResult{
		Message: &verifierpb.Message{
			Version:              uint32(message.Version),
			SourceChainSelector:  uint64(message.SourceChainSelector),
			DestChainSelector:    uint64(message.DestChainSelector),
			SequenceNumber:       uint64(message.SequenceNumber),
			OnRampAddressLength:  uint32(message.OnRampAddressLength),
			OnRampAddress:        message.OnRampAddress[:],
			OffRampAddressLength: uint32(message.OffRampAddressLength),
			OffRampAddress:       message.OffRampAddress[:],
			Finality:             uint32(message.Finality),
			ExecutionGasLimit:    message.ExecutionGasLimit,
			CcipReceiveGasLimit:  message.CcipReceiveGasLimit,
			CcvAndExecutorHash:   ccvAndExecutorHash[:],
			SenderLength:         uint32(message.SenderLength),
			Sender:               message.Sender[:],
			ReceiverLength:       uint32(message.ReceiverLength),
			Receiver:             message.Receiver[:],
			DestBlobLength:       uint32(message.DestBlobLength),
			DestBlob:             message.DestBlob[:],
			TokenTransferLength:  uint32(message.TokenTransferLength),
			TokenTransfer: func() []byte {
				if message.TokenTransfer != nil {
					encoded, err := message.TokenTransfer.Encode()
					require.NoError(t, err)
					return encoded
				}
				return []byte{}
			}(),
			DataLength: uint32(message.DataLength),
			Data:       message.Data[:],
		},
		CcvVersion:      ccvVersion,
		CcvAddresses:    ccvAddresses,
		ExecutorAddress: executorAddress,
	}

	// Now compute the correct messageID from the message with CCV data
	protocolMessage, err := ccvcommon.MapProtoMessageToProtocolMessage(msgWithCCV.Message)
	require.NoError(t, err)
	messageID, err := protocolMessage.MessageID()
	require.NoError(t, err)

	// Sign the correct messageID
	r32, s32, signerAddr, err := protocol.SignV27(messageID[:], signer.key)
	require.NoError(t, err)

	sigData := protocol.Data{
		R:      r32,
		S:      s32,
		Signer: signerAddr,
	}

	signature, err := protocol.EncodeSingleECDSASignature(sigData)
	require.NoError(t, err)

	msgWithCCV.Signature = signature
	return msgWithCCV
}

// getMessageIDFromProto is a helper to derive messageID from the proto message.
func getMessageIDFromProto(t *testing.T, msgWithCCV *committeepb.CommitteeVerifierNodeResult) []byte {
	protocolMessage, err := ccvcommon.MapProtoMessageToProtocolMessage(msgWithCCV.Message)
	require.NoError(t, err)
	messageID, err := protocolMessage.MessageID()
	require.NoError(t, err)
	return messageID[:]
}

func createTestCommitVerificationRecord(t *testing.T, msgWithCCV *committeepb.CommitteeVerifierNodeResult, signer *testFixture) *model.CommitVerificationRecord {
	signerAddress := common.HexToAddress(signer.Signer.Address)

	record, err := model.CommitVerificationRecordFromProto(msgWithCCV)
	require.NoError(t, err)
	record.SignerIdentifier = &model.SignerIdentifier{
		Identifier: signerAddress.Bytes(),
	}

	return record
}

func createTestCommitVerificationRecordWithNewKey(t *testing.T, msgWithCCV *committeepb.CommitteeVerifierNodeResult) *model.CommitVerificationRecord {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	signerAddress := crypto.PubkeyToAddress(privateKey.PublicKey)

	record, err := model.CommitVerificationRecordFromProto(msgWithCCV)
	require.NoError(t, err)
	record.SignerIdentifier = &model.SignerIdentifier{
		Identifier: signerAddress.Bytes(),
	}

	return record
}

func setupTestDB(t *testing.T) (*DatabaseStorage, func()) {
	t.Helper()
	storage, _, cleanup := setupTestDBWithDatabase(t)
	return storage, cleanup
}

func setupTestDBWithDatabase(t *testing.T) (*DatabaseStorage, *sqlx.DB, func()) {
	t.Helper()
	ds, cleanup := testutil.SetupTestPostgresDB(t)
	err := RunMigrations(ds, "postgres")
	require.NoError(t, err)
	storage := NewDatabaseStorage(ds, 10, 10*time.Second, logger.TestSugared(t))
	return storage, ds, cleanup
}

func TestSaveCommitVerification_HappyPath(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t)
	message := createTestProtocolMessage()
	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	record := createTestCommitVerificationRecord(t, msgWithCCV, signer)

	aggregationKey := protocol.ByteSlice(getMessageIDFromProto(t, msgWithCCV)).String()

	err := storage.SaveCommitVerification(ctx, record, aggregationKey)
	require.NoError(t, err)

	id, err := record.GetID()
	require.NoError(t, err)

	retrieved, err := storage.GetCommitVerification(ctx, *id)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assertCommitVerificationRecordEqual(t, record, retrieved, "SaveCommitVerification_HappyPath")
}

func TestSaveCommitVerification_NilRecord(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	err := storage.SaveCommitVerification(ctx, nil, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "commit verification record cannot be nil")
}

func TestSaveCommitVerification_Idempotency(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t)
	message := createTestProtocolMessage()
	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	record := createTestCommitVerificationRecord(t, msgWithCCV, signer)
	aggregationKey := protocol.ByteSlice(getMessageIDFromProto(t, msgWithCCV)).String()

	err := storage.SaveCommitVerification(ctx, record, aggregationKey)
	require.NoError(t, err)

	err = storage.SaveCommitVerification(ctx, record, aggregationKey)
	require.NoError(t, err)

	err = storage.SaveCommitVerification(ctx, record, aggregationKey)
	require.NoError(t, err)

	id, err := record.GetID()
	require.NoError(t, err)

	retrieved, err := storage.GetCommitVerification(ctx, *id)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assertCommitVerificationRecordEqual(t, record, retrieved, "SaveCommitVerification_Idempotency")

	messageID := getMessageIDFromProto(t, msgWithCCV)

	records, err := storage.ListCommitVerificationByAggregationKey(ctx, messageID, aggregationKey)
	require.NoError(t, err)
	require.Len(t, records, 1, "Should have exactly 1 record after multiple saves")
}

func TestGetCommitVerification_NotFound(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	id := model.CommitVerificationRecordIdentifier{
		MessageID: []byte("nonexistent"),
		Address:   protocol.ByteSlice([]byte("address")),
	}

	_, err := storage.GetCommitVerification(ctx, id)
	require.Error(t, err)
	require.Contains(t, err.Error(), "commit verification record not found")
}

func TestGetCommitVerification_MultipleVersions(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t)
	message := createTestProtocolMessage()
	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	aggregationKey := protocol.ByteSlice(getMessageIDFromProto(t, msgWithCCV)).String()

	record1 := createTestCommitVerificationRecord(t, msgWithCCV, signer)
	err := storage.SaveCommitVerification(ctx, record1, aggregationKey)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	record2 := createTestCommitVerificationRecordWithNewKey(t, msgWithCCV)
	record2.SetTimestampFromMillis(time.Now().UnixMilli())
	err = storage.SaveCommitVerification(ctx, record2, aggregationKey)
	require.NoError(t, err)

	id, err := record2.GetID()
	require.NoError(t, err)

	retrieved, err := storage.GetCommitVerification(ctx, *id)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Equal(t, record2.GetTimestamp().Unix(), retrieved.GetTimestamp().Unix(), "Should retrieve latest version")
	assertCommitVerificationRecordEqual(t, record2, retrieved, "GetCommitVerification_MultipleVersions")
}

func TestListCommitVerificationByAggregationKey(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	message := createTestProtocolMessage()
	signer1 := newTestSigner(t)
	signer2 := newTestSigner(t)

	msgWithCCV1 := createTestMessageWithCCV(t, message, signer1)
	messageID := getMessageIDFromProto(t, msgWithCCV1)
	aggregationKey := protocol.ByteSlice(messageID).String()

	record1 := createTestCommitVerificationRecord(t, msgWithCCV1, signer1)
	err := storage.SaveCommitVerification(ctx, record1, aggregationKey)
	require.NoError(t, err)

	msgWithCCV2 := createTestMessageWithCCV(t, message, signer2)
	record2 := createTestCommitVerificationRecord(t, msgWithCCV2, signer2)
	err = storage.SaveCommitVerification(ctx, record2, aggregationKey)
	require.NoError(t, err)

	records, err := storage.ListCommitVerificationByAggregationKey(ctx, messageID, aggregationKey)
	require.NoError(t, err)
	require.Len(t, records, 2)

	foundSigner1 := false
	foundSigner2 := false
	for _, rec := range records {
		if bytes.Equal(rec.SignerIdentifier.Identifier, record1.SignerIdentifier.Identifier) {
			foundSigner1 = true
			assertCommitVerificationRecordEqual(t, record1, rec, "Signer1")
		}
		if bytes.Equal(rec.SignerIdentifier.Identifier, record2.SignerIdentifier.Identifier) {
			foundSigner2 = true
			assertCommitVerificationRecordEqual(t, record2, rec, "Signer2")
		}
	}
	require.True(t, foundSigner1, "Should find record from signer1")
	require.True(t, foundSigner2, "Should find record from signer2")
}

func TestListCommitVerificationByAggregationKey_DifferentAggregationKey(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	message := createTestProtocolMessage()
	signer1 := newTestSigner(t)
	signer2 := newTestSigner(t)

	msgWithCCV1 := createTestMessageWithCCV(t, message, signer1)
	messageID := getMessageIDFromProto(t, msgWithCCV1)

	record1 := createTestCommitVerificationRecord(t, msgWithCCV1, signer1)
	aggregationKey1 := "aggregationKey1"
	err := storage.SaveCommitVerification(ctx, record1, aggregationKey1)
	require.NoError(t, err)

	msgWithCCV2 := createTestMessageWithCCV(t, message, signer2)
	aggregationKey2 := "aggregationKey2"
	record2 := createTestCommitVerificationRecord(t, msgWithCCV2, signer2)
	err = storage.SaveCommitVerification(ctx, record2, aggregationKey2)
	require.NoError(t, err)

	records, err := storage.ListCommitVerificationByAggregationKey(ctx, messageID, aggregationKey1)
	require.NoError(t, err)
	require.Len(t, records, 1)

	records, err = storage.ListCommitVerificationByAggregationKey(ctx, messageID, aggregationKey2)
	require.NoError(t, err)
	require.Len(t, records, 1)
}

func TestListCommitVerificationByAggregationKey_DifferentAggregationKey_SameSigner(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	message := createTestProtocolMessage()
	signer1 := newTestSigner(t)

	msgWithCCV1 := createTestMessageWithCCV(t, message, signer1)
	messageID := getMessageIDFromProto(t, msgWithCCV1)

	record1 := createTestCommitVerificationRecord(t, msgWithCCV1, signer1)
	aggregationKey1 := "aggregationKey1"
	err := storage.SaveCommitVerification(ctx, record1, aggregationKey1)
	require.NoError(t, err)

	aggregationKey2 := "aggregationKey2"
	err = storage.SaveCommitVerification(ctx, record1, aggregationKey2)
	require.NoError(t, err)

	records, err := storage.ListCommitVerificationByAggregationKey(ctx, messageID, aggregationKey1)
	require.NoError(t, err)
	require.Len(t, records, 1)

	records, err = storage.ListCommitVerificationByAggregationKey(ctx, messageID, aggregationKey2)
	require.NoError(t, err)
	require.Len(t, records, 1)
}

func TestListCommitVerificationByMessageID_EmptyResults(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	records, err := storage.ListCommitVerificationByAggregationKey(ctx, []byte("nonexistent"), "")
	require.NoError(t, err)
	require.Empty(t, records)
}

func TestQueryAggregatedReports_NilToken(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	result, err := storage.QueryAggregatedReports(ctx, 0)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Empty(t, result.Reports)
	require.False(t, result.HasMore)
}

func TestQueryAggregatedReports_Pagination(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	signer := newTestSigner(t)

	for i := range 15 {
		message := createTestProtocolMessage()
		message.SequenceNumber = protocol.SequenceNumber(i)
		msgWithCCV := createTestMessageWithCCV(t, message, signer)
		messageID := getMessageIDFromProto(t, msgWithCCV)
		aggregationKey := protocol.ByteSlice(messageID).String()
		record := createTestCommitVerificationRecord(t, msgWithCCV, signer)

		err := storage.SaveCommitVerification(ctx, record, aggregationKey)
		require.NoError(t, err)

		report := &model.CommitAggregatedReport{
			MessageID:     messageID,
			Verifications: []*model.CommitVerificationRecord{record},
		}

		err = storage.SubmitAggregatedReport(ctx, report)
		require.NoError(t, err)

		time.Sleep(5 * time.Millisecond)
	}

	result, err := storage.QueryAggregatedReports(ctx, 0)
	require.NoError(t, err)
	require.Len(t, result.Reports, 10)
	require.True(t, result.HasMore)

	for _, report := range result.Reports {
		require.Len(t, report.Verifications, 1)
		require.NotEmpty(t, report.MessageID)
	}

	lastSequence := result.Reports[len(result.Reports)-1].Sequence
	result2, err := storage.QueryAggregatedReports(ctx, lastSequence+1)
	require.NoError(t, err)
	require.Len(t, result2.Reports, 5)
	require.False(t, result2.HasMore)

	for _, report := range result2.Reports {
		require.Len(t, report.Verifications, 1)
		require.NotEmpty(t, report.MessageID)
	}
}

func TestGetCCVData_Found(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t)
	message := createTestProtocolMessage()
	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	messageID := getMessageIDFromProto(t, msgWithCCV)
	aggregationKey := protocol.ByteSlice(messageID).String()
	record := createTestCommitVerificationRecord(t, msgWithCCV, signer)

	err := storage.SaveCommitVerification(ctx, record, aggregationKey)
	require.NoError(t, err)

	report := &model.CommitAggregatedReport{
		MessageID:     messageID,
		Verifications: []*model.CommitVerificationRecord{record},
	}

	err = storage.SubmitAggregatedReport(ctx, report)
	require.NoError(t, err)

	retrieved, err := storage.GetCommitAggregatedReportByMessageID(ctx, messageID[:])
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Len(t, retrieved.Verifications, 1)
	require.Equal(t, messageID[:], retrieved.MessageID)
	assertCommitVerificationRecordEqual(t, record, retrieved.Verifications[0], "GetCCVData_Found")
}

func TestGetCCVData_NotFound(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	retrieved, err := storage.GetCommitAggregatedReportByMessageID(ctx, []byte("nonexistent"))
	require.NoError(t, err)
	require.Nil(t, retrieved)
}

func TestSubmitReport_HappyPath(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t)
	message := createTestProtocolMessage()
	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	messageID := getMessageIDFromProto(t, msgWithCCV)
	aggregationKey := protocol.ByteSlice(messageID).String()
	record := createTestCommitVerificationRecord(t, msgWithCCV, signer)

	err := storage.SaveCommitVerification(ctx, record, aggregationKey)
	require.NoError(t, err)

	report := &model.CommitAggregatedReport{
		MessageID:     messageID,
		Verifications: []*model.CommitVerificationRecord{record},
	}

	err = storage.SubmitAggregatedReport(ctx, report)
	require.NoError(t, err)

	retrieved, err := storage.GetCommitAggregatedReportByMessageID(ctx, messageID[:])
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Equal(t, messageID[:], retrieved.MessageID)
	require.Len(t, retrieved.Verifications, 1)
	assertCommitVerificationRecordEqual(t, record, retrieved.Verifications[0], "SubmitReport_HappyPath")
}

func TestSubmitReport_DuplicateHandling(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t)
	message := createTestProtocolMessage()
	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	messageID := getMessageIDFromProto(t, msgWithCCV)
	aggregationKey := protocol.ByteSlice(messageID).String()
	record := createTestCommitVerificationRecord(t, msgWithCCV, signer)

	err := storage.SaveCommitVerification(ctx, record, aggregationKey)
	require.NoError(t, err)

	report := &model.CommitAggregatedReport{
		MessageID:     messageID,
		Verifications: []*model.CommitVerificationRecord{record},
	}

	err = storage.SubmitAggregatedReport(ctx, report)
	require.NoError(t, err)

	err = storage.SubmitAggregatedReport(ctx, report)
	require.NoError(t, err)

	result, err := storage.QueryAggregatedReports(ctx, 0)
	require.NoError(t, err)
	require.Len(t, result.Reports, 1, "Should have exactly 1 report after duplicate submission")
	require.Equal(t, messageID[:], result.Reports[0].MessageID)
}

func TestListOrphanedKeys(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	signer := newTestSigner(t)

	message1 := createTestProtocolMessage()
	message1.SequenceNumber = 1
	msgWithCCV1 := createTestMessageWithCCV(t, message1, signer)
	messageID1 := getMessageIDFromProto(t, msgWithCCV1)
	aggregationKey1 := protocol.ByteSlice(messageID1).String()
	orphanRecord := createTestCommitVerificationRecord(t, msgWithCCV1, signer)
	err := storage.SaveCommitVerification(ctx, orphanRecord, aggregationKey1)
	require.NoError(t, err)

	aggregationKey1a := "different"
	err = storage.SaveCommitVerification(ctx, orphanRecord, aggregationKey1a)
	require.NoError(t, err)

	message2 := createTestProtocolMessage()
	message2.SequenceNumber = 2
	msgWithCCV2 := createTestMessageWithCCV(t, message2, signer)
	messageID2 := getMessageIDFromProto(t, msgWithCCV2)
	aggregationKey2 := protocol.ByteSlice(messageID2).String()
	aggregatedRecord := createTestCommitVerificationRecord(t, msgWithCCV2, signer)
	err = storage.SaveCommitVerification(ctx, aggregatedRecord, aggregationKey2)
	require.NoError(t, err)

	aggregationKey2a := "different"
	err = storage.SaveCommitVerification(ctx, aggregatedRecord, aggregationKey2a)
	require.NoError(t, err)

	report := &model.CommitAggregatedReport{
		MessageID:     messageID2,
		Verifications: []*model.CommitVerificationRecord{aggregatedRecord},
	}
	err = storage.SubmitAggregatedReport(ctx, report)
	require.NoError(t, err)

	orphanKeysCh, errCh := storage.ListOrphanedKeys(ctx, time.Time{}, 100)

	orphanedKeys := []model.OrphanedKey{}
	for keys := range orphanKeysCh {
		orphanedKeys = append(orphanedKeys, keys)
	}

	err = <-errCh
	require.NoError(t, err)

	require.Len(t, orphanedKeys, 2)
	require.Equal(t, messageID1[:], orphanedKeys[0].MessageID)
	require.Equal(t, aggregationKey1, orphanedKeys[0].AggregationKey)

	require.Equal(t, messageID1[:], orphanedKeys[1].MessageID)
	require.Equal(t, aggregationKey1a, orphanedKeys[1].AggregationKey)
}

func TestListOrphanedKeys_ContextCancellation(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	messageIDCh, errCh := storage.ListOrphanedKeys(ctx, time.Time{}, 100)

	for range messageIDCh {
	}

	err := <-errCh
	require.Error(t, err)
}

func TestListOrphanedKeys_FiltersRecordsOlderThanCutoff(t *testing.T) {
	storage, ds, cleanup := setupTestDBWithDatabase(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t)

	type recordData struct {
		messageID      []byte
		aggregationKey string
	}
	orphans := make([]recordData, 3)

	for i := range 3 {
		message := createTestProtocolMessage()
		message.SequenceNumber = protocol.SequenceNumber(i + 1)
		msgWithCCV := createTestMessageWithCCV(t, message, signer)
		messageID := getMessageIDFromProto(t, msgWithCCV)
		aggregationKey := protocol.ByteSlice(messageID).String()
		record := createTestCommitVerificationRecord(t, msgWithCCV, signer)
		err := storage.SaveCommitVerification(ctx, record, aggregationKey)
		require.NoError(t, err)

		orphans[i] = recordData{
			messageID:      messageID,
			aggregationKey: aggregationKey,
		}
	}

	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	for i := range 2 {
		_, err := ds.ExecContext(ctx,
			"UPDATE commit_verification_records SET created_at = $1 WHERE message_id = $2",
			twoHoursAgo,
			protocol.ByteSlice(orphans[i].messageID).String(),
		)
		require.NoError(t, err)
	}

	cutoff := time.Now().Add(-1 * time.Hour)
	orphanKeysCh, errCh := storage.ListOrphanedKeys(ctx, cutoff, 100)

	orphanedKeys := []model.OrphanedKey{}
	for key := range orphanKeysCh {
		orphanedKeys = append(orphanedKeys, key)
	}
	err := <-errCh
	require.NoError(t, err)

	require.Len(t, orphanedKeys, 1, "Should only return orphan newer than cutoff")
	require.Equal(t, orphans[2].aggregationKey, orphanedKeys[0].AggregationKey,
		"Should return only the recent orphan")
}

func TestListOrphanedKeys_PaginationReturnsAllResults(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t)

	const totalOrphans = 7

	for i := range totalOrphans {
		message := createTestProtocolMessage()
		message.SequenceNumber = protocol.SequenceNumber(i + 1)
		msgWithCCV := createTestMessageWithCCV(t, message, signer)
		messageID := getMessageIDFromProto(t, msgWithCCV)
		aggregationKey := protocol.ByteSlice(messageID).String()
		record := createTestCommitVerificationRecord(t, msgWithCCV, signer)
		err := storage.SaveCommitVerification(ctx, record, aggregationKey)
		require.NoError(t, err)
	}

	// Use pageSize=2 so pagination is exercised with a small number of records
	orphanKeysCh, errCh := storage.ListOrphanedKeys(ctx, time.Time{}, 2)

	orphanedKeys := make([]model.OrphanedKey, 0, totalOrphans)
	for key := range orphanKeysCh {
		orphanedKeys = append(orphanedKeys, key)
	}
	err := <-errCh
	require.NoError(t, err)

	require.Len(t, orphanedKeys, totalOrphans, "Paginated scan must return all orphans")

	for i := 1; i < len(orphanedKeys); i++ {
		prev := protocol.ByteSlice(orphanedKeys[i-1].MessageID).String() + orphanedKeys[i-1].AggregationKey
		curr := protocol.ByteSlice(orphanedKeys[i].MessageID).String() + orphanedKeys[i].AggregationKey
		require.True(t, prev < curr, "Results must be in sorted order: %s >= %s", prev, curr)
	}
}

func TestBatchOperations_MultipleSigners(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	message := createTestProtocolMessage()

	signers := []*testFixture{
		newTestSigner(t),
		newTestSigner(t),
		newTestSigner(t),
	}

	records := []*model.CommitVerificationRecord{}
	var messageID []byte
	for _, signer := range signers {
		msgWithCCV := createTestMessageWithCCV(t, message, signer)
		messageID = getMessageIDFromProto(t, msgWithCCV)
		aggregationKey := protocol.ByteSlice(messageID).String()
		record := createTestCommitVerificationRecord(t, msgWithCCV, signer)
		err := storage.SaveCommitVerification(ctx, record, aggregationKey)
		require.NoError(t, err)
		records = append(records, record)
	}

	report := &model.CommitAggregatedReport{
		MessageID:     messageID,
		Verifications: records,
	}

	err := storage.SubmitAggregatedReport(ctx, report)
	require.NoError(t, err)

	retrieved, err := storage.GetCommitAggregatedReportByMessageID(ctx, messageID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Len(t, retrieved.Verifications, 3)
	require.Equal(t, messageID, retrieved.MessageID)

	for i, expectedRecord := range records {
		found := false
		for _, actualRecord := range retrieved.Verifications {
			if bytes.Equal(actualRecord.SignerIdentifier.Identifier, expectedRecord.SignerIdentifier.Identifier) {
				assertCommitVerificationRecordEqual(t, expectedRecord, actualRecord, fmt.Sprintf("BatchOperations_Signer%d", i))
				found = true
				break
			}
		}
		require.True(t, found, "Should find record for signer %d", i)
	}

	require.Equal(t, protocol.UnknownAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14}, retrieved.GetMessageExecutorAddress(), "MessageExecutorAddress should match that of the last signer")
	for i, addr := range retrieved.GetMessageCCVAddresses() {
		require.Equal(t, protocol.UnknownAddress{0x02, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}, addr, "MessageCCVAddresses[%d] should match that of the last signer", i)
	}
}

func TestSubmitReport_NilReport(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	err := storage.SubmitAggregatedReport(ctx, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "aggregated report cannot be nil")
}

func TestQueryAggregatedReports_SinceSequence(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t)

	var firstReportSeq int64

	for i := range 5 {
		message := createTestProtocolMessage()
		message.SequenceNumber = protocol.SequenceNumber(i)
		msgWithCCV := createTestMessageWithCCV(t, message, signer)
		aggregationKey := protocol.ByteSlice(getMessageIDFromProto(t, msgWithCCV)).String()
		record := createTestCommitVerificationRecord(t, msgWithCCV, signer)

		err := storage.SaveCommitVerification(ctx, record, aggregationKey)
		require.NoError(t, err)

		protocolMessage, err := ccvcommon.MapProtoMessageToProtocolMessage(msgWithCCV.Message)
		require.NoError(t, err)
		messageID, err := protocolMessage.MessageID()
		require.NoError(t, err)

		report := &model.CommitAggregatedReport{
			MessageID:     messageID[:],
			Verifications: []*model.CommitVerificationRecord{record},
		}

		err = storage.SubmitAggregatedReport(ctx, report)
		require.NoError(t, err)

		if i == 0 {
			retrieved, err := storage.GetCommitAggregatedReportByMessageID(ctx, messageID[:])
			require.NoError(t, err)
			firstReportSeq = retrieved.Sequence
		}

		time.Sleep(5 * time.Millisecond)
	}

	result, err := storage.QueryAggregatedReports(ctx, firstReportSeq+2)
	require.NoError(t, err)
	require.Len(t, result.Reports, 3)

	for _, report := range result.Reports {
		require.Len(t, report.Verifications, 1)
		require.GreaterOrEqual(t, report.Sequence, firstReportSeq+2, "All reports should be at or after the requested sequence")
	}
}

func TestDatabaseStorage_PageSize(t *testing.T) {
	ds, cleanup := testutil.SetupTestPostgresDB(t)
	defer cleanup()

	customPageSize := 25
	storage := NewDatabaseStorage(ds, customPageSize, 10*time.Second, logger.TestSugared(t))

	require.Equal(t, customPageSize, storage.pageSize)
}

// TestSubmitAggregatedReport_FiltersByVersion verifies that when submitting an aggregated report,
// only verification records matching the report's CCVVersion are included, even when a signer
// has multiple records with different versions for the same messageID.
func TestSubmitAggregatedReport_FiltersByVersion(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	message := createTestProtocolMessage()

	// Create three signers
	signer1 := newTestSigner(t)
	signer2 := newTestSigner(t)
	signer3 := newTestSigner(t)

	version1 := []byte{0x01, 0x02, 0x03, 0x04}
	version2 := []byte{0x05, 0x06, 0x07, 0x08}

	// Signer1 commits with version1
	msgWithCCV1 := createTestMessageWithCCV(t, message, signer1)
	msgWithCCV1.CcvVersion = version1
	messageID := getMessageIDFromProto(t, msgWithCCV1)
	aggregationKey1 := protocol.ByteSlice(messageID).String()

	record1v1 := createTestCommitVerificationRecord(t, msgWithCCV1, signer1)
	record1v1.CCVVersion = version1
	err := storage.SaveCommitVerification(ctx, record1v1, aggregationKey1)
	require.NoError(t, err)

	// Sleep to ensure different seq_num
	time.Sleep(10 * time.Millisecond)

	// Signer1 also commits with version2 (different aggregation key)
	record1v2 := createTestCommitVerificationRecord(t, msgWithCCV1, signer1)
	record1v2.CCVVersion = version2
	record1v2.MessageID = messageID
	err = storage.SaveCommitVerification(ctx, record1v2, "aggregation_key_v2")
	require.NoError(t, err)

	// Signer2 commits with version1
	msgWithCCV2 := createTestMessageWithCCV(t, message, signer2)
	msgWithCCV2.CcvVersion = version1
	record2v1 := createTestCommitVerificationRecord(t, msgWithCCV2, signer2)
	record2v1.CCVVersion = version1
	record2v1.MessageID = messageID
	err = storage.SaveCommitVerification(ctx, record2v1, aggregationKey1)
	require.NoError(t, err)

	// Signer3 commits with version1
	msgWithCCV3 := createTestMessageWithCCV(t, message, signer3)
	msgWithCCV3.CcvVersion = version1
	record3v1 := createTestCommitVerificationRecord(t, msgWithCCV3, signer3)
	record3v1.CCVVersion = version1
	record3v1.MessageID = messageID
	err = storage.SaveCommitVerification(ctx, record3v1, aggregationKey1)
	require.NoError(t, err)

	// Submit aggregated report with version1
	report := &model.CommitAggregatedReport{
		MessageID:     messageID,
		Verifications: []*model.CommitVerificationRecord{record1v1, record2v1, record3v1},
	}
	err = storage.SubmitAggregatedReport(ctx, report)
	require.NoError(t, err)

	// Retrieve and verify
	retrieved, err := storage.GetCommitAggregatedReportByMessageID(ctx, messageID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Len(t, retrieved.Verifications, 3)

	// All verifications should have version1
	for _, v := range retrieved.Verifications {
		require.Equal(t, version1, v.CCVVersion)
	}

	// Verify signer1's record is the version1 record, not version2
	var foundSigner1 bool
	for _, v := range retrieved.Verifications {
		if bytes.Equal(v.SignerIdentifier.Identifier, record1v1.SignerIdentifier.Identifier) {
			foundSigner1 = true
			require.Equal(t, version1, v.CCVVersion)
		}
	}
	require.True(t, foundSigner1)
	require.Equal(t, version1, retrieved.GetVersion())
}

// TestSubmitAggregatedReport_FailsWhenVersionMismatch tests that submitting an aggregated
// report fails when the database doesn't have records matching the expected version.
func TestSubmitAggregatedReport_FailsWhenVersionMismatch(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	signer := newTestSigner(t)
	message := createTestProtocolMessage()

	// Create and save verification with version 1
	version1 := []byte{0x01, 0x02, 0x03, 0x04}
	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	msgWithCCV.CcvVersion = version1
	messageID := getMessageIDFromProto(t, msgWithCCV)
	aggregationKey := protocol.ByteSlice(messageID).String()

	record := createTestCommitVerificationRecord(t, msgWithCCV, signer)
	record.CCVVersion = version1
	err := storage.SaveCommitVerification(ctx, record, aggregationKey)
	require.NoError(t, err)

	// Try to submit aggregated report with different version
	version2 := []byte{0x05, 0x06, 0x07, 0x08}
	record.CCVVersion = version2

	aggregatedReport := &model.CommitAggregatedReport{
		MessageID:     messageID,
		Verifications: []*model.CommitVerificationRecord{record},
	}

	// This should fail because batchGetVerificationRecordIDs won't find a record
	// with version2 for this signer
	err = storage.SubmitAggregatedReport(ctx, aggregatedReport)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to find verification record ID")
}

func TestGetCommitAggregatedReportByMessageID_ReturnsOnlyLatestReport(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	message := createTestProtocolMessage()

	signer1 := newTestSigner(t)
	signer2 := newTestSigner(t)
	signer3 := newTestSigner(t)

	msgWithCCV1 := createTestMessageWithCCV(t, message, signer1)
	messageID := getMessageIDFromProto(t, msgWithCCV1)
	aggregationKey := protocol.ByteSlice(messageID).String()

	record1 := createTestCommitVerificationRecord(t, msgWithCCV1, signer1)
	require.NoError(t, storage.SaveCommitVerification(ctx, record1, aggregationKey))

	msgWithCCV2 := createTestMessageWithCCV(t, message, signer2)
	record2 := createTestCommitVerificationRecord(t, msgWithCCV2, signer2)
	record2.MessageID = messageID
	require.NoError(t, storage.SaveCommitVerification(ctx, record2, aggregationKey))

	msgWithCCV3 := createTestMessageWithCCV(t, message, signer3)
	record3 := createTestCommitVerificationRecord(t, msgWithCCV3, signer3)
	record3.MessageID = messageID
	require.NoError(t, storage.SaveCommitVerification(ctx, record3, aggregationKey))

	oldReport := &model.CommitAggregatedReport{
		MessageID:     messageID,
		Verifications: []*model.CommitVerificationRecord{record1, record2, record3},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, oldReport))

	retrieved, err := storage.GetCommitAggregatedReportByMessageID(ctx, messageID)
	require.NoError(t, err)
	require.Len(t, retrieved.Verifications, 3)
	oldSeq := retrieved.Sequence

	newReport := &model.CommitAggregatedReport{
		MessageID:     messageID,
		Verifications: []*model.CommitVerificationRecord{record2, record3},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, newReport))

	retrieved, err = storage.GetCommitAggregatedReportByMessageID(ctx, messageID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Greater(t, retrieved.Sequence, oldSeq)
	require.Len(t, retrieved.Verifications, 2, "should return only the latest report's verifications")

	signerAddrs := make(map[string]struct{})
	for _, v := range retrieved.Verifications {
		signerAddrs[common.BytesToAddress(v.SignerIdentifier.Identifier).Hex()] = struct{}{}
	}
	_, hasSigner2 := signerAddrs[signer2.Signer.Address]
	_, hasSigner3 := signerAddrs[signer3.Signer.Address]
	require.True(t, hasSigner2, "signer2 should be in the latest report")
	require.True(t, hasSigner3, "signer3 should be in the latest report")
}

func TestGetBatchAggregatedReportByMessageIDs_ReturnsOnlyLatestReportPerMessage(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	signer1 := newTestSigner(t)
	signer2 := newTestSigner(t)
	signer3 := newTestSigner(t)

	msg1 := createTestProtocolMessage()
	msg1.SequenceNumber = 100

	msgWithCCV1s1 := createTestMessageWithCCV(t, msg1, signer1)
	messageID1 := getMessageIDFromProto(t, msgWithCCV1s1)
	aggKey1 := protocol.ByteSlice(messageID1).String()

	r1s1 := createTestCommitVerificationRecord(t, msgWithCCV1s1, signer1)
	require.NoError(t, storage.SaveCommitVerification(ctx, r1s1, aggKey1))

	msgWithCCV1s2 := createTestMessageWithCCV(t, msg1, signer2)
	r1s2 := createTestCommitVerificationRecord(t, msgWithCCV1s2, signer2)
	r1s2.MessageID = messageID1
	require.NoError(t, storage.SaveCommitVerification(ctx, r1s2, aggKey1))

	msgWithCCV1s3 := createTestMessageWithCCV(t, msg1, signer3)
	r1s3 := createTestCommitVerificationRecord(t, msgWithCCV1s3, signer3)
	r1s3.MessageID = messageID1
	require.NoError(t, storage.SaveCommitVerification(ctx, r1s3, aggKey1))

	oldReport1 := &model.CommitAggregatedReport{
		MessageID:     messageID1,
		Verifications: []*model.CommitVerificationRecord{r1s1, r1s2, r1s3},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, oldReport1))

	newReport1 := &model.CommitAggregatedReport{
		MessageID:     messageID1,
		Verifications: []*model.CommitVerificationRecord{r1s2, r1s3},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, newReport1))

	msg2 := createTestProtocolMessage()
	msg2.SequenceNumber = 200

	msgWithCCV2s1 := createTestMessageWithCCV(t, msg2, signer1)
	messageID2 := getMessageIDFromProto(t, msgWithCCV2s1)
	aggKey2 := protocol.ByteSlice(messageID2).String()

	r2s1 := createTestCommitVerificationRecord(t, msgWithCCV2s1, signer1)
	require.NoError(t, storage.SaveCommitVerification(ctx, r2s1, aggKey2))

	msgWithCCV2s2 := createTestMessageWithCCV(t, msg2, signer2)
	r2s2 := createTestCommitVerificationRecord(t, msgWithCCV2s2, signer2)
	r2s2.MessageID = messageID2
	require.NoError(t, storage.SaveCommitVerification(ctx, r2s2, aggKey2))

	singleReport2 := &model.CommitAggregatedReport{
		MessageID:     messageID2,
		Verifications: []*model.CommitVerificationRecord{r2s1, r2s2},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, singleReport2))

	results, err := storage.GetBatchAggregatedReportByMessageIDs(ctx, []model.MessageID{messageID1, messageID2})
	require.NoError(t, err)
	require.Len(t, results, 2)

	msgID1Hex := protocol.ByteSlice(messageID1).String()
	report1 := results[msgID1Hex]
	require.NotNil(t, report1)
	require.Len(t, report1.Verifications, 2, "message1 should return only the latest report with 2 verifications")

	msgID2Hex := protocol.ByteSlice(messageID2).String()
	report2 := results[msgID2Hex]
	require.NotNil(t, report2)
	require.Len(t, report2.Verifications, 2, "message2 should return the single report with 2 verifications")
}

func TestGetCommitAggregatedReportByMessageID_DisjointVerifications_ReturnsOnlyLatest(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	message := createTestProtocolMessage()

	signer1 := newTestSigner(t)
	signer2 := newTestSigner(t)
	signer3 := newTestSigner(t)
	signer4 := newTestSigner(t)
	signer5 := newTestSigner(t)

	msgWithCCV1 := createTestMessageWithCCV(t, message, signer1)
	messageID := getMessageIDFromProto(t, msgWithCCV1)
	aggregationKey := protocol.ByteSlice(messageID).String()

	record1 := createTestCommitVerificationRecord(t, msgWithCCV1, signer1)
	require.NoError(t, storage.SaveCommitVerification(ctx, record1, aggregationKey))

	msgWithCCV2 := createTestMessageWithCCV(t, message, signer2)
	record2 := createTestCommitVerificationRecord(t, msgWithCCV2, signer2)
	record2.MessageID = messageID
	require.NoError(t, storage.SaveCommitVerification(ctx, record2, aggregationKey))

	firstReport := &model.CommitAggregatedReport{
		MessageID:     messageID,
		Verifications: []*model.CommitVerificationRecord{record1, record2},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, firstReport))

	msgWithCCV3 := createTestMessageWithCCV(t, message, signer3)
	record3 := createTestCommitVerificationRecord(t, msgWithCCV3, signer3)
	record3.MessageID = messageID
	require.NoError(t, storage.SaveCommitVerification(ctx, record3, aggregationKey))

	msgWithCCV4 := createTestMessageWithCCV(t, message, signer4)
	record4 := createTestCommitVerificationRecord(t, msgWithCCV4, signer4)
	record4.MessageID = messageID
	require.NoError(t, storage.SaveCommitVerification(ctx, record4, aggregationKey))

	msgWithCCV5 := createTestMessageWithCCV(t, message, signer5)
	record5 := createTestCommitVerificationRecord(t, msgWithCCV5, signer5)
	record5.MessageID = messageID
	require.NoError(t, storage.SaveCommitVerification(ctx, record5, aggregationKey))

	secondReport := &model.CommitAggregatedReport{
		MessageID:     messageID,
		Verifications: []*model.CommitVerificationRecord{record3, record4, record5},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, secondReport))

	retrieved, err := storage.GetCommitAggregatedReportByMessageID(ctx, messageID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Len(t, retrieved.Verifications, 3, "should return only the latest report's 3 verifications, not all 5")

	signerAddrs := make(map[string]struct{})
	for _, v := range retrieved.Verifications {
		signerAddrs[common.BytesToAddress(v.SignerIdentifier.Identifier).Hex()] = struct{}{}
	}
	_, hasSigner3 := signerAddrs[signer3.Signer.Address]
	_, hasSigner4 := signerAddrs[signer4.Signer.Address]
	_, hasSigner5 := signerAddrs[signer5.Signer.Address]
	require.True(t, hasSigner3, "signer3 should be in the latest report")
	require.True(t, hasSigner4, "signer4 should be in the latest report")
	require.True(t, hasSigner5, "signer5 should be in the latest report")

	_, hasSigner1 := signerAddrs[signer1.Signer.Address]
	_, hasSigner2 := signerAddrs[signer2.Signer.Address]
	require.False(t, hasSigner1, "signer1 from old report should not appear")
	require.False(t, hasSigner2, "signer2 from old report should not appear")
}

func TestGetBatchAggregatedReportByMessageIDs_DisjointVerifications_ReturnsOnlyLatest(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	signer1 := newTestSigner(t)
	signer2 := newTestSigner(t)
	signer3 := newTestSigner(t)
	signer4 := newTestSigner(t)
	signer5 := newTestSigner(t)

	msg1 := createTestProtocolMessage()
	msg1.SequenceNumber = 300

	msgWithCCV1s1 := createTestMessageWithCCV(t, msg1, signer1)
	messageID1 := getMessageIDFromProto(t, msgWithCCV1s1)
	aggKey1 := protocol.ByteSlice(messageID1).String()

	r1s1 := createTestCommitVerificationRecord(t, msgWithCCV1s1, signer1)
	require.NoError(t, storage.SaveCommitVerification(ctx, r1s1, aggKey1))

	msgWithCCV1s2 := createTestMessageWithCCV(t, msg1, signer2)
	r1s2 := createTestCommitVerificationRecord(t, msgWithCCV1s2, signer2)
	r1s2.MessageID = messageID1
	require.NoError(t, storage.SaveCommitVerification(ctx, r1s2, aggKey1))

	oldReport1 := &model.CommitAggregatedReport{
		MessageID:     messageID1,
		Verifications: []*model.CommitVerificationRecord{r1s1, r1s2},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, oldReport1))

	msgWithCCV1s3 := createTestMessageWithCCV(t, msg1, signer3)
	r1s3 := createTestCommitVerificationRecord(t, msgWithCCV1s3, signer3)
	r1s3.MessageID = messageID1
	require.NoError(t, storage.SaveCommitVerification(ctx, r1s3, aggKey1))

	msgWithCCV1s4 := createTestMessageWithCCV(t, msg1, signer4)
	r1s4 := createTestCommitVerificationRecord(t, msgWithCCV1s4, signer4)
	r1s4.MessageID = messageID1
	require.NoError(t, storage.SaveCommitVerification(ctx, r1s4, aggKey1))

	msgWithCCV1s5 := createTestMessageWithCCV(t, msg1, signer5)
	r1s5 := createTestCommitVerificationRecord(t, msgWithCCV1s5, signer5)
	r1s5.MessageID = messageID1
	require.NoError(t, storage.SaveCommitVerification(ctx, r1s5, aggKey1))

	newReport1 := &model.CommitAggregatedReport{
		MessageID:     messageID1,
		Verifications: []*model.CommitVerificationRecord{r1s3, r1s4, r1s5},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, newReport1))

	msg2 := createTestProtocolMessage()
	msg2.SequenceNumber = 400

	msgWithCCV2s1 := createTestMessageWithCCV(t, msg2, signer1)
	messageID2 := getMessageIDFromProto(t, msgWithCCV2s1)
	aggKey2 := protocol.ByteSlice(messageID2).String()

	r2s1 := createTestCommitVerificationRecord(t, msgWithCCV2s1, signer1)
	require.NoError(t, storage.SaveCommitVerification(ctx, r2s1, aggKey2))

	msgWithCCV2s2 := createTestMessageWithCCV(t, msg2, signer2)
	r2s2 := createTestCommitVerificationRecord(t, msgWithCCV2s2, signer2)
	r2s2.MessageID = messageID2
	require.NoError(t, storage.SaveCommitVerification(ctx, r2s2, aggKey2))

	singleReport2 := &model.CommitAggregatedReport{
		MessageID:     messageID2,
		Verifications: []*model.CommitVerificationRecord{r2s1, r2s2},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, singleReport2))

	results, err := storage.GetBatchAggregatedReportByMessageIDs(ctx, []model.MessageID{messageID1, messageID2})
	require.NoError(t, err)
	require.Len(t, results, 2)

	msgID1Hex := protocol.ByteSlice(messageID1).String()
	report1 := results[msgID1Hex]
	require.NotNil(t, report1)
	require.Len(t, report1.Verifications, 3, "message1 should return only the latest report with 3 verifications, not all 5")

	signerAddrs := make(map[string]struct{})
	for _, v := range report1.Verifications {
		signerAddrs[common.BytesToAddress(v.SignerIdentifier.Identifier).Hex()] = struct{}{}
	}
	_, hasSigner3 := signerAddrs[signer3.Signer.Address]
	_, hasSigner4 := signerAddrs[signer4.Signer.Address]
	_, hasSigner5 := signerAddrs[signer5.Signer.Address]
	require.True(t, hasSigner3, "signer3 should be in the latest report for message1")
	require.True(t, hasSigner4, "signer4 should be in the latest report for message1")
	require.True(t, hasSigner5, "signer5 should be in the latest report for message1")

	_, hasSigner1 := signerAddrs[signer1.Signer.Address]
	_, hasSigner2 := signerAddrs[signer2.Signer.Address]
	require.False(t, hasSigner1, "signer1 from old report should not appear for message1")
	require.False(t, hasSigner2, "signer2 from old report should not appear for message1")

	msgID2Hex := protocol.ByteSlice(messageID2).String()
	report2 := results[msgID2Hex]
	require.NotNil(t, report2)
	require.Len(t, report2.Verifications, 2, "message2 should return the single report with 2 verifications")
}
