package postgres

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	pkgcommon "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
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

func newTestSigner(tb testing.TB) *testFixture {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	signerAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
	return &testFixture{
		Signer: model.Signer{Address: signerAddress.Hex()},
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

func createTestMessageWithCCV(tb testing.TB, message *protocol.Message, signer *testFixture) *committeepb.CommitteeVerifierNodeResult {
	tb.Helper()
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
	if err != nil {
		tb.Fatalf("compute CCV and executor hash: %v", err)
	}
	var tokenTransferEncoded []byte
	if message.TokenTransfer != nil {
		tokenTransferEncoded, err = message.TokenTransfer.Encode()
		if err != nil {
			tb.Fatalf("encode token transfer: %v", err)
		}
	}
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
			TokenTransfer:        tokenTransferEncoded,
			DataLength:           uint32(message.DataLength),
			Data:                 message.Data[:],
		},
		CcvVersion:      ccvVersion,
		CcvAddresses:    ccvAddresses,
		ExecutorAddress: executorAddress,
	}
	protocolMessage, err := ccvcommon.MapProtoMessageToProtocolMessage(msgWithCCV.Message)
	if err != nil {
		tb.Fatalf("map proto message: %v", err)
	}
	messageID, err := protocolMessage.MessageID()
	if err != nil {
		tb.Fatalf("message ID: %v", err)
	}
	r32, s32, signerAddr, err := protocol.SignV27(messageID[:], signer.key)
	if err != nil {
		tb.Fatalf("sign: %v", err)
	}
	sigData := protocol.Data{
		R:      r32,
		S:      s32,
		Signer: signerAddr,
	}
	signature, err := protocol.EncodeSingleECDSASignature(sigData)
	if err != nil {
		tb.Fatalf("encode signature: %v", err)
	}

	msgWithCCV.Signature = signature
	return msgWithCCV
}

// getMessageIDFromProto is a helper to derive messageID from the proto message.
func getMessageIDFromProto(tb testing.TB, msgWithCCV *committeepb.CommitteeVerifierNodeResult) []byte {
	tb.Helper()
	protocolMessage, err := ccvcommon.MapProtoMessageToProtocolMessage(msgWithCCV.Message)
	if err != nil {
		tb.Fatalf("map proto message: %v", err)
	}
	messageID, err := protocolMessage.MessageID()
	if err != nil {
		tb.Fatalf("message ID: %v", err)
	}
	return messageID[:]
}

func createTestCommitVerificationRecord(tb testing.TB, msgWithCCV *committeepb.CommitteeVerifierNodeResult, signer *testFixture) *model.CommitVerificationRecord {
	signerAddress := common.HexToAddress(signer.Signer.Address)
	record, err := model.CommitVerificationRecordFromProto(msgWithCCV)
	if err != nil {
		tb.Fatalf("commit verification record from proto: %v", err)
	}
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

func setupTestDBWithDatabase(tb testing.TB) (*DatabaseStorage, *sqlx.DB, func()) {
	tb.Helper()
	ds, cleanup := testutil.SetupTestPostgresDB(tb)
	if err := RunMigrations(ds, "postgres"); err != nil {
		cleanup()
		tb.Fatalf("run migrations: %v", err)
	}
	storage := NewDatabaseStorage(ds, 10, 10*time.Second, logger.Sugared(logger.Test(tb)))
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

func TestListCommitVerificationByAggregationKey_ReturnsEmptyForNonexistentMessage(t *testing.T) {
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
			MessageID:      messageID,
			AggregationKey: aggregationKey,
			Verifications:  []*model.CommitVerificationRecord{record},
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
		MessageID:      messageID,
		AggregationKey: aggregationKey,
		Verifications:  []*model.CommitVerificationRecord{record},
	}

	err = storage.SubmitAggregatedReport(ctx, report)
	require.NoError(t, err)

	retrieved, err := storage.GetCommitAggregatedReportByAggregationKey(ctx, messageID[:], aggregationKey)
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

	retrieved, err := storage.GetCommitAggregatedReportByAggregationKey(ctx, []byte("nonexistent"), "nonexistent-key")
	require.ErrorIs(t, err, pkgcommon.ErrNotFound)
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
		MessageID:      messageID,
		AggregationKey: aggregationKey,
		Verifications:  []*model.CommitVerificationRecord{record},
	}

	err = storage.SubmitAggregatedReport(ctx, report)
	require.NoError(t, err)

	retrieved, err := storage.GetCommitAggregatedReportByAggregationKey(ctx, messageID[:], aggregationKey)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Equal(t, messageID[:], retrieved.MessageID)
	require.Len(t, retrieved.Verifications, 1)
	assertCommitVerificationRecordEqual(t, record, retrieved.Verifications[0], "SubmitReport_HappyPath")
}

func TestSubmitReport_DuplicateSubmissionCreatesOnlyOneRow(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := t.Context()
	signer := newTestSigner(t)
	message := createTestProtocolMessage()
	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	messageID := getMessageIDFromProto(t, msgWithCCV)
	aggregationKey := protocol.ByteSlice(messageID).String()
	record := createTestCommitVerificationRecord(t, msgWithCCV, signer)

	err := storage.SaveCommitVerification(ctx, record, aggregationKey)
	require.NoError(t, err)

	report := &model.CommitAggregatedReport{
		MessageID:      messageID,
		AggregationKey: aggregationKey,
		Verifications:  []*model.CommitVerificationRecord{record},
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
		MessageID:      messageID2,
		AggregationKey: aggregationKey2,
		Verifications:  []*model.CommitVerificationRecord{aggregatedRecord},
	}
	err = storage.SubmitAggregatedReport(ctx, report)
	require.NoError(t, err)

	orphanKeysCh, errCh := storage.ListOrphanedKeys(ctx, time.Time{}, 100)

	orphanedKeys := make([]model.OrphanedKey, 0, 3)
	for keys := range orphanKeysCh {
		orphanedKeys = append(orphanedKeys, keys)
	}

	err = <-errCh
	require.NoError(t, err)

	require.Len(t, orphanedKeys, 3, "should find 3 orphans: 2 for message1 + 1 for message2's unmatched aggregation key")

	type orphanID struct {
		messageIDHex   string
		aggregationKey string
	}
	orphanSet := make(map[orphanID]bool)
	for _, key := range orphanedKeys {
		orphanSet[orphanID{
			messageIDHex:   protocol.ByteSlice(key.MessageID).String(),
			aggregationKey: key.AggregationKey,
		}] = true
	}

	require.True(t, orphanSet[orphanID{protocol.ByteSlice(messageID1).String(), aggregationKey1}],
		"should find orphan for (message1, aggregationKey1)")
	require.True(t, orphanSet[orphanID{protocol.ByteSlice(messageID1).String(), aggregationKey1a}],
		"should find orphan for (message1, aggregationKey1a)")
	require.True(t, orphanSet[orphanID{protocol.ByteSlice(messageID2).String(), aggregationKey2a}],
		"should find orphan for (message2, aggregationKey2a)")
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

	orphanedKeys := make([]model.OrphanedKey, 0, 1)
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

	records := make([]*model.CommitVerificationRecord, 0, len(signers))
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

	aggKey := protocol.ByteSlice(messageID).String()
	report := &model.CommitAggregatedReport{
		MessageID:      messageID,
		AggregationKey: aggKey,
		Verifications:  records,
	}

	err := storage.SubmitAggregatedReport(ctx, report)
	require.NoError(t, err)

	retrieved, err := storage.GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggKey)
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
			MessageID:      messageID[:],
			AggregationKey: aggregationKey,
			Verifications:  []*model.CommitVerificationRecord{record},
		}

		err = storage.SubmitAggregatedReport(ctx, report)
		require.NoError(t, err)

		if i == 0 {
			retrieved, err := storage.GetCommitAggregatedReportByAggregationKey(ctx, messageID[:], aggregationKey)
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

// TestSubmitAggregatedReport_FiltersByAggregationKey verifies that when submitting an aggregated report,
// only verification records matching the report's AggregationKey are included, even when a signer
// has multiple records with different aggregation keys for the same messageID.
func TestSubmitAggregatedReport_FiltersByAggregationKey(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	message := createTestProtocolMessage()

	signer1 := newTestSigner(t)
	signer2 := newTestSigner(t)
	signer3 := newTestSigner(t)

	version1 := []byte{0x01, 0x02, 0x03, 0x04}
	version2 := []byte{0x05, 0x06, 0x07, 0x08}

	msgWithCCV1 := createTestMessageWithCCV(t, message, signer1)
	msgWithCCV1.CcvVersion = version1
	messageID := getMessageIDFromProto(t, msgWithCCV1)
	aggregationKey1 := protocol.ByteSlice(messageID).String()

	record1v1 := createTestCommitVerificationRecord(t, msgWithCCV1, signer1)
	record1v1.CCVVersion = version1
	err := storage.SaveCommitVerification(ctx, record1v1, aggregationKey1)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	record1v2 := createTestCommitVerificationRecord(t, msgWithCCV1, signer1)
	record1v2.CCVVersion = version2
	record1v2.MessageID = messageID
	err = storage.SaveCommitVerification(ctx, record1v2, "aggregation_key_v2")
	require.NoError(t, err)

	msgWithCCV2 := createTestMessageWithCCV(t, message, signer2)
	msgWithCCV2.CcvVersion = version1
	record2v1 := createTestCommitVerificationRecord(t, msgWithCCV2, signer2)
	record2v1.CCVVersion = version1
	record2v1.MessageID = messageID
	err = storage.SaveCommitVerification(ctx, record2v1, aggregationKey1)
	require.NoError(t, err)

	msgWithCCV3 := createTestMessageWithCCV(t, message, signer3)
	msgWithCCV3.CcvVersion = version1
	record3v1 := createTestCommitVerificationRecord(t, msgWithCCV3, signer3)
	record3v1.CCVVersion = version1
	record3v1.MessageID = messageID
	err = storage.SaveCommitVerification(ctx, record3v1, aggregationKey1)
	require.NoError(t, err)

	report := &model.CommitAggregatedReport{
		MessageID:      messageID,
		AggregationKey: aggregationKey1,
		Verifications:  []*model.CommitVerificationRecord{record1v1, record2v1, record3v1},
	}
	err = storage.SubmitAggregatedReport(ctx, report)
	require.NoError(t, err)

	retrieved, err := storage.GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey1)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Len(t, retrieved.Verifications, 3)

	for _, v := range retrieved.Verifications {
		require.Equal(t, version1, v.CCVVersion)
	}

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

// TestSubmitAggregatedReport_FailsWhenAggregationKeyMismatch tests that submitting an aggregated
// report fails when the database doesn't have records matching the expected aggregation key.
func TestSubmitAggregatedReport_FailsWhenAggregationKeyMismatch(t *testing.T) {
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

	aggregatedReport := &model.CommitAggregatedReport{
		MessageID:      messageID,
		AggregationKey: "wrong_aggregation_key",
		Verifications:  []*model.CommitVerificationRecord{record},
	}

	err = storage.SubmitAggregatedReport(ctx, aggregatedReport)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to find verification record ID")
}

func TestGetCommitAggregatedReportByAggregationKey_ReturnsOnlyLatestReport(t *testing.T) {
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
		MessageID:      messageID,
		AggregationKey: aggregationKey,
		Verifications:  []*model.CommitVerificationRecord{record1, record2, record3},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, oldReport))

	retrieved, err := storage.GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey)
	require.NoError(t, err)
	require.Len(t, retrieved.Verifications, 3)
	oldSeq := retrieved.Sequence

	newReport := &model.CommitAggregatedReport{
		MessageID:      messageID,
		AggregationKey: aggregationKey,
		Verifications:  []*model.CommitVerificationRecord{record2, record3},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, newReport))

	retrieved, err = storage.GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey)
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
		MessageID:      messageID1,
		AggregationKey: aggKey1,
		Verifications:  []*model.CommitVerificationRecord{r1s1, r1s2, r1s3},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, oldReport1))

	newReport1 := &model.CommitAggregatedReport{
		MessageID:      messageID1,
		AggregationKey: aggKey1,
		Verifications:  []*model.CommitVerificationRecord{r1s2, r1s3},
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
		MessageID:      messageID2,
		AggregationKey: aggKey2,
		Verifications:  []*model.CommitVerificationRecord{r2s1, r2s2},
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

func TestGetCommitAggregatedReportByAggregationKey_DisjointVerifications_ReturnsOnlyLatest(t *testing.T) {
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
		MessageID:      messageID,
		AggregationKey: aggregationKey,
		Verifications:  []*model.CommitVerificationRecord{record1, record2},
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
		MessageID:      messageID,
		AggregationKey: aggregationKey,
		Verifications:  []*model.CommitVerificationRecord{record3, record4, record5},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, secondReport))

	retrieved, err := storage.GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey)
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
		MessageID:      messageID1,
		AggregationKey: aggKey1,
		Verifications:  []*model.CommitVerificationRecord{r1s1, r1s2},
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
		MessageID:      messageID1,
		AggregationKey: aggKey1,
		Verifications:  []*model.CommitVerificationRecord{r1s3, r1s4, r1s5},
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
		MessageID:      messageID2,
		AggregationKey: aggKey2,
		Verifications:  []*model.CommitVerificationRecord{r2s1, r2s2},
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

func TestOnDeleteRestrict_PreventsVerificationDeletion(t *testing.T) {
	_, ds, cleanup := setupTestDBWithDatabase(t)
	defer cleanup()

	storage := NewDatabaseStorage(ds, 10, 10*time.Second, logger.TestSugared(t))
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
		MessageID:      messageID,
		AggregationKey: aggregationKey,
		Verifications:  []*model.CommitVerificationRecord{record},
	}
	err = storage.SubmitAggregatedReport(ctx, report)
	require.NoError(t, err)

	_, err = ds.ExecContext(ctx, "DELETE FROM commit_verification_records")
	require.Error(t, err, "DELETE should be blocked by ON DELETE RESTRICT")
	require.Contains(t, err.Error(), "violates foreign key constraint")
}

func TestScanErrorHandling_CorruptedData(t *testing.T) {
	_, ds, cleanup := setupTestDBWithDatabase(t)
	defer cleanup()

	storage := NewDatabaseStorage(ds, 10, 10*time.Second, logger.TestSugared(t))
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
		MessageID:      messageID,
		AggregationKey: aggregationKey,
		Verifications:  []*model.CommitVerificationRecord{record},
	}
	err = storage.SubmitAggregatedReport(ctx, report)
	require.NoError(t, err)

	_, err = ds.ExecContext(ctx, "ALTER TABLE commit_verification_records DISABLE TRIGGER ALL")
	require.NoError(t, err)
	_, err = ds.ExecContext(ctx, "DELETE FROM commit_verification_records")
	require.NoError(t, err)
	_, err = ds.ExecContext(ctx, "ALTER TABLE commit_verification_records ENABLE TRIGGER ALL")
	require.NoError(t, err)

	t.Run("GetCommitAggregatedReportByAggregationKey returns error", func(t *testing.T) {
		_, err := storage.GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey)
		require.Error(t, err, "should return error for corrupted report")
	})

	t.Run("QueryAggregatedReports skips corrupted report", func(t *testing.T) {
		result, err := storage.QueryAggregatedReports(ctx, 0)
		require.NoError(t, err)
		require.Empty(t, result.Reports, "corrupted report should be skipped")
	})

	t.Run("GetBatchAggregatedReportByMessageIDs excludes corrupted report", func(t *testing.T) {
		results, err := storage.GetBatchAggregatedReportByMessageIDs(ctx, []model.MessageID{messageID})
		require.NoError(t, err)
		msgIDHex := protocol.ByteSlice(messageID).String()
		_, found := results[msgIDHex]
		require.False(t, found, "corrupted report should be absent from results")
	})
}

func TestOrphanDetection_ByAggregationKey(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t)

	message := createTestProtocolMessage()
	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	messageID := getMessageIDFromProto(t, msgWithCCV)
	record := createTestCommitVerificationRecord(t, msgWithCCV, signer)

	aggKeyA := "aggregation_key_A"
	err := storage.SaveCommitVerification(ctx, record, aggKeyA)
	require.NoError(t, err)

	aggKeyB := "aggregation_key_B"
	err = storage.SaveCommitVerification(ctx, record, aggKeyB)
	require.NoError(t, err)

	reportA := &model.CommitAggregatedReport{
		MessageID:      messageID,
		AggregationKey: aggKeyA,
		Verifications:  []*model.CommitVerificationRecord{record},
	}
	err = storage.SubmitAggregatedReport(ctx, reportA)
	require.NoError(t, err)

	orphanKeysCh, errCh := storage.ListOrphanedKeys(ctx, time.Time{}, 100)
	orphanedKeys := collectOrphanedKeys(t, orphanKeysCh, errCh)

	require.Len(t, orphanedKeys, 1)
	require.Equal(t, messageID[:], orphanedKeys[0].MessageID)
	require.Equal(t, aggKeyB, orphanedKeys[0].AggregationKey)
}

func TestGetCommitAggregatedReportByAggregationKey_PopulatesAggregationKey(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t)
	message := createTestProtocolMessage()
	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	messageID := getMessageIDFromProto(t, msgWithCCV)
	aggregationKey := "my_specific_aggregation_key"

	record := createTestCommitVerificationRecord(t, msgWithCCV, signer)
	require.NoError(t, storage.SaveCommitVerification(ctx, record, aggregationKey))

	report := &model.CommitAggregatedReport{
		MessageID:      messageID,
		AggregationKey: aggregationKey,
		Verifications:  []*model.CommitVerificationRecord{record},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, report))

	retrieved, err := storage.GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Equal(t, aggregationKey, retrieved.AggregationKey,
		"AggregationKey should be populated from commit_aggregated_reports table")
	require.Len(t, retrieved.Verifications, 1)
}

func TestQueryAggregatedReports_ReturnsReportsFromDifferentAggregationKeys(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t)

	message := createTestProtocolMessage()
	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	messageID := getMessageIDFromProto(t, msgWithCCV)
	record := createTestCommitVerificationRecord(t, msgWithCCV, signer)

	aggKeyV1 := "aggregation_key_v1"
	aggKeyV2 := "aggregation_key_v2"

	require.NoError(t, storage.SaveCommitVerification(ctx, record, aggKeyV1))
	require.NoError(t, storage.SaveCommitVerification(ctx, record, aggKeyV2))

	report1 := &model.CommitAggregatedReport{
		MessageID:      messageID,
		AggregationKey: aggKeyV1,
		Verifications:  []*model.CommitVerificationRecord{record},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, report1))

	report2 := &model.CommitAggregatedReport{
		MessageID:      messageID,
		AggregationKey: aggKeyV2,
		Verifications:  []*model.CommitVerificationRecord{record},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, report2))

	result, err := storage.QueryAggregatedReports(ctx, 0)
	require.NoError(t, err)
	require.Len(t, result.Reports, 2, "should return reports from different aggregation keys for the same message_id")

	aggKeys := map[model.AggregationKey]bool{
		result.Reports[0].AggregationKey: true,
		result.Reports[1].AggregationKey: true,
	}
	require.True(t, aggKeys[aggKeyV1], "should include report with aggKeyV1")
	require.True(t, aggKeys[aggKeyV2], "should include report with aggKeyV2")
}

func TestQueryAggregatedReports_ReturnsAllReportsForSameAggregationKey(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer1 := newTestSigner(t)
	signer2 := newTestSigner(t)

	message := createTestProtocolMessage()
	msgWithCCV1 := createTestMessageWithCCV(t, message, signer1)
	messageID := getMessageIDFromProto(t, msgWithCCV1)
	aggregationKey := protocol.ByteSlice(messageID).String()

	record1 := createTestCommitVerificationRecord(t, msgWithCCV1, signer1)
	require.NoError(t, storage.SaveCommitVerification(ctx, record1, aggregationKey))

	msgWithCCV2 := createTestMessageWithCCV(t, message, signer2)
	record2 := createTestCommitVerificationRecord(t, msgWithCCV2, signer2)
	record2.MessageID = messageID
	require.NoError(t, storage.SaveCommitVerification(ctx, record2, aggregationKey))

	report1 := &model.CommitAggregatedReport{
		MessageID:      messageID,
		AggregationKey: aggregationKey,
		Verifications:  []*model.CommitVerificationRecord{record1},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, report1))

	report2 := &model.CommitAggregatedReport{
		MessageID:      messageID,
		AggregationKey: aggregationKey,
		Verifications:  []*model.CommitVerificationRecord{record1, record2},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, report2))

	result, err := storage.QueryAggregatedReports(ctx, 0)
	require.NoError(t, err)
	require.Len(t, result.Reports, 2, "should return all reports including multiple for the same (message_id, aggregation_key)")
	require.Len(t, result.Reports[0].Verifications, 1, "first report should have 1 verification")
	require.Len(t, result.Reports[1].Verifications, 2, "second report should have 2 verifications")
}

func TestGetCommitAggregatedReportByAggregationKey_ReturnsNotFoundForDifferentAggregationKey(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t)
	message := createTestProtocolMessage()
	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	messageID := getMessageIDFromProto(t, msgWithCCV)
	oldAggKey := "old_aggregation_key"
	newAggKey := "new_aggregation_key"

	record := createTestCommitVerificationRecord(t, msgWithCCV, signer)
	require.NoError(t, storage.SaveCommitVerification(ctx, record, oldAggKey))

	report := &model.CommitAggregatedReport{
		MessageID:      messageID,
		AggregationKey: oldAggKey,
		Verifications:  []*model.CommitVerificationRecord{record},
	}
	require.NoError(t, storage.SubmitAggregatedReport(ctx, report))

	retrieved, err := storage.GetCommitAggregatedReportByAggregationKey(ctx, messageID, oldAggKey)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Equal(t, oldAggKey, retrieved.AggregationKey)

	_, err = storage.GetCommitAggregatedReportByAggregationKey(ctx, messageID, newAggKey)
	require.ErrorIs(t, err, pkgcommon.ErrNotFound,
		"querying with a different aggregation key should return not found")
}

// migrationVersionBeforeJunctionTable is the last migration version that uses
// the old BIGINT[] schema for verification_record_ids.
const migrationVersionBeforeJunctionTable = 2

func TestMigrationDataConsistency_OldSchemaDataSurvivesMigration(t *testing.T) {
	ds, cleanup := testutil.SetupTestPostgresDB(t)
	defer cleanup()

	ctx := context.Background()
	migrationsPath := findMigrationsPath(t)

	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(ds.DB, migrationsPath, migrationVersionBeforeJunctionTable))

	signer1 := newTestSigner(t)
	signer2 := newTestSigner(t)
	message := createTestProtocolMessage()
	msgWithCCV1 := createTestMessageWithCCV(t, message, signer1)
	record1 := createTestCommitVerificationRecord(t, msgWithCCV1, signer1)
	messageID := getMessageIDFromProto(t, msgWithCCV1)
	messageIDHex := protocol.ByteSlice(messageID).String()
	aggKey := "test-agg-key-v1"

	msgWithCCV2 := createTestMessageWithCCV(t, message, signer2)
	record2 := createTestCommitVerificationRecord(t, msgWithCCV2, signer2)
	record2.MessageID = messageID

	params1, err := recordToInsertParams(record1, aggKey)
	require.NoError(t, err)
	params2, err := recordToInsertParams(record2, aggKey)
	require.NoError(t, err)

	insertVerification := `INSERT INTO commit_verification_records
		(message_id, signer_identifier, aggregation_key,
		 ccv_version, signature, message_ccv_addresses, message_executor_address, message_data)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id`

	var id1, id2 int64
	require.NoError(t, ds.GetContext(ctx, &id1, insertVerification,
		params1["message_id"], params1["signer_identifier"], params1["aggregation_key"],
		params1["ccv_version"], params1["signature"], params1["message_ccv_addresses"],
		params1["message_executor_address"], params1["message_data"],
	))
	require.NoError(t, ds.GetContext(ctx, &id2, insertVerification,
		params2["message_id"], params2["signer_identifier"], params2["aggregation_key"],
		params2["ccv_version"], params2["signature"], params2["message_ccv_addresses"],
		params2["message_executor_address"], params2["message_data"],
	))

	insertOldReport := `INSERT INTO commit_aggregated_reports (message_id, verification_record_ids)
		VALUES ($1, $2)`
	_, err = ds.ExecContext(ctx, insertOldReport, messageIDHex, pq.Array([]int64{id1, id2}))
	require.NoError(t, err)

	require.NoError(t, goose.Up(ds.DB, migrationsPath))

	storage := NewDatabaseStorage(ds, 10, 10*time.Second, logger.TestSugared(t))

	report, err := storage.GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggKey)
	require.NoError(t, err)
	require.NotNil(t, report)
	require.Equal(t, messageID[:], report.MessageID)
	require.Equal(t, aggKey, report.AggregationKey)
	require.Len(t, report.Verifications, 2)

	expectedByAddress := map[string]*model.CommitVerificationRecord{
		signer1.Signer.Address: record1,
		signer2.Signer.Address: record2,
	}
	for i, v := range report.Verifications {
		signerAddr := common.BytesToAddress(v.SignerIdentifier.Identifier).Hex()
		matched, ok := expectedByAddress[signerAddr]
		require.Truef(t, ok, "verification[%d] signer %s not in expected set", i, signerAddr)
		assertCommitVerificationRecordEqual(t, matched, v, fmt.Sprintf("verification[%d]", i))
	}

	batch, err := storage.QueryAggregatedReports(ctx, 0)
	require.NoError(t, err)
	require.Len(t, batch.Reports, 1)
	require.Equal(t, messageID[:], batch.Reports[0].MessageID)
	require.Equal(t, aggKey, batch.Reports[0].AggregationKey)
	require.Len(t, batch.Reports[0].Verifications, 2)

	batchResult, err := storage.GetBatchAggregatedReportByMessageIDs(ctx, []model.MessageID{messageID})
	require.NoError(t, err)
	batchReport, ok := batchResult[messageIDHex]
	require.True(t, ok)
	require.Equal(t, messageID[:], batchReport.MessageID)
	require.Len(t, batchReport.Verifications, 2)
}

func findMigrationsPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"../../../migrations/postgres",
		"../../../../aggregator/migrations/postgres",
	}
	for _, candidate := range candidates {
		absPath, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if info, err := os.Stat(absPath); err == nil && info.IsDir() {
			return absPath
		}
	}
	t.Fatal("could not find migrations directory")
	panic("unreachable")
}

func collectOrphanedKeys(t *testing.T, ch <-chan model.OrphanedKey, errCh <-chan error) []model.OrphanedKey {
	t.Helper()
	result := make([]model.OrphanedKey, 0, 16)
	for key := range ch {
		result = append(result, key)
	}
	require.NoError(t, <-errCh)
	return result
}
