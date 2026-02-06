package postgres

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	_ "github.com/lib/pq"

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
	storage, _, cleanup := setupTestDBWithDatabase(t)
	return storage, cleanup
}

func setupTestDBWithDatabase(t *testing.T) (*DatabaseStorage, *sqlx.DB, func()) {
	ctx := context.Background()
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	postgresContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("test_storage_db"),
		postgres.WithUsername("test_user"),
		postgres.WithPassword("test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err)

	connectionString, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("postgres", connectionString)
	require.NoError(t, err)

	ds := sqlx.NewDb(db, "postgres")

	err = RunMigrations(ds, "postgres")
	require.NoError(t, err)

	storage := NewDatabaseStorage(ds, 10, logger.TestSugared(t))

	cleanup := func() {
		ds.Close()
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	}

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

	orphanKeysCh, errCh := storage.ListOrphanedKeys(ctx, time.Time{})

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

	messageIDCh, errCh := storage.ListOrphanedKeys(ctx, time.Time{})

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
	orphanKeysCh, errCh := storage.ListOrphanedKeys(ctx, cutoff)

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
	ctx := context.Background()
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	postgresContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("test_pagesize_db"),
		postgres.WithUsername("test_user"),
		postgres.WithPassword("test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err)

	defer func() {
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	}()

	connectionString, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("postgres", connectionString)
	require.NoError(t, err)

	ds := sqlx.NewDb(db, "postgres")
	defer ds.Close()

	customPageSize := 25
	storage := NewDatabaseStorage(ds, customPageSize, logger.TestSugared(t))

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
