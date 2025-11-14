package postgres

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	_ "github.com/lib/pq"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func assertCommitVerificationRecordEqual(t *testing.T, expected, actual *model.CommitVerificationRecord, msgPrefix string) {
	require.Equal(t, expected.MessageID, actual.MessageID, "%s: MessageID mismatch", msgPrefix)
	require.Equal(t, expected.SourceVerifierAddress, actual.SourceVerifierAddress, "%s: SourceVerifierAddress mismatch", msgPrefix)
	require.Equal(t, expected.Timestamp, actual.Timestamp, "%s: Timestamp mismatch", msgPrefix)
	require.Equal(t, expected.BlobData, actual.BlobData, "%s: BlobData mismatch", msgPrefix)
	require.Equal(t, expected.CcvData, actual.CcvData, "%s: CcvData mismatch", msgPrefix)

	if expected.Message != nil && actual.Message != nil {
		require.Equal(t, expected.Message.Version, actual.Message.Version, "%s: Message.Version mismatch", msgPrefix)
		require.Equal(t, expected.Message.SourceChainSelector, actual.Message.SourceChainSelector, "%s: Message.SourceChainSelector mismatch", msgPrefix)
		require.Equal(t, expected.Message.DestChainSelector, actual.Message.DestChainSelector, "%s: Message.DestChainSelector mismatch", msgPrefix)
		require.Equal(t, expected.Message.Nonce, actual.Message.Nonce, "%s: Message.Nonce mismatch", msgPrefix)
		require.Equal(t, expected.Message.OnRampAddress, actual.Message.OnRampAddress, "%s: Message.OnRampAddress mismatch", msgPrefix)
		require.Equal(t, expected.Message.OffRampAddress, actual.Message.OffRampAddress, "%s: Message.OffRampAddress mismatch", msgPrefix)
		require.Equal(t, expected.Message.Sender, actual.Message.Sender, "%s: Message.Sender mismatch", msgPrefix)
		require.Equal(t, expected.Message.Receiver, actual.Message.Receiver, "%s: Message.Receiver mismatch", msgPrefix)
		require.Equal(t, expected.Message.Data, actual.Message.Data, "%s: Message.Data mismatch", msgPrefix)
	}

	if expected.IdentifierSigner != nil && actual.IdentifierSigner != nil {
		require.Equal(t, expected.IdentifierSigner.ParticipantID, actual.IdentifierSigner.ParticipantID, "%s: IdentifierSigner.ParticipantID mismatch", msgPrefix)
		require.Equal(t, expected.IdentifierSigner.Address, actual.IdentifierSigner.Address, "%s: IdentifierSigner.Address mismatch", msgPrefix)
		require.Equal(t, expected.IdentifierSigner.SignatureR, actual.IdentifierSigner.SignatureR, "%s: IdentifierSigner.SignatureR mismatch", msgPrefix)
		require.Equal(t, expected.IdentifierSigner.SignatureS, actual.IdentifierSigner.SignatureS, "%s: IdentifierSigner.SignatureS mismatch", msgPrefix)
	}
}

type testFixture struct {
	key    *ecdsa.PrivateKey
	Signer model.Signer
}

func newTestSigner(t *testing.T, name string) *testFixture {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	signerAddress := crypto.PubkeyToAddress(privateKey.PublicKey)

	signer := model.Signer{
		ParticipantID: name,
		Addresses:     []string{signerAddress.Hex()},
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
		Nonce:                123,
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
		TokenTransfer:        []byte{},
		DataLength:           8,
		Data:                 []byte("testdata"),
	}
}

func createTestMessageWithCCV(t *testing.T, message *protocol.Message, signer *testFixture) *pb.MessageWithCCVNodeData {
	messageID, err := message.MessageID()
	require.NoError(t, err)

	sourceVerifierKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	sourceVerifierAddress := crypto.PubkeyToAddress(sourceVerifierKey.PublicKey).Bytes()

	ccvArgs := make([]byte, 8)
	binary.BigEndian.PutUint64(ccvArgs, 123)

	r32, s32, signerAddr, err := protocol.SignV27(messageID[:], signer.key)
	require.NoError(t, err)

	sigData := []protocol.Data{
		{
			R:      r32,
			S:      s32,
			Signer: signerAddr,
		},
	}

	ccvData, err := protocol.EncodeSignatures(sigData)
	require.NoError(t, err)

	return &pb.MessageWithCCVNodeData{
		MessageId:             messageID[:],
		SourceVerifierAddress: sourceVerifierAddress,
		Message: &pb.Message{
			Version:              uint32(message.Version),
			SourceChainSelector:  uint64(message.SourceChainSelector),
			DestChainSelector:    uint64(message.DestChainSelector),
			Nonce:                uint64(message.Nonce),
			OnRampAddressLength:  uint32(message.OnRampAddressLength),
			OnRampAddress:        message.OnRampAddress[:],
			OffRampAddressLength: uint32(message.OffRampAddressLength),
			OffRampAddress:       message.OffRampAddress[:],
			Finality:             uint32(message.Finality),
			SenderLength:         uint32(message.SenderLength),
			Sender:               message.Sender[:],
			ReceiverLength:       uint32(message.ReceiverLength),
			Receiver:             message.Receiver[:],
			DestBlobLength:       uint32(message.DestBlobLength),
			DestBlob:             message.DestBlob[:],
			TokenTransferLength:  uint32(message.TokenTransferLength),
			TokenTransfer:        message.TokenTransfer[:],
			DataLength:           uint32(message.DataLength),
			Data:                 message.Data[:],
		},
		BlobData:  []byte("test blob data"),
		CcvData:   ccvData,
		Timestamp: time.Now().UnixMilli(),
	}
}

func createTestCommitVerificationRecord(msgWithCCV *pb.MessageWithCCVNodeData, signer *testFixture) *model.CommitVerificationRecord {
	r32, s32 := [32]byte{}, [32]byte{}
	copy(r32[:], []byte("r_signature_test_32_bytes_here!"))
	copy(s32[:], []byte("s_signature_test_32_bytes_here!"))

	signerAddress := common.HexToAddress(signer.Signer.Addresses[0])

	record := model.CommitVerificationRecordFromProto(msgWithCCV)
	record.IdentifierSigner = &model.IdentifierSigner{
		ParticipantID: signer.Signer.ParticipantID,
		Address:       signerAddress.Bytes(),
		SignatureR:    r32,
		SignatureS:    s32,
	}
	record.IdempotencyKey = uuid.New()

	return record
}

func setupTestDB(t *testing.T) (*DatabaseStorage, func()) {
	ctx := context.Background()

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

	return storage, cleanup
}

func TestSaveCommitVerification_HappyPath(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t, "test-node-1")
	message := createTestProtocolMessage()
	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	record := createTestCommitVerificationRecord(msgWithCCV, signer)

	aggregationKey := hex.EncodeToString(msgWithCCV.MessageId)

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
	signer := newTestSigner(t, "test-node-1")
	message := createTestProtocolMessage()
	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	record := createTestCommitVerificationRecord(msgWithCCV, signer)
	aggregationKey := hex.EncodeToString(msgWithCCV.MessageId)

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

	messageID, err := message.MessageID()
	require.NoError(t, err)

	records, err := storage.ListCommitVerificationByAggregationKey(ctx, messageID[:], aggregationKey)
	require.NoError(t, err)
	require.Len(t, records, 1, "Should have exactly 1 record after multiple saves")
}

func TestGetCommitVerification_NotFound(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	id := model.CommitVerificationRecordIdentifier{
		MessageID: []byte("nonexistent"),
		Address:   []byte("address"),
	}

	_, err := storage.GetCommitVerification(ctx, id)
	require.Error(t, err)
	require.Contains(t, err.Error(), "commit verification record not found")
}

func TestGetCommitVerification_MultipleVersions(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t, "test-node-1")
	message := createTestProtocolMessage()
	msgWithCCV := createTestMessageWithCCV(t, message, signer)

	aggregationKey := hex.EncodeToString(msgWithCCV.MessageId)

	record1 := createTestCommitVerificationRecord(msgWithCCV, signer)
	err := storage.SaveCommitVerification(ctx, record1, aggregationKey)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	record2 := createTestCommitVerificationRecord(msgWithCCV, signer)
	record2.SetTimestampFromMillis(time.Now().UnixMilli())
	err = storage.SaveCommitVerification(ctx, record2, aggregationKey)
	require.NoError(t, err)

	id, err := record1.GetID()
	require.NoError(t, err)

	retrieved, err := storage.GetCommitVerification(ctx, *id)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Equal(t, record2.Timestamp, retrieved.Timestamp, "Should retrieve latest version")
	assertCommitVerificationRecordEqual(t, record2, retrieved, "GetCommitVerification_MultipleVersions")
}

func TestListCommitVerificationByAggregationKey(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	message := createTestProtocolMessage()
	messageID, err := message.MessageID()
	aggregationKey := hex.EncodeToString(messageID[:])
	require.NoError(t, err)

	signer1 := newTestSigner(t, "node-1")
	signer2 := newTestSigner(t, "node-2")

	msgWithCCV1 := createTestMessageWithCCV(t, message, signer1)

	record1 := createTestCommitVerificationRecord(msgWithCCV1, signer1)
	err = storage.SaveCommitVerification(ctx, record1, aggregationKey)
	require.NoError(t, err)

	msgWithCCV2 := createTestMessageWithCCV(t, message, signer2)
	record2 := createTestCommitVerificationRecord(msgWithCCV2, signer2)
	err = storage.SaveCommitVerification(ctx, record2, aggregationKey)
	require.NoError(t, err)

	records, err := storage.ListCommitVerificationByAggregationKey(ctx, messageID[:], aggregationKey)
	require.NoError(t, err)
	require.Len(t, records, 2)

	foundSigner1 := false
	foundSigner2 := false
	for _, rec := range records {
		if rec.IdentifierSigner.ParticipantID == "node-1" {
			foundSigner1 = true
			assertCommitVerificationRecordEqual(t, record1, rec, "Signer1")
		}
		if rec.IdentifierSigner.ParticipantID == "node-2" {
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
	messageID, err := message.MessageID()
	require.NoError(t, err)

	signer1 := newTestSigner(t, "node-1")
	signer2 := newTestSigner(t, "node-2")

	msgWithCCV1 := createTestMessageWithCCV(t, message, signer1)

	record1 := createTestCommitVerificationRecord(msgWithCCV1, signer1)
	aggregationKey1 := "aggregationKey1"
	err = storage.SaveCommitVerification(ctx, record1, aggregationKey1)
	require.NoError(t, err)

	msgWithCCV2 := createTestMessageWithCCV(t, message, signer2)
	aggregationKey2 := "aggregationKey2"
	record2 := createTestCommitVerificationRecord(msgWithCCV2, signer2)
	err = storage.SaveCommitVerification(ctx, record2, aggregationKey2)
	require.NoError(t, err)

	records, err := storage.ListCommitVerificationByAggregationKey(ctx, messageID[:], aggregationKey1)
	require.NoError(t, err)
	require.Len(t, records, 1)

	records, err = storage.ListCommitVerificationByAggregationKey(ctx, messageID[:], aggregationKey2)
	require.NoError(t, err)
	require.Len(t, records, 1)
}

func TestListCommitVerificationByAggregationKey_DifferentAggregationKey_SameSigner(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	message := createTestProtocolMessage()
	messageID, err := message.MessageID()
	require.NoError(t, err)

	signer1 := newTestSigner(t, "node-1")

	msgWithCCV1 := createTestMessageWithCCV(t, message, signer1)

	record1 := createTestCommitVerificationRecord(msgWithCCV1, signer1)
	aggregationKey1 := "aggregationKey1"
	err = storage.SaveCommitVerification(ctx, record1, aggregationKey1)
	require.NoError(t, err)

	aggregationKey2 := "aggregationKey2"
	err = storage.SaveCommitVerification(ctx, record1, aggregationKey2)
	require.NoError(t, err)

	records, err := storage.ListCommitVerificationByAggregationKey(ctx, messageID[:], aggregationKey1)
	require.NoError(t, err)
	require.Len(t, records, 1)

	records, err = storage.ListCommitVerificationByAggregationKey(ctx, messageID[:], aggregationKey2)
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

	result, err := storage.QueryAggregatedReports(ctx, 0, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Empty(t, result.Reports)
	require.Nil(t, result.NextPageToken)
}

func TestQueryAggregatedReports_Pagination(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	signer := newTestSigner(t, "node-1")

	for i := 0; i < 15; i++ {
		message := createTestProtocolMessage()
		message.Nonce = protocol.Nonce(uint64(i))
		msgWithCCV := createTestMessageWithCCV(t, message, signer)
		aggregationKey := hex.EncodeToString(msgWithCCV.GetMessageId())
		record := createTestCommitVerificationRecord(msgWithCCV, signer)

		err := storage.SaveCommitVerification(ctx, record, aggregationKey)
		require.NoError(t, err)

		messageID, err := message.MessageID()
		require.NoError(t, err)

		report := &model.CommitAggregatedReport{
			MessageID:     messageID[:],
			Verifications: []*model.CommitVerificationRecord{record},
		}

		err = storage.SubmitReport(ctx, report)
		require.NoError(t, err)

		time.Sleep(5 * time.Millisecond)
	}

	result, err := storage.QueryAggregatedReports(ctx, 0, nil)
	require.NoError(t, err)
	require.Len(t, result.Reports, 10)
	require.NotNil(t, result.NextPageToken)

	for _, report := range result.Reports {
		require.Len(t, report.Verifications, 1)
		require.NotEmpty(t, report.MessageID)
	}

	result2, err := storage.QueryAggregatedReports(ctx, 0, result.NextPageToken)
	require.NoError(t, err)
	require.Len(t, result2.Reports, 5)
	require.Nil(t, result2.NextPageToken)

	for _, report := range result2.Reports {
		require.Len(t, report.Verifications, 1)
		require.NotEmpty(t, report.MessageID)
	}
}

func TestQueryAggregatedReports_InvalidToken(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	invalidToken := "invalid-json"
	_, err := storage.QueryAggregatedReports(ctx, 0, &invalidToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse pagination token")
}

func TestGetCCVData_Found(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t, "node-1")
	message := createTestProtocolMessage()
	messageID, err := message.MessageID()
	require.NoError(t, err)

	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	aggregationKey := hex.EncodeToString(msgWithCCV.GetMessageId())
	record := createTestCommitVerificationRecord(msgWithCCV, signer)

	err = storage.SaveCommitVerification(ctx, record, aggregationKey)
	require.NoError(t, err)

	report := &model.CommitAggregatedReport{
		MessageID:     messageID[:],
		Verifications: []*model.CommitVerificationRecord{record},
	}

	err = storage.SubmitReport(ctx, report)
	require.NoError(t, err)

	retrieved, err := storage.GetCCVData(ctx, messageID[:])
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

	retrieved, err := storage.GetCCVData(ctx, []byte("nonexistent"))
	require.NoError(t, err)
	require.Nil(t, retrieved)
}

func TestSubmitReport_HappyPath(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t, "node-1")
	message := createTestProtocolMessage()
	messageID, err := message.MessageID()
	require.NoError(t, err)

	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	aggregationKey := hex.EncodeToString(msgWithCCV.GetMessageId())
	record := createTestCommitVerificationRecord(msgWithCCV, signer)

	err = storage.SaveCommitVerification(ctx, record, aggregationKey)
	require.NoError(t, err)

	report := &model.CommitAggregatedReport{
		MessageID:     messageID[:],
		Verifications: []*model.CommitVerificationRecord{record},
	}

	err = storage.SubmitReport(ctx, report)
	require.NoError(t, err)

	retrieved, err := storage.GetCCVData(ctx, messageID[:])
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
	signer := newTestSigner(t, "node-1")
	message := createTestProtocolMessage()
	messageID, err := message.MessageID()
	require.NoError(t, err)

	msgWithCCV := createTestMessageWithCCV(t, message, signer)
	aggregationKey := hex.EncodeToString(msgWithCCV.GetMessageId())
	record := createTestCommitVerificationRecord(msgWithCCV, signer)

	err = storage.SaveCommitVerification(ctx, record, aggregationKey)
	require.NoError(t, err)

	report := &model.CommitAggregatedReport{
		MessageID:     messageID[:],
		Verifications: []*model.CommitVerificationRecord{record},
	}

	err = storage.SubmitReport(ctx, report)
	require.NoError(t, err)

	err = storage.SubmitReport(ctx, report)
	require.NoError(t, err)

	result, err := storage.QueryAggregatedReports(ctx, 0, nil)
	require.NoError(t, err)
	require.Len(t, result.Reports, 1, "Should have exactly 1 report after duplicate submission")
	require.Equal(t, messageID[:], result.Reports[0].MessageID)
}

func TestListOrphanedKeys(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	signer := newTestSigner(t, "node-1")

	message1 := createTestProtocolMessage()
	message1.Nonce = 1
	messageID1, err := message1.MessageID()
	require.NoError(t, err)
	msgWithCCV1 := createTestMessageWithCCV(t, message1, signer)
	aggregationKey1 := hex.EncodeToString(msgWithCCV1.GetMessageId())
	orphanRecord := createTestCommitVerificationRecord(msgWithCCV1, signer)
	err = storage.SaveCommitVerification(ctx, orphanRecord, aggregationKey1)
	require.NoError(t, err)

	aggregationKey1a := "different"
	err = storage.SaveCommitVerification(ctx, orphanRecord, aggregationKey1a)
	require.NoError(t, err)

	message2 := createTestProtocolMessage()
	message2.Nonce = 2
	messageID2, err := message2.MessageID()
	require.NoError(t, err)
	msgWithCCV2 := createTestMessageWithCCV(t, message2, signer)
	aggregationKey2 := hex.EncodeToString(msgWithCCV2.GetMessageId())
	aggregatedRecord := createTestCommitVerificationRecord(msgWithCCV2, signer)
	err = storage.SaveCommitVerification(ctx, aggregatedRecord, aggregationKey2)
	require.NoError(t, err)

	aggregationKey2a := "different"
	err = storage.SaveCommitVerification(ctx, aggregatedRecord, aggregationKey2a)
	require.NoError(t, err)

	report := &model.CommitAggregatedReport{
		MessageID:     messageID2[:],
		Verifications: []*model.CommitVerificationRecord{aggregatedRecord},
	}
	err = storage.SubmitReport(ctx, report)
	require.NoError(t, err)

	orphanKeysCh, errCh := storage.ListOrphanedKeys(ctx)

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

	messageIDCh, errCh := storage.ListOrphanedKeys(ctx)

	for range messageIDCh {
	}

	err := <-errCh
	require.Error(t, err)
}

func TestBatchOperations_MultipleSigners(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	message := createTestProtocolMessage()
	messageID, err := message.MessageID()
	require.NoError(t, err)

	signers := []*testFixture{
		newTestSigner(t, "node-1"),
		newTestSigner(t, "node-2"),
		newTestSigner(t, "node-3"),
	}

	records := []*model.CommitVerificationRecord{}
	for _, signer := range signers {
		msgWithCCV := createTestMessageWithCCV(t, message, signer)
		aggregationKey := hex.EncodeToString(msgWithCCV.GetMessageId())
		record := createTestCommitVerificationRecord(msgWithCCV, signer)
		err := storage.SaveCommitVerification(ctx, record, aggregationKey)
		require.NoError(t, err)
		records = append(records, record)
	}

	report := &model.CommitAggregatedReport{
		MessageID:     messageID[:],
		Verifications: records,
	}

	err = storage.SubmitReport(ctx, report)
	require.NoError(t, err)

	retrieved, err := storage.GetCCVData(ctx, messageID[:])
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Len(t, retrieved.Verifications, 3)
	require.Equal(t, messageID[:], retrieved.MessageID)

	for i, expectedRecord := range records {
		found := false
		for _, actualRecord := range retrieved.Verifications {
			if actualRecord.IdentifierSigner.ParticipantID == expectedRecord.IdentifierSigner.ParticipantID {
				assertCommitVerificationRecordEqual(t, expectedRecord, actualRecord, "BatchOperations_Signer"+expectedRecord.IdentifierSigner.ParticipantID)
				found = true
				break
			}
		}
		require.True(t, found, "Should find record for signer %d", i)
	}
}

func TestSubmitReport_NilReport(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	err := storage.SubmitReport(ctx, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "aggregated report cannot be nil")
}

func TestQueryAggregatedReports_SinceSequence(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	signer := newTestSigner(t, "node-1")

	var firstReportSeq int64

	for i := 0; i < 5; i++ {
		message := createTestProtocolMessage()
		message.Nonce = protocol.Nonce(uint64(i))
		msgWithCCV := createTestMessageWithCCV(t, message, signer)
		aggregationKey := hex.EncodeToString(msgWithCCV.GetMessageId())
		record := createTestCommitVerificationRecord(msgWithCCV, signer)

		err := storage.SaveCommitVerification(ctx, record, aggregationKey)
		require.NoError(t, err)

		messageID, err := message.MessageID()
		require.NoError(t, err)

		report := &model.CommitAggregatedReport{
			MessageID:     messageID[:],
			Verifications: []*model.CommitVerificationRecord{record},
		}

		err = storage.SubmitReport(ctx, report)
		require.NoError(t, err)

		if i == 0 {
			retrieved, err := storage.GetCCVData(ctx, messageID[:])
			require.NoError(t, err)
			firstReportSeq = retrieved.Sequence
		}

		time.Sleep(5 * time.Millisecond)
	}

	result, err := storage.QueryAggregatedReports(ctx, firstReportSeq+2, nil)
	require.NoError(t, err)
	require.Len(t, result.Reports, 3)

	for _, report := range result.Reports {
		require.Len(t, report.Verifications, 1)
		require.GreaterOrEqual(t, report.Sequence, firstReportSeq+2, "All reports should be at or after the requested sequence")
	}
}

func TestDatabaseStorage_PageSize(t *testing.T) {
	ctx := context.Background()

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

func TestListCommitVerificationByAggregationKey_DistinctOnSigner(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	message := createTestProtocolMessage()
	messageID, err := message.MessageID()
	aggregationKey := hex.EncodeToString(messageID[:])
	require.NoError(t, err)

	signer := newTestSigner(t, "node-1")

	msgWithCCV1 := createTestMessageWithCCV(t, message, signer)
	record1 := createTestCommitVerificationRecord(msgWithCCV1, signer)
	record1.SetTimestampFromMillis(time.Now().UnixMilli())
	err = storage.SaveCommitVerification(ctx, record1, aggregationKey)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	msgWithCCV2 := createTestMessageWithCCV(t, message, signer)
	record2 := createTestCommitVerificationRecord(msgWithCCV2, signer)
	record2.SetTimestampFromMillis(time.Now().UnixMilli())
	err = storage.SaveCommitVerification(ctx, record2, aggregationKey)
	require.NoError(t, err)

	records, err := storage.ListCommitVerificationByAggregationKey(ctx, messageID[:], aggregationKey)
	require.NoError(t, err)
	require.Len(t, records, 1, "Should return only latest version")
	require.Equal(t, record2.Timestamp, records[0].Timestamp, "Should be the second (latest) record")
	assertCommitVerificationRecordEqual(t, record2, records[0], "DistinctOnSigner_Latest")
}
