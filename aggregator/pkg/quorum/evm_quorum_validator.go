package quorum

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	committee "github.com/smartcontractkit/chainlink-ccv/committee/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type EVMQuorumValidator struct {
	Committee *model.Committee
	l         logger.SugaredLogger
}

func (q *EVMQuorumValidator) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, q.l)
}

func (q *EVMQuorumValidator) CheckQuorum(ctx context.Context, aggregatedReport *model.CommitAggregatedReport) (bool, error) {
	if len(aggregatedReport.Verifications) == 0 {
		q.logger(ctx).Error("No verifications found")
		return false, nil
	}

	if q.Committee == nil {
		q.logger(ctx).Error("committee config not found")
		return false, fmt.Errorf("committee config not found")
	}

	quorumConfig, exists := q.Committee.GetQuorumConfig(aggregatedReport.GetSourceChainSelector())
	if !exists {
		q.logger(ctx).Errorf("Failed to get quorum config for source selector: %d", aggregatedReport.GetSourceChainSelector())
		return false, fmt.Errorf("failed to get quorum config for source selector: %d", aggregatedReport.GetSourceChainSelector())
	}

	if len(aggregatedReport.Verifications) < int(quorumConfig.Threshold) {
		q.logger(ctx).Debugf("Not enough verifications to meet quorum: have %d, need %d", len(aggregatedReport.Verifications), quorumConfig.Threshold)
		return false, nil
	}

	signerAddressesSet := make(map[string]struct{})
	var referenceHash model.SignableHash
	validSignerCount := 0
	for i, verification := range aggregatedReport.Verifications {
		result, err := q.ValidateSignature(ctx, verification)
		if err != nil {
			q.logger(ctx).Errorw("Failed to validate signature", "error", err)
			continue
		}
		if result.Signer == nil {
			q.logger(ctx).Warn("No valid signer found. Might be due to a config change")
			continue
		}
		if validSignerCount == 0 {
			referenceHash = result.Hash
		} else if !bytes.Equal(result.Hash[:], referenceHash[:]) {
			q.logger(ctx).Errorw("Hash mismatch detected - possible data tampering",
				"index", i, "expected", hex.EncodeToString(referenceHash[:]), "got", hex.EncodeToString(result.Hash[:]))
			return false, fmt.Errorf("verification hash mismatch: possible data tampering detected")
		}
		validSignerCount++
		signerAddressesSet[string(result.Signer.Identifier)] = struct{}{}
	}

	if len(signerAddressesSet) < int(quorumConfig.Threshold) {
		q.logger(ctx).Debugf("Quorum not met: have %d unique signer addresses, need %d", len(signerAddressesSet), quorumConfig.Threshold)
		return false, nil
	}

	q.logger(ctx).Debugf("Quorum met with %d unique signer addresses", len(signerAddressesSet))
	return true, nil
}

func (q *EVMQuorumValidator) DeriveAggregationKey(ctx context.Context, record *model.CommitVerificationRecord) (model.AggregationKey, error) {
	messageID, err := record.Message.MessageID()
	if err != nil {
		q.logger(ctx).Errorw("Failed to compute message hash", "error", err)
		return "", err
	}

	hash, err := committee.NewSignableHash(messageID, record.CCVVersion)
	if err != nil {
		q.logger(ctx).Errorw("Failed to produce signed hash", "error", err)
		return "", err
	}
	return hex.EncodeToString(hash[:]), nil
}

func (q *EVMQuorumValidator) ValidateSignature(ctx context.Context, record *model.CommitVerificationRecord) (*model.SignatureValidationResult, error) {
	q.logger(ctx).Debug("Validating signature for report")
	if record.Signature == nil {
		q.logger(ctx).Error("Missing signature in report")
		return nil, fmt.Errorf("missing signature in report")
	}

	message := record.Message

	messageID, err := message.MessageID()
	if err != nil {
		q.logger(ctx).Errorw("Failed to compute message hash", "error", err)
		return nil, err
	}

	hash, err := committee.NewSignableHash(messageID, record.CCVVersion)
	if err != nil {
		q.logger(ctx).Errorw("Failed to produce signed hash", "error", err)
		return nil, err
	}

	r, s, _, err := protocol.DecodeSingleEcdsaSignature(record.Signature)
	if err != nil {
		q.logger(ctx).Errorw("Failed to decode single signature", "error", err)
		return nil, fmt.Errorf("failed to decode single signature: %w", err)
	}

	if q.Committee == nil {
		q.logger(ctx).Error("committee config not found")
		return nil, fmt.Errorf("committee config not found")
	}

	quorumConfig, exists := q.Committee.GetQuorumConfig(uint64(message.SourceChainSelector))
	if !exists {
		q.logger(ctx).Errorf("Failed to get quorum config for source selector: %d", message.SourceChainSelector)
		return nil, fmt.Errorf("failed to get quorum config for source selector: %d", message.SourceChainSelector)
	}

	recoveredAddress, err := protocol.RecoverEcdsaSigner(hash, r, s)
	if err != nil {
		q.logger(ctx).Errorw("Failed to recover address from signature", "error", err)
		return nil, fmt.Errorf("failed to recover address from signature: %w", err)
	}
	q.logger(ctx).Tracef("Recovered address: %s", recoveredAddress.Hex())

	for _, candidateSigner := range quorumConfig.Signers {
		candidateSignerAddress := common.HexToAddress(candidateSigner.Address)

		if candidateSignerAddress == recoveredAddress {
			q.logger(ctx).Infow("Recovered address from signature", "address", recoveredAddress.Hex())
			return &model.SignatureValidationResult{
				Signer: &model.SignerIdentifier{
					Identifier: candidateSignerAddress.Bytes(),
				},
				QuorumConfig: quorumConfig,
				Hash:         hash,
			}, nil
		}
	}

	q.logger(ctx).Debug("No valid signers found for the provided signature")
	return nil, fmt.Errorf("no valid signers found for the provided signature")
}

func NewQuorumValidator(config *model.AggregatorConfig, l logger.SugaredLogger) *EVMQuorumValidator {
	return &EVMQuorumValidator{
		Committee: config.Committee,
		l:         l,
	}
}
