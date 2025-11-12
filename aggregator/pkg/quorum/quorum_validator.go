package quorum

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	committee "github.com/smartcontractkit/chainlink-ccv/committee/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type EVMQuorumValidator struct {
	Committees map[string]*model.Committee
	l          logger.SugaredLogger
}

func (q *EVMQuorumValidator) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, q.l)
}

func (q *EVMQuorumValidator) CheckQuorum(ctx context.Context, aggregatedReport *model.CommitAggregatedReport) (bool, error) {
	if len(aggregatedReport.Verifications) == 0 {
		q.logger(ctx).Error("No verifications found")
		return false, nil
	}

	_, quorumConfig, err := q.getQuorumConfig(protocol.ChainSelector(aggregatedReport.GetSourceChainSelector()), protocol.ChainSelector(aggregatedReport.GetDestinationSelector()), aggregatedReport.GetSourceVerifierAddress())
	if err != nil {
		q.logger(ctx).Errorf("Failed to get quorum config: %v", err)
		return false, err
	}

	if len(aggregatedReport.Verifications) < int(quorumConfig.Threshold) {
		q.logger(ctx).Debugf("Not enough verifications to meet quorum: have %d, need %d", len(aggregatedReport.Verifications), quorumConfig.Threshold)
		return false, nil
	}

	participantIDs := make(map[string]struct{})
	for _, verification := range aggregatedReport.Verifications {
		signers, _, err := q.ValidateSignature(ctx, verification)
		if err != nil {
			q.logger(ctx).Errorw("Failed to validate signature: %v", err)
			continue
		}
		if len(signers) == 0 {
			q.logger(ctx).Warn("No valid signers found. Might be due to a config change")
			continue
		}
		for _, signer := range signers {
			participantIDs[signer.ParticipantID] = struct{}{}
		}
	}

	// Check if we have enough unique participant IDs to meet the quorum
	if len(participantIDs) < int(quorumConfig.Threshold) {
		q.logger(ctx).Debugf("Quorum not met: have %d unique participant IDs, need %d", len(participantIDs), quorumConfig.Threshold)
		return false, nil
	}

	q.logger(ctx).Debugf("Quorum met with %d unique participant IDs", len(participantIDs))
	return true, nil
}

func (q *EVMQuorumValidator) DeriveAggregationKey(ctx context.Context, record *model.CommitVerificationRecord) (model.AggregationKey, error) {
	messageID, err := record.Message.MessageID()
	if err != nil {
		q.logger(ctx).Errorw("Failed to compute message hash", "error", err)
		return "", err
	}

	hash, err := committee.NewSignableHash(messageID, record.BlobData)
	if err != nil {
		q.logger(ctx).Errorw("Failed to produce signed hash", "error", err)
		return "", err
	}
	return hex.EncodeToString(hash[:]), nil
}

// ValidateSignature validates the signature of a commit verification record and returns the signers and the quorum config used.
// It can return multiple signers from the same participant if they have multiple addresses in the config.
func (q *EVMQuorumValidator) ValidateSignature(ctx context.Context, record *model.CommitVerificationRecord) ([]*model.IdentifierSigner, *model.QuorumConfig, error) {
	q.logger(ctx).Debug("Validating signature for report")
	if record.CcvData == nil {
		q.logger(ctx).Error("Missing signature in report")
		return nil, nil, fmt.Errorf("missing signature in report")
	}

	message := record.Message

	messageID, err := message.MessageID()
	if err != nil {
		q.logger(ctx).Errorw("Failed to compute message hash", "error", err)
		return nil, nil, err
	}

	hash, err := committee.NewSignableHash(messageID, record.BlobData)
	if err != nil {
		q.logger(ctx).Errorw("Failed to produce signed hash", "error", err)
		return nil, nil, err
	}

	rs, ss, err := protocol.DecodeSignatures(record.CcvData)
	if err != nil {
		q.logger(ctx).Errorw("Failed to decode signatures", "error", err)
		return nil, nil, err
	}

	if len(rs) != len(ss) {
		q.logger(ctx).Error("Mismatched signature lengths")
		return nil, nil, fmt.Errorf("invalid signature format")
	}

	committeeName, quorumConfig, err := q.getQuorumConfig(record.Message.SourceChainSelector, record.Message.DestChainSelector, record.SourceVerifierAddress)
	if err != nil {
		q.logger(ctx).Errorf("Failed to get quorum config: %v", err)
		return nil, nil, err
	}
	identifiedSigners := make([]*model.IdentifierSigner, 0, len(rs))
	for i := range rs {
		for vValue := byte(0); vValue <= 1; vValue++ {
			combined := append(rs[i][:], ss[i][:]...)
			combined = append(combined, vValue)
			address, err := q.ecrecover(combined, hash[:])
			if err != nil {
				q.logger(ctx).Tracef("Failed to recover address from signature", "error", err)
				continue
			}
			q.logger(ctx).Tracef("Recovered address: %s", address.Hex())

			for _, signer := range quorumConfig.Signers {
				for _, s := range signer.Addresses {
					signerAddress := common.HexToAddress(s)

					if signerAddress == address {
						q.logger(ctx).Infow("Recovered address from signature", "address", address.Hex())
						identifiedSigners = append(identifiedSigners, &model.IdentifierSigner{
							Signer:      signer,
							Address:     signerAddress.Bytes(),
							SignatureR:  rs[i],
							SignatureS:  ss[i],
							CommitteeID: committeeName,
						})
					}
				}
			}
		}
	}

	if len(identifiedSigners) == 0 {
		q.logger(ctx).Debug("No valid signers found for the provided signature")
		return nil, nil, fmt.Errorf("no valid signers found for the provided signature")
	}

	q.logger(ctx).Debugf("Successfully validated signatures with %d signers", len(identifiedSigners))
	return identifiedSigners, quorumConfig, nil
}

func (q *EVMQuorumValidator) ecrecover(signature, msgHash []byte) (common.Address, error) {
	pubKeyBytes, err := crypto.Ecrecover(msgHash, signature)
	if err != nil {
		return common.Address{}, err
	}
	// Skip the 0x04 prefix and hash the uncompressed public key
	hash := protocol.Keccak256(pubKeyBytes[1:])
	// Take the last 20 bytes
	return common.BytesToAddress(hash[12:]), nil
}

func (q *EVMQuorumValidator) getQuorumConfig(sourceSelector, destSelector protocol.ChainSelector, sourceVerifierAddress []byte) (model.CommitteeID, *model.QuorumConfig, error) {
	for name, committee := range q.Committees {
		sourceAddress, ok := committee.SourceVerifierAddresses[fmt.Sprintf("%d", uint64(sourceSelector))]
		if !ok {
			continue
		}
		if !bytes.Equal(common.HexToAddress(sourceAddress).Bytes(), sourceVerifierAddress) {
			continue
		}

		if config, exists := committee.GetQuorumConfig(uint64(destSelector)); exists {
			return name, config, nil
		}
	}
	return "", nil, fmt.Errorf("quorum config not found for chain selector: %d and address: %s", destSelector, common.BytesToAddress(sourceVerifierAddress).Hex())
}

func NewQuorumValidator(config *model.AggregatorConfig, l logger.SugaredLogger) *EVMQuorumValidator {
	return &EVMQuorumValidator{
		Committees: config.Committees,
		l:          l,
	}
}
