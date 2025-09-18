package quorum

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/common/pkg/signature"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
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

	_, quorumConfig, err := q.getQuorumConfig(types.ChainSelector(aggregatedReport.GetSourceChainSelector()), types.ChainSelector(aggregatedReport.GetDestinationSelector()), aggregatedReport.GetSourceVerifierAddress())
	if err != nil {
		q.logger(ctx).Errorf("Failed to get quorum config: %v", err)
		return false, err
	}

	participantIDs := make(map[string]struct{})
	for _, verification := range aggregatedReport.Verifications {
		signers, _, err := q.ValidateSignature(ctx, &verification.MessageWithCCVNodeData)
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

// ValidateSignature validates the signature of a commit verification record and returns the signers and the quorum config used.
// It can return multiple signers from the same participant if they have multiple addresses in the config.
func (q *EVMQuorumValidator) ValidateSignature(ctx context.Context, report *aggregator.MessageWithCCVNodeData) ([]*model.IdentifierSigner, *model.QuorumConfig, error) {
	q.logger(ctx).Debug("Validating signature for report")
	ccvData := report.CcvData
	if ccvData == nil {
		q.logger(ctx).Error("Missing signature in report")
		return nil, nil, fmt.Errorf("missing signature in report")
	}

	reportMessage := report.Message

	message := model.MapProtoMessageToProtocolMessage(reportMessage)

	messageHash, err := message.MessageID()
	if err != nil {
		q.logger(ctx).Errorw("Failed to compute message hash", "error", err)
		return nil, nil, err
	}

	ccvArgs, rs, ss, err := signature.DecodeSignaturesABI(ccvData)
	if err != nil {
		q.logger(ctx).Errorw("Failed to decode signatures", "error", err)
		return nil, nil, err
	}

	signatureHash := q.calculateSignatureHash(messageHash, ccvArgs)

	if len(rs) != len(ss) {
		q.logger(ctx).Error("Mismatched signature lengths")
		return nil, nil, fmt.Errorf("invalid signature format")
	}

	committeeName, quorumConfig, err := q.getQuorumConfig(types.ChainSelector(report.Message.SourceChainSelector), types.ChainSelector(report.Message.DestChainSelector), report.SourceVerifierAddress)
	if err != nil {
		q.logger(ctx).Errorf("Failed to get quorum config: %v", err)
		return nil, nil, err
	}
	identifiedSigners := make([]*model.IdentifierSigner, 0, len(rs))
	for i := range rs {
		for vValue := byte(0); vValue <= 1; vValue++ {
			combined := append(rs[i][:], ss[i][:]...)
			combined = append(combined, vValue)
			address, err := q.ecrecover(combined, signatureHash[:])
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
							Signer:     signer,
							Address:    signerAddress.Bytes(),
							SignatureR: rs[i],
							SignatureS: ss[i],
							Committee:  committeeName,
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

func keccak256(data []byte) [32]byte {
	hash := crypto.Keccak256(data)
	var result [32]byte
	copy(result[:], hash)
	return result
}

func (q *EVMQuorumValidator) calculateSignatureHash(messageHash types.Bytes32, ccvArgs []byte) [32]byte {
	var buf bytes.Buffer
	buf.Write(messageHash[:])
	buf.Write(ccvArgs)
	return keccak256(buf.Bytes())
}

func (q *EVMQuorumValidator) ecrecover(signature, msgHash []byte) (common.Address, error) {
	pubKeyBytes, err := crypto.Ecrecover(msgHash, signature)
	if err != nil {
		return common.Address{}, err
	}
	// Skip the 0x04 prefix and hash the uncompressed public key
	hash := crypto.Keccak256(pubKeyBytes[1:])
	// Take the last 20 bytes
	return common.BytesToAddress(hash[12:]), nil
}

func (q *EVMQuorumValidator) getQuorumConfig(sourceSelector, destSelector types.ChainSelector, sourceVerifierAddress []byte) (string, *model.QuorumConfig, error) {
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
