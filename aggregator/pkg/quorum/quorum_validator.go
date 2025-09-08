package quorum

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

type EVMQuorumValidator struct {
	Committees map[string]*model.Committee
	// Add any necessary fields here
}

func (q *EVMQuorumValidator) CheckQuorum(aggregatedReport *model.CommitAggregatedReport) (bool, error) {
	if len(aggregatedReport.Verifications) == 0 {
		return false, nil
	}

	quorumConfig, err := q.getQuorumConfig(types.ChainSelector(aggregatedReport.GetDestinationSelector()), aggregatedReport.GetOffRampAddress())
	if err != nil {
		return false, err
	}

	participantIDs := make(map[string]struct{})
	for _, verification := range aggregatedReport.Verifications {
		signers, _, err := q.ValidateSignature(&verification.MessageWithCCVNodeData)
		if err != nil {
			continue
		}
		if len(signers) == 0 {
			continue
		}
		for _, signer := range signers {
			participantIDs[signer.ParticipantID] = struct{}{}
		}
	}

	// Check if we have enough unique participant IDs to meet the quorum
	if len(participantIDs) != int(quorumConfig.F)+1 {
		return false, nil
	}

	return true, nil
}

// ValidateSignature validates the signature of a commit verification record and returns the signers and the quorum config used.
// It can return multiple signers from the same participant if they have multiple addresses in the config.
func (q *EVMQuorumValidator) ValidateSignature(report *aggregator.MessageWithCCVNodeData) ([]*model.IdentifierSigner, *model.QuorumConfig, error) {
	signature := report.CcvData
	if signature == nil {
		return nil, nil, fmt.Errorf("missing signature in report")
	}

	reportMessage := report.Message

	message := types.Message{
		Version:              uint8(reportMessage.Version), //nolint:gosec // G115: Protocol-defined conversion
		SourceChainSelector:  types.ChainSelector(reportMessage.SourceChainSelector),
		DestChainSelector:    types.ChainSelector(reportMessage.DestChainSelector),
		SequenceNumber:       types.SeqNum(reportMessage.SequenceNumber),
		OnRampAddressLength:  uint8(reportMessage.OnRampAddressLength), //nolint:gosec // G115: Protocol-defined conversion
		OnRampAddress:        reportMessage.OnRampAddress,
		OffRampAddressLength: uint8(reportMessage.OffRampAddressLength), //nolint:gosec // G115: Protocol-defined conversion
		OffRampAddress:       reportMessage.OffRampAddress,
		Finality:             uint16(reportMessage.Finality),    //nolint:gosec // G115: Protocol-defined conversion
		SenderLength:         uint8(reportMessage.SenderLength), //nolint:gosec // G115: Protocol-defined conversion
		Sender:               reportMessage.Sender,
		ReceiverLength:       uint8(reportMessage.ReceiverLength), //nolint:gosec // G115: Protocol-defined conversion
		Receiver:             reportMessage.Receiver,
		DestBlobLength:       uint16(reportMessage.DestBlobLength), //nolint:gosec // G115: Protocol-defined conversion
		DestBlob:             reportMessage.DestBlob,
		TokenTransferLength:  uint16(reportMessage.TokenTransferLength), //nolint:gosec // G115: Protocol-defined conversion
		TokenTransfer:        reportMessage.TokenTransfer,
		DataLength:           uint16(reportMessage.DataLength), //nolint:gosec // G115: Protocol-defined conversion
		Data:                 reportMessage.Data,
	}

	messageHash, err := message.MessageID()
	if err != nil {
		return nil, nil, err
	}

	blob, err := q.getReceiptBlobForVerifier(report)
	if err != nil {
		return nil, nil, err
	}

	signatureHash, err := q.calculateSignatureHash(messageHash, blob)
	if err != nil {
		return nil, nil, err
	}

	rs, ss, err := model.DecodeSignatures(signature)
	if err != nil {
		return nil, nil, err
	}

	if len(rs) != len(ss) {
		return nil, nil, fmt.Errorf("invalid signature format")
	}

	quorumConfig, err := q.getQuorumConfig(types.ChainSelector(report.Message.DestChainSelector), report.Message.OffRampAddress)
	if err != nil {
		return nil, nil, err
	}
	identifiedSigners := make([]*model.IdentifierSigner, 0, len(rs))
	for i := range rs {
		for vValue := byte(0); vValue <= 1; vValue++ {
			combined := append(rs[i][:], ss[i][:]...)
			combined = append(combined, vValue)
			address, err := q.ecrecover(combined, signatureHash[:])
			if err != nil {
				continue
			}

			for _, signer := range quorumConfig.Signers {
				for _, s := range signer.Addresses {
					signerAddress := common.HexToAddress(s)

					if signerAddress == address {
						identifiedSigners = append(identifiedSigners, &model.IdentifierSigner{
							Signer:     signer,
							Address:    signerAddress.Bytes(),
							SignatureR: rs[i],
							SignatureS: ss[i],
						})
					}
				}
			}
		}
	}

	if len(identifiedSigners) == 0 {
		return nil, nil, fmt.Errorf("no valid signers found for the provided signature")
	}

	return identifiedSigners, quorumConfig, nil
}

func keccak256(data []byte) [32]byte {
	hash := crypto.Keccak256(data)
	var result [32]byte
	copy(result[:], hash)
	return result
}

func (q *EVMQuorumValidator) calculateSignatureHash(messageHash types.Bytes32, verifierBlob []byte) ([32]byte, error) {
	verifierBlobHash := keccak256(verifierBlob)

	// Canonical encoding: simply concatenate the two 32-byte hashes
	var buf bytes.Buffer
	buf.Write(messageHash[:])
	buf.Write(verifierBlobHash[:])

	return keccak256(buf.Bytes()), nil
}

func (q *EVMQuorumValidator) getReceiptBlobForVerifier(report *aggregator.MessageWithCCVNodeData) ([]byte, error) {
	sourceVerifier := report.SourceVerifierAddress
	for _, blob := range report.ReceiptBlobs {
		if bytes.Equal(blob.Issuer, sourceVerifier) {
			return blob.Blob, nil
		}
	}
	return nil, fmt.Errorf("receipt blob not found for verifier: %x", sourceVerifier)
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

func (q *EVMQuorumValidator) getQuorumConfig(chainSelector types.ChainSelector, offrampAddress []byte) (*model.QuorumConfig, error) {
	for _, committee := range q.Committees {
		if config, exists := committee.QuorumConfigs[uint64(chainSelector)]; exists {
			if bytes.Equal(config.OfframpAddress, offrampAddress) {
				return config, nil
			}
		}
	}
	return nil, fmt.Errorf("quorum config not found for chain selector: %d and address: %s", chainSelector, common.BytesToAddress(offrampAddress).Hex())
}

func NewQuorumValidator(config model.AggregatorConfig) *EVMQuorumValidator {
	return &EVMQuorumValidator{
		Committees: config.Committees,
	}
}
