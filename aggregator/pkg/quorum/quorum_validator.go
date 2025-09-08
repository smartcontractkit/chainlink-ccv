package quorum

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

type EVMQuorumValidator struct {
	Committees map[string]model.Committee
	// Add any necessary fields here
}

func EncodeSignatures(rs, ss [][32]byte) ([]byte, error) {
	if len(rs) != len(ss) {
		return nil, fmt.Errorf("rs and ss arrays must have the same length")
	}

	var buf bytes.Buffer

	// Encode array length as uint16 (big-endian)
	arrayLen := uint16(len(rs))
	if err := binary.Write(&buf, binary.BigEndian, arrayLen); err != nil {
		return nil, err
	}

	// Encode rs array
	for _, r := range rs {
		buf.Write(r[:])
	}

	// Encode ss array
	for _, s := range ss {
		buf.Write(s[:])
	}

	return buf.Bytes(), nil
}

func DecodeSignatures(data []byte) (rs, ss [][32]byte, err error) {
	if len(data) < 2 {
		return nil, nil, fmt.Errorf("data too short to contain length")
	}

	// Read array length
	arrayLen := binary.BigEndian.Uint16(data[:2])
	expectedLen := 2 + int(arrayLen)*32*2
	if len(data) != expectedLen {
		return nil, nil, fmt.Errorf("invalid data length: expected %d, got %d", expectedLen, len(data))
	}

	rs = make([][32]byte, arrayLen)
	ss = make([][32]byte, arrayLen)

	// Offsets
	offset := 2
	// Decode rs
	for i := 0; i < int(arrayLen); i++ {
		copy(rs[i][:], data[offset:offset+32])
		offset += 32
	}
	// Decode ss
	for i := 0; i < int(arrayLen); i++ {
		copy(ss[i][:], data[offset:offset+32])
		offset += 32
	}

	return rs, ss, nil
}

func (q *EVMQuorumValidator) CheckQuorum(aggregatedReport *model.CommitAggregatedReport) (bool, error) {
	if len(aggregatedReport.Verifications) == 0 {
		return false, nil
	}

	var quorumConfig *model.QuorumConfig

	participantIDs := make(map[string]struct{})
	for _, verification := range aggregatedReport.Verifications {
		if signers, qConfig, err := q.ValidateSignature(verification); err != nil {
			return false, err
		} else if len(signers) == 0 {
			return false, nil
		} else {
			for _, signer := range signers {
				participantIDs[signer.ParticipantID] = struct{}{}
			}
			if quorumConfig == nil {
				quorumConfig = qConfig
			} else if quorumConfig != qConfig {
				// We have many different quorum configs in the same aggregated report. We can't possibly know which one to use.
				return false, fmt.Errorf("signatures correspond to different quorum configurations. This mean that the public keys used to sign the verifications are not all part of the same committee. This can happen if the config changed after receiving the first verifications")
			}
		}
	}

	// Check if we have enough unique participant IDs to meet the quorum
	if len(participantIDs) != int(quorumConfig.F)+1 {
		return false, nil
	}

	return true, nil
}

func (q *EVMQuorumValidator) ValidateSignature(report *model.CommitVerificationRecord) ([]*model.Signer, *model.QuorumConfig, error) {
	signature := report.CcvData
	if signature == nil {
		return nil, nil, fmt.Errorf("missing signature in report")
	}

	reportMessage := report.Message

	message := types.Message{
		Version:              uint8(reportMessage.Version),
		SourceChainSelector:  types.ChainSelector(reportMessage.SourceChainSelector),
		DestChainSelector:    types.ChainSelector(reportMessage.DestChainSelector),
		SequenceNumber:       types.SeqNum(reportMessage.SequenceNumber),
		OnRampAddressLength:  uint8(reportMessage.OnRampAddressLength),
		OnRampAddress:        reportMessage.OnRampAddress,
		OffRampAddressLength: uint8(reportMessage.OffRampAddressLength),
		OffRampAddress:       reportMessage.OffRampAddress,
		Finality:             uint16(reportMessage.Finality),
		SenderLength:         uint8(reportMessage.SenderLength),
		Sender:               reportMessage.Sender,
		ReceiverLength:       uint8(reportMessage.ReceiverLength),
		Receiver:             reportMessage.Receiver,
		DestBlobLength:       uint16(reportMessage.DestBlobLength),
		DestBlob:             reportMessage.DestBlob,
		TokenTransferLength:  uint16(reportMessage.TokenTransferLength),
		TokenTransfer:        reportMessage.TokenTransfer,
		DataLength:           uint16(reportMessage.DataLength),
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

	rs, ss, err := DecodeSignatures(signature)
	if err != nil {
		return nil, nil, err
	}

	if len(rs) != len(ss) {
		return nil, nil, fmt.Errorf("invalid signature format")
	}

	var quorumConfig *model.QuorumConfig
	identifiedSigners := make([]*model.Signer, 0, len(rs))
	for i := range rs {
		for vValue := byte(0); vValue <= 1; vValue++ {
			combined := append(rs[i][:], ss[i][:]...)
			combined = append(combined, vValue)
			address, err := q.ecrecover(combined, signatureHash[:])
			if err != nil {
				continue
			}

			qConfig, err := q.getQuorumConfig(types.ChainSelector(report.Message.DestChainSelector), address)
			if err != nil {
				continue
			}

			if quorumConfig == nil {
				quorumConfig = qConfig
			} else if quorumConfig != qConfig {
				return nil, nil, fmt.Errorf("signatures correspond to different quorum configurations. This mean that the public keys used to sign the verifications are not all part of the same committee. This can happen if the config changed after receiving the first verifications")
			}

			for _, signer := range quorumConfig.Signers {
				for _, s := range signer.Addresses {
					signerAddress := common.HexToAddress(s)

					if signerAddress == address {
						identifiedSigners = append(identifiedSigners, &signer)
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

func (q *EVMQuorumValidator) getReceiptBlobForVerifier(report *model.CommitVerificationRecord) ([]byte, error) {
	sourceVerifier := report.SourceVerifierAddress
	for _, blob := range report.ReceiptBlobs {
		if bytes.Equal(blob.Issuer, sourceVerifier) {
			return blob.Blob, nil
		}
	}
	return nil, fmt.Errorf("receipt blob not found for verifier: %x", sourceVerifier)
}

func (q *EVMQuorumValidator) ecrecover(signature []byte, msgHash []byte) (common.Address, error) {
	pubKeyBytes, err := crypto.Ecrecover(msgHash, signature)
	if err != nil {
		return common.Address{}, err
	}
	// Skip the 0x04 prefix and hash the uncompressed public key
	hash := crypto.Keccak256(pubKeyBytes[1:])
	// Take the last 20 bytes
	return common.BytesToAddress(hash[12:]), nil
}

func (q *EVMQuorumValidator) getQuorumConfig(chainSelector types.ChainSelector, address common.Address) (*model.QuorumConfig, error) {
	for _, committee := range q.Committees {
		if config, exists := committee.QuorumConfigs[uint64(chainSelector)]; exists {
			for _, signer := range config.Signers {
				for _, addr := range signer.Addresses {
					signerAddress := common.HexToAddress(addr)
					if signerAddress == address {
						return config, nil
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("quorum config not found for chain selector: %d and address: %s", chainSelector, address.Hex())
}

func NewQuorumValidator(config model.AggregatorConfig) *EVMQuorumValidator {
	return &EVMQuorumValidator{
		Committees: config.Committees,
	}
}
