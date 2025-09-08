package model

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
)

// Signer represents a participant in the commit verification process.
type Signer struct {
	ParticipantID string   `toml:"participantID"`
	Addresses     []string `toml:"addresses"`
}

type IdentifierSigner struct {
	Signer
	Address    []byte
	SignatureR [32]byte
	SignatureS [32]byte
}

// Committee represents a group of signers participating in the commit verification process.
type Committee struct {
	// QuorumConfigs stores a QuorumConfig for each chain selector
	// there is a commit verifier for.
	// The aggregator uses this to verify signatures from each chain's
	// commit verifier set.
	QuorumConfigs map[uint64]*QuorumConfig `toml:"quorumConfigs"`
}

func FindSignersFromSelectorAndOfframp(committees map[string]*Committee, chainSelector uint64, offrampAddress []byte) []Signer {
	for _, committee := range committees {
		quorumConfig, exists := committee.QuorumConfigs[chainSelector]
		if !exists {
			continue
		}

		if !bytes.Equal(quorumConfig.OfframpAddress, offrampAddress) {
			continue
		}
		return quorumConfig.Signers
	}
	return nil
}

// QuorumConfig represents the configuration for a quorum of signers.
type QuorumConfig struct {
	OfframpAddress []byte   `toml:"offrampAddress"`
	Signers        []Signer `toml:"signers"`
	F              uint8    `toml:"f"`
}

func (q *QuorumConfig) GetParticipantFromAddress(address []byte) *Signer {
	for _, signer := range q.Signers {
		for _, addr := range signer.Addresses {
			// TODO: Do not use go ethereum common package here
			addrBytes := common.HexToAddress(addr).Bytes()
			if bytes.Equal(addrBytes, address) {
				return &signer
			}
		}
	}
	return nil
}

// StorageConfig represents the configuration for the storage backend.
type StorageConfig struct {
	StorageType string `toml:"type"`
}

// ServerConfig represents the configuration for the server.
type ServerConfig struct {
	Address string `toml:"address"`
}

// AggregatorConfig is the root configuration for the aggregator.
type AggregatorConfig struct {
	Committees        map[string]*Committee `toml:"committees"`
	Server            ServerConfig          `toml:"server"`
	Storage           StorageConfig         `toml:"storage"`
	DisableValidation bool                  `toml:"disableValidation"`
	StubMode          bool                  `toml:"stubQuorumValidation"`
}

// Validate validates the aggregator configuration for integrity and correctness.
func (c *AggregatorConfig) Validate() error {
	// TODO: Add Validate() method to AggregatorConfig to ensure configuration integrity
	// Should validate:
	// - No duplicate signers within the same QuorumConfig
	// - StorageType is supported (memory, etc.)
	// - AggregationStrategy is supported (stub, etc.)
	// - F value follows N = 3F + 1 rule, so F = (N-1) // 3
	// - Committee names are valid
	// - QuorumConfig chain selectors are valid
	// - Server address format is correct
	// - Offramp address cannot be shared across same chain on different committees
	return nil
}
