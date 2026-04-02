package common

import (
	"bytes"
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// MessageDiscovery defines the interface for discovering messages from a trusted discovery source.
type MessageDiscovery interface {
	// Start MessageDiscovery and listen to new CCIP Messages.
	Start(ctx context.Context) chan VerifierResultWithMetadata
	// Close gracefully stops MessageDiscovery.
	Close() error
	// Replay messages since a given sequence number until an inclusive end value.
	Replay(ctx context.Context, start, end uint64) error
}

// VerifierNameResolver resolves verifier addresses to human-readable names.
type VerifierNameResolver interface {
	// GetVerifierNameFromAddress returns the configured name for a verifier address.
	GetVerifierNameFromAddress(addr protocol.UnknownAddress) string
}

// IsDiscoveryOnly checks whether the verification data is a discovery-only
// marker (not valid on-chain) by inspecting the 4-byte version prefix of CCVData.
func IsDiscoveryOnly(vr protocol.VerifierResult) bool {
	if len(vr.CCVData) <= protocol.MessageDiscoveryVersionLength {
		return true
	}
	version := vr.CCVData[:protocol.MessageDiscoveryVersionLength]
	return bytes.Equal(version, protocol.MessageDiscoveryVersion)
}

// ConvertDiscoveryResponses converts raw aggregator query responses into typed
// metadata structs. It returns:
//   - messages: one MessageWithMetadata per response (always included).
//   - persistable: verifications that are NOT discovery-only (suitable for DB persistence).
//   - all: every verification regardless of discovery-only status (used for channel emission in the live path).
func ConvertDiscoveryResponses(
	responses []protocol.QueryResponse,
	ingestionTimestamp time.Time,
	resolver VerifierNameResolver,
) (
	messages []MessageWithMetadata,
	persistable []VerifierResultWithMetadata,
	all []VerifierResultWithMetadata,
) {
	messages = make([]MessageWithMetadata, 0, len(responses))
	persistable = make([]VerifierResultWithMetadata, 0, len(responses))
	all = make([]VerifierResultWithMetadata, 0, len(responses))

	for _, resp := range responses {
		messages = append(messages, MessageWithMetadata{
			Message: resp.Data.Message,
			Metadata: MessageMetadata{
				Status:             MessageProcessing,
				IngestionTimestamp: ingestionTimestamp,
			},
		})

		var verifierName string
		if resolver != nil {
			verifierName = resolver.GetVerifierNameFromAddress(resp.Data.VerifierSourceAddress)
		}

		vrm := VerifierResultWithMetadata{
			VerifierResult: resp.Data,
			Metadata: VerifierResultMetadata{
				IngestionTimestamp:   ingestionTimestamp,
				AttestationTimestamp: resp.Data.Timestamp,
				VerifierName:         verifierName,
			},
		}
		all = append(all, vrm)

		if !IsDiscoveryOnly(resp.Data) {
			persistable = append(persistable, vrm)
		}
	}

	return messages, persistable, all
}
