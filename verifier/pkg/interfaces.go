package verifier

import (
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	vtypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

// Type aliases - the actual definitions live in verifier/pkg/vtypes.
// These aliases preserve backward compatibility for all existing consumers of verifier/pkg.
type (
	MessageSigner          = vtypes.MessageSigner
	VerificationResult     = vtypes.VerificationResult
	Verifier               = vtypes.Verifier
	VerifierDecorator      = vtypes.VerifierDecorator
	MessageLatencyTracker  = vtypes.MessageLatencyTracker
	Monitoring             = vtypes.Monitoring
	Tracing                = tracing.Tracing
	MetricLabeler          = vtypes.MetricLabeler
	FinalityCheckerMetrics = vtypes.FinalityCheckerMetrics
)
