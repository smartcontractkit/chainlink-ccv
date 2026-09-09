package taskverifier

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/policy"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type detailsRecordingVerifier struct {
	tasks []verifier.VerificationTask
}

func (v *detailsRecordingVerifier) VerifyMessages(_ context.Context, tasks []verifier.VerificationTask) []verifier.VerificationResult {
	v.tasks = tasks
	return nil
}

func TestProcessor_ReadsMessageDetailsBeforeVerification(t *testing.T) {
	for _, persisted := range []bool{false, true} {
		name := "legacy task"
		if persisted {
			name = "reader details already persisted"
		}
		t.Run(name, func(t *testing.T) {
			task := verifier.VerificationTask{
				MessageID: protocol.Bytes32{0x01}.String(),
				Message: protocol.Message{
					Sender: protocol.UnknownAddress{0x02}, Finality: protocol.FinalityWaitForSafe,
				},
				FeeToken:     protocol.UnknownAddress{0x03},
				ReceiptBlobs: []protocol.ReceiptWithBlob{{FeeTokenAmount: big.NewInt(4)}},
			}
			if persisted {
				// Distinct values prove persisted reader metadata is not recomputed on retry.
				task.MessageDetails = &protocol.MessageDetails{
					Sender:   protocol.UnknownAddress{0x05},
					Finality: protocol.FinalityRequirement{Mode: protocol.FinalityModeBlockDepth, BlockDepth: 6},
				}
			}
			stored, err := json.Marshal(task)
			require.NoError(t, err)
			var payload verifier.VerificationTask
			require.NoError(t, json.Unmarshal(stored, &payload))
			spy := &detailsRecordingVerifier{}
			processor := &Processor{
				lggr: logger.Test(t), verifierID: "v", verifier: spy,
				monitoring: monitoring.NewFakeVerifierMonitoring(),
			}
			require.NoError(t, processor.processJobs(t.Context(), []jobqueue.Job[verifier.VerificationTask]{{ID: "job", Payload: payload}}))
			require.Len(t, spy.tasks, 1)
			got := spy.tasks[0]
			require.NotNil(t, got.MessageDetails)
			assert.Equal(t, payload.Message, got.Message)
			if persisted {
				assert.Same(t, payload.MessageDetails, got.MessageDetails)
			} else {
				assert.Nil(t, payload.MessageDetails, "reading must not modify the queued payload")
				assert.Len(t, got.MessageDetails.Sender, 32)
				assert.Equal(t, byte(2), got.MessageDetails.Sender[31])
				assert.Equal(t, big.NewInt(4), got.MessageDetails.FeeTokenAmount)
				assert.True(t, got.MessageDetails.Finality.Safe)
			}
			_, err = policy.NewEvaluateRequest("v", &got)
			require.NoError(t, err, "policy must receive a complete reader view after queue read")
		})
	}
}
