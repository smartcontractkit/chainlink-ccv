package load

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/metrics"
)

// VerificationContext holds the minimal dependencies needed by AssertMessagesAsync.
// Callers construct a VerificationContext from whatever test harness they use (EVM, Solana, etc.),
// keeping the verification pipeline chain-agnostic.
type VerificationContext struct {
	Ctx  context.Context
	T    testing.TB
	Impl map[uint64]cciptestinterfaces.CCIP17
}

// AssertMessagesAsync starts a background verification pipeline that reads
// sent messages from the gun's channel and confirms execution on dest chains.
// Returns a closure that blocks until verification completes and returns metrics.
// The caller must call gun.CloseSentChannel() after the load run completes to unblock the pipeline.
func AssertMessagesAsync(vc VerificationContext, gun LoadGun, overallTimeout time.Duration) func() ([]metrics.MessageMetrics, metrics.MessageTotals) {
	var wg sync.WaitGroup
	var totalSent, totalReceived atomic.Int32

	sentMessages := &sync.Map{}
	receivedMessages := &sync.Map{}
	metricsData := &sync.Map{}

	verifyCtx, cancelVerify := context.WithTimeout(vc.Ctx, overallTimeout)

	go func() {
		defer cancelVerify()

		logTimeout := sync.OnceFunc(func() {
			vc.T.Logf("Overall verification timeout reached, stopping new verifications")
		})

		for sentMsg := range gun.SentMessages() {
			// Always record sent messages for accurate totals, even after timeout.
			msgIDHex := "0x" + hex.EncodeToString(sentMsg.MessageID[:])
			totalSent.Add(1)
			sentMessages.Store(sentMsg.SeqNo, msgIDHex)

			select {
			case <-verifyCtx.Done():
				// Log once and keep draining to avoid blocking the gun's producer goroutine.
				logTimeout()
				continue
			default:
			}

			wg.Add(1)
			go func(msg SentMessage) {
				defer wg.Done()

				msgIDHex := "0x" + hex.EncodeToString(msg.MessageID[:])

				if _, ok := vc.Impl[msg.ChainPair.Dest]; !ok {
					vc.T.Logf("No implementation available to verify message %d", msg.SeqNo)
					return
				}

				execEvent, err := vc.Impl[msg.ChainPair.Dest].ConfirmExecOnDest(verifyCtx, msg.ChainPair.Src, cciptestinterfaces.MessageEventKey{SeqNum: msg.SeqNo}, 0)
				if err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						vc.T.Logf("Message %d verification cancelled or timed out", msg.SeqNo)
					} else {
						vc.T.Logf("Failed to get execution event for sequence number %d: %v", msg.SeqNo, err)
					}
					return
				}

				if execEvent.State != cciptestinterfaces.ExecutionStateSuccess {
					vc.T.Logf("Message with sequence number %d was not successfully executed, state: %d", msg.SeqNo, execEvent.State)
					return
				}

				executedTime := time.Now()
				latency := executedTime.Sub(msg.SentTime)

				vc.T.Logf("Message with sequence number %d successfully executed (latency: %v)", msg.SeqNo, latency)

				totalReceived.Add(1)
				receivedMessages.Store(msg.SeqNo, msgIDHex)

				metricsData.Store(msg.SeqNo, metrics.MessageMetrics{
					SeqNo:           msg.SeqNo,
					MessageID:       msgIDHex,
					SourceChain:     msg.ChainPair.Src,
					DestChain:       msg.ChainPair.Dest,
					SentTime:        msg.SentTime,
					ExecutedTime:    executedTime,
					LatencyDuration: latency,
				})
			}(sentMsg)
		}

		vc.T.Logf("All messages sent, waiting for verifications to complete")

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			vc.T.Logf("All verification goroutines completed successfully")
		case <-verifyCtx.Done():
			vc.T.Logf("Verification timeout reached, %d messages may be unverified", totalSent.Load()-totalReceived.Load())
		}
	}()

	return func() ([]metrics.MessageMetrics, metrics.MessageTotals) {
		<-verifyCtx.Done()

		datum := make([]metrics.MessageMetrics, 0, int(totalReceived.Load()))
		metricsData.Range(func(key, value any) bool {
			datum = append(datum, value.(metrics.MessageMetrics))
			return true
		})

		sent := make(map[uint64]string)
		sentMessages.Range(func(key, value any) bool {
			sent[key.(uint64)] = value.(string)
			return true
		})

		received := make(map[uint64]string)
		receivedMessages.Range(func(key, value any) bool {
			received[key.(uint64)] = value.(string)
			return true
		})

		totals := metrics.MessageTotals{
			Sent:             int(totalSent.Load()),
			Received:         int(totalReceived.Load()),
			SentMessages:     sent,
			ReceivedMessages: received,
		}

		notVerified := totals.Sent - totals.Received
		vc.T.Logf("Verification complete - Sent: %d, Received: %d, Not Received: %d",
			totals.Sent, totals.Received, notVerified)

		return datum, totals
	}
}
