package e2e

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/mock_receiver_v2"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/proxy"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_1_0/operations/cctp_verifier"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	apiv1 "github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/v1"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const (
	// maxShortVisibilityWindowSec is the largest indexer window this test accepts (standard.short-timeout.profile).
	maxShortVisibilityWindowSec = 120
	timeoutReplayOverallTimeout = 5 * time.Minute
)

// TestE2ESmoke_TimeoutReplayTokenTransfer sends a USDC transfer while the token verifier is down,
// waits for the indexer to mark the message TIMEOUT, starts the token verifier again,
// and recovers the message with `indexer-replay messages --ids`.
func TestE2ESmoke_TimeoutReplayTokenTransfer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)
	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	require.GreaterOrEqual(t, len(in.Indexer), 1, "expected at least one indexer")
	require.NotNil(t, in.Indexer[0].IndexerConfig, "indexer config must be set")
	window := in.Indexer[0].IndexerConfig.Scheduler.VerificationVisibilityWindow
	if window <= 0 || window > maxShortVisibilityWindowSec {
		t.Skipf("indexer VerificationVisibilityWindow is %ds; run with standard.short-timeout.profile", window)
	}
	require.GreaterOrEqual(t, len(in.TokenVerifier), 1, "expected at least one token verifier")
	require.NotNil(t, in.TokenVerifier[0].Out, "token verifier must have output")
	tokenVerifierContainer := strings.TrimPrefix(in.TokenVerifier[0].Out.ContainerName, "/")
	require.NotEmpty(t, tokenVerifierContainer)

	lib, err := ccv.NewLibFromCCVEnv(l, smokeTestConfig, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains for this test in the environment")
	chainMap, err := lib.ChainsMap(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	db, indexerContainer := openIndexerDB(t, in)
	indexerMonitor := SetupIndexerMonitor(t, ctx, lib)

	srcSel, destSel := chains[0].Details.ChainSelector, chains[1].Details.ChainSelector
	srcChain := chainMap[srcSel]
	// The committee verifier is also required, so the indexer discovers the message through the aggregator.
	receiver := getContractAddress(t, in, destSel,
		datastore.ContractType(mock_receiver_v2.ContractType), mock_receiver_v2.Deploy.Version(),
		common.CCTPSecondaryReceiverQualifier, "")

	stopContainer(t, l, tokenVerifierContainer)

	msgID := sendUSDCTransfer(t, ctx, in, srcChain, srcSel, destSel, receiver)
	msgIDHex := "0x" + hex.EncodeToString(msgID[:])
	l.Info().Str("MessageID", msgIDHex).Msg("USDC transfer sent with the token verifier down")

	timeoutWait := time.Duration(window)*time.Second + 2*time.Minute
	require.NoError(t, waitForIndexerStatus(ctx, db, msgIDHex, "TIMEOUT", timeoutWait),
		"message %s must reach TIMEOUT while the token verifier is down", msgIDHex)

	restartContainer(t, l, tokenVerifierContainer)
	require.NoError(t, waitForTokenVerifierResult(ctx, in.TokenVerifier[0].Out.ExternalHTTPURL, msgID, timeoutReplayOverallTimeout),
		"token verifier must serve the result for message %s after the restart", msgIDHex)

	// The indexer does not retry a TIMEOUT message by itself, so only the replay can recover it.
	status, err := getIndexerStatus(ctx, db, msgIDHex)
	require.NoError(t, err)
	require.Equal(t, "TIMEOUT", status, "message %s must stay TIMEOUT until the replay", msgIDHex)

	out, err := execInContainer(ctx, indexerContainer, replayCLIArgs("messages", "--ids", msgIDHex)...)
	require.NoError(t, err, "replay of message %s must succeed; output: %s", msgIDHex, out)
	require.NoError(t, waitForIndexerStatus(ctx, db, msgIDHex, "SUCCESS", time.Duration(window)*time.Second+time.Minute),
		"message %s must reach SUCCESS after the replay", msgIDHex)

	res, err := indexerMonitor.GetVerificationsForMessageID(ctx, msgID)
	require.NoError(t, err)
	require.Len(t, res.Results, 2, "expected the committee and the CCTP verifier results for message %s", msgIDHex)
}

// sendUSDCTransfer sends a USDC transfer, registers its CCTP attestation, and returns the message ID.
func sendUSDCTransfer(
	t *testing.T,
	ctx context.Context,
	in *ccv.Cfg,
	srcChain cciptestinterfaces.CCIP17,
	srcSel, destSel uint64,
	receiver protocol.UnknownAddress,
) protocol.Bytes32 {
	t.Helper()
	seqNo, err := srcChain.GetExpectedNextSequenceNumber(ctx, destSel)
	require.NoError(t, err)

	_, err = srcChain.SendMessage(ctx, destSel,
		cciptestinterfaces.MessageFields{
			Receiver: receiver,
			TokenAmount: cciptestinterfaces.TokenAmount{
				Amount:       big.NewInt(10),
				TokenAddress: getUSDCTokenAddress(t, in, srcSel),
			},
		},
		cciptestinterfaces.MessageOptions{
			FinalityConfig:    protocol.NewFinality().WithBlockDepth(1),
			ExecutionGasLimit: 200_000,
			Executor: getContractAddress(t, in, srcSel, datastore.ContractType(sequences.ExecutorProxyType),
				proxy.Deploy.Version(), common.DefaultExecutorQualifier, "executor"),
		},
		3,
	)
	require.NoError(t, err)

	sentEvt, err := srcChain.ConfirmSendOnSource(ctx, destSel, cciptestinterfaces.MessageEventKey{SeqNum: seqNo}, defaultSentTimeout)
	require.NoError(t, err)

	cctpMessageSender := getContractAddress(t, in, srcSel,
		datastore.ContractType(cctp_verifier.ContractType), cctp_verifier.Deploy.Version(), "", "")
	registerCCTPAttestation(t, in.Fake.Out.ExternalHTTPURL, sentEvt.MessageID, cctpMessageSender, receiver, "complete",
		srcSel, destSel, getUSDCTokenAddress(t, in, srcSel), getCCTPTokenMessengerAddress(t, in, destSel))
	return sentEvt.MessageID
}

func getIndexerStatus(ctx context.Context, db *sql.DB, msgIDHex string) (string, error) {
	var status string
	err := db.QueryRowContext(ctx, "SELECT status FROM indexer.messages WHERE message_id = $1", msgIDHex).Scan(&status)
	return status, err
}

// waitForIndexerStatus polls the indexer DB until the message has the wanted status.
func waitForIndexerStatus(ctx context.Context, db *sql.DB, msgIDHex, want string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	last := ""
	for time.Now().Before(deadline) {
		if status, err := getIndexerStatus(ctx, db, msgIDHex); err == nil {
			if status == want {
				return nil
			}
			last = status
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("message %s has status %q, want %q after %s", msgIDHex, last, want, timeout)
}

// waitForTokenVerifierResult polls the token verifier REST API until it serves a result for the message.
func waitForTokenVerifierResult(ctx context.Context, baseURL string, msgID protocol.Bytes32, timeout time.Duration) error {
	url := fmt.Sprintf("%s/v1/verifications?messageID=%s", baseURL, msgID.String())
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = fetchTokenVerifierResult(ctx, url, msgID)
		if lastErr == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("no token verifier result after %s: %w", timeout, lastErr)
}

func fetchTokenVerifierResult(ctx context.Context, url string, msgID protocol.Bytes32) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	var body apiv1.VerifierResultsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}
	results, err := body.ToVerifierResults()
	if err != nil {
		return err
	}
	if _, ok := results[msgID]; !ok {
		return fmt.Errorf("no result for message %s", msgID.String())
	}
	return nil
}
