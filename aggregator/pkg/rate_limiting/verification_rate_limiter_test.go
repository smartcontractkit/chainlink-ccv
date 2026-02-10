package rate_limiting

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

const (
	signerA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	signerB = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	signerC = "0xcccccccccccccccccccccccccccccccccccccccc"
)

type tryAcquireStep struct {
	signer            string
	seq               uint64
	wantSuccess       bool
	wantMedian        float64
	wantMAD           float64
	assertStats       bool
	wantErrorContains string
	waitBefore        time.Duration
}

func getStats(
	ctx context.Context,
	limiter *VerificationRateLimiter,
	committee *model.Committee,
	sourceSelector uint64,
) (median, mad float64, err error) {
	quorumConfig, ok := committee.GetQuorumConfig(sourceSelector)
	if !ok || quorumConfig == nil {
		return 0, 0, fmt.Errorf("no quorum config for source selector %d", sourceSelector)
	}
	keys, err := limiter.computeAllKeysForCommitteePerSourceSelector(sourceSelector, quorumConfig)
	if err != nil {
		return 0, 0, err
	}
	rates, err := limiter.getAllRates(ctx, keys)
	if err != nil {
		return 0, 0, err
	}
	median = limiter.computeMedian(rates)
	mad = limiter.computeMAD(rates, median)
	return median, mad, nil
}

func validCommittee() *model.Committee {
	return &model.Committee{
		QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{
			"1": {
				SourceVerifierAddress: "0x1234567890abcdef1234567890abcdef12345678",
				Signers: []model.Signer{
					{Address: signerA},
					{Address: signerB},
					{Address: signerC},
				},
				Threshold: 1,
			},
		},
		DestinationVerifiers: map[model.DestinationSelector]string{
			"2": "0xabcdef1234567890abcdef1234567890abcdef12",
		},
	}
}

func makeRecord(
	t *testing.T,
	signerAddr string,
	sourceSelector uint64,
	sequenceNumber uint64,
) *model.CommitVerificationRecord {
	t.Helper()

	onRamp, _ := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
	offRamp, _ := protocol.NewUnknownAddressFromHex("0x2222222222222222222222222222222222222222")
	sender, _ := protocol.NewUnknownAddressFromHex("0x3333333333333333333333333333333333333333")
	receiver, _ := protocol.NewUnknownAddressFromHex("0x4444444444444444444444444444444444444444")

	msg, err := protocol.NewMessage(
		protocol.ChainSelector(sourceSelector),
		protocol.ChainSelector(2),
		protocol.SequenceNumber(sequenceNumber),
		onRamp, offRamp,
		1, 300_000, 300_000,
		protocol.Bytes32{},
		sender, receiver,
		nil, nil,
		nil,
	)
	require.NoError(t, err)

	messageID, err := msg.MessageID()
	require.NoError(t, err)

	identifier, err := protocol.NewByteSliceFromHex(signerAddr)
	require.NoError(t, err)

	return &model.CommitVerificationRecord{
		MessageID:        messageID[:],
		Message:          msg,
		SignerIdentifier: &model.SignerIdentifier{Identifier: identifier},
	}
}

func createRedisContainer(t *testing.T) string {
	t.Helper()

	redisReq := testcontainers.ContainerRequest{
		Image:        "redis:7-alpine",
		WaitingFor:   wait.ForLog("Ready to accept connections"),
		ExposedPorts: []string{"6379/tcp"},
	}

	redisContainer, err := testcontainers.GenericContainer(t.Context(), testcontainers.GenericContainerRequest{
		ContainerRequest: redisReq,
		Started:          true,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = redisContainer.Terminate(context.Background())
	})

	host, err := redisContainer.Host(t.Context())
	require.NoError(t, err)

	port, err := redisContainer.MappedPort(t.Context(), nat.Port("6379"))
	require.NoError(t, err)

	return fmt.Sprintf("%s:%s", host, port.Port())
}

func newLimiter(t *testing.T, host string, cfg model.VerificationRateLimiterConfig) *VerificationRateLimiter {
	t.Helper()
	if cfg.Redis == nil {
		cfg.Redis = &model.VerificationRateLimiterRedisConfig{Address: host}
	} else {
		cfg.Redis.Address = host
	}
	limiter, err := NewVerificationRateLimiter(cfg)
	require.NoError(t, err)
	return limiter
}

func TestVerificationRateLimiter_TryAcquire(t *testing.T) {
	tests := []struct {
		name           string
		config         model.VerificationRateLimiterConfig
		committee      func() *model.Committee
		sourceSelector uint64
		steps          []tryAcquireStep
	}{
		{
			name: "rejects when rate exceeds median plus K times MAD after two signers",
			config: model.VerificationRateLimiterConfig{
				Redis:                         &model.VerificationRateLimiterRedisConfig{},
				Enabled:                       true,
				K:                             1.0,
				MinCommitteeSize:              1,
				MinRateBeforeComparingWithMAD: 2.0,
				RateWindow:                    1 * time.Second,
			},
			committee:      validCommittee,
			sourceSelector: 1,
			steps: []tryAcquireStep{
				{signerA, 1, true, 0, 0, true, "", 0},
				{signerB, 2, true, 1, 0, true, "", 0},
				{signerA, 4, true, 1, 1, true, "", 0},
				{signerA, 5, false, 1, 1, true, "verification rate is not within bounds", 0}, // Rate is 3 which is greater than K (1) * MAD (1) + Median (1) = 2
			},
		},
		{
			name: "succeeds when rate below minRateBeforeComparingWithMAD",
			config: model.VerificationRateLimiterConfig{
				Redis:                         &model.VerificationRateLimiterRedisConfig{},
				Enabled:                       true,
				K:                             1.0,
				MinCommitteeSize:              1,
				MinRateBeforeComparingWithMAD: 4.0,
				RateWindow:                    1 * time.Second,
			},
			committee:      validCommittee,
			sourceSelector: 1,
			steps: []tryAcquireStep{
				{signerA, 1, true, 0, 0, true, "", 0},
				{signerB, 2, true, 1, 0, true, "", 0},
				{signerA, 4, true, 1, 1, true, "", 0},
				{signerA, 5, true, 1, 1, true, "", 0}, // Rate is 3 which is greater than K (1) * MAD (1) + Median (1) = 2 but below minRateBeforeComparingWithMAD (4.0)
			},
		},
		{
			name: "rejects when signer A far above others with high minRateBeforeComparingWithMAD",
			config: model.VerificationRateLimiterConfig{
				Redis:                         &model.VerificationRateLimiterRedisConfig{},
				Enabled:                       true,
				K:                             1.0,
				MinCommitteeSize:              1,
				MinRateBeforeComparingWithMAD: 5.0,
				RateWindow:                    1 * time.Second,
			},
			committee:      validCommittee,
			sourceSelector: 1,
			steps: []tryAcquireStep{
				{signerA, 1, true, 0, 0, true, "", 0},
				{signerA, 2, true, 0, 0, true, "", 0},
				{signerA, 3, true, 0, 0, true, "", 0},
				{signerA, 4, true, 0, 0, true, "", 0},
				{signerB, 5, true, 1, 1, true, "", 0},
				{signerC, 6, true, 1, 0, true, "", 0},
				{signerA, 7, false, 1, 0, true, "verification rate is not within bounds", 0},
			},
		},
		{
			name: "succeeds when committee size below minimum",
			config: model.VerificationRateLimiterConfig{
				Redis:                         &model.VerificationRateLimiterRedisConfig{},
				Enabled:                       true,
				K:                             1.0,
				MinCommitteeSize:              10,
				MinRateBeforeComparingWithMAD: 2.0,
				RateWindow:                    1 * time.Second,
			},
			committee:      validCommittee,
			sourceSelector: 1,
			steps: []tryAcquireStep{
				{signerA, 1, true, 0, 0, false, "", 0}, // Don't assert stats because rate limit is not enabled for committee size below minimum
				{signerB, 2, true, 1, 0, false, "", 0},
				{signerA, 4, true, 1, 1, false, "", 0},
				{signerA, 5, true, 1, 1, false, "", 0}, // Rate is 3 which is greater than K (1) * MAD (1) + Median (1) = 2
			},
		},
		{
			name: "succeeds when median below minRateBeforeComparingWithMAD",
			config: model.VerificationRateLimiterConfig{
				Redis:                         &model.VerificationRateLimiterRedisConfig{},
				Enabled:                       true,
				K:                             1.0,
				MinCommitteeSize:              1,
				MinRateBeforeComparingWithMAD: 100.0,
				RateWindow:                    1 * time.Second,
			},
			committee:      validCommittee,
			sourceSelector: 1,
			steps: []tryAcquireStep{
				{signerA, 1, true, 0, 0, true, "", 0},
				{signerA, 2, true, 0, 0, true, "", 0},
				{signerA, 3, true, 0, 0, true, "", 0},
				{signerA, 4, true, 0, 0, true, "", 0},
				{signerB, 5, true, 1, 1, true, "", 0},
				{signerC, 6, true, 1, 0, true, "", 0},
				{signerA, 7, true, 1, 0, true, "", 0},
			},
		},
		{
			name: "succeeds after rate window expires and old entries are removed",
			config: model.VerificationRateLimiterConfig{
				Redis:                         &model.VerificationRateLimiterRedisConfig{},
				Enabled:                       true,
				K:                             1.0,
				MinCommitteeSize:              1,
				MinRateBeforeComparingWithMAD: 2.0,
				RateWindow:                    100 * time.Millisecond,
			},
			committee:      validCommittee,
			sourceSelector: 1,
			steps: []tryAcquireStep{
				{signerA, 1, true, 0, 0, true, "", 0},
				{signerA, 2, false, 0, 0, true, "verification rate is not within bounds", 0},
				{signerA, 3, true, 0, 0, true, "", 2 * time.Second}, // Rate window expires and old entries are removed
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := createRedisContainer(t)
			limiter := newLimiter(t, host, tt.config)
			committee := tt.committee()
			ctx := context.Background()

			quorumConfig, ok := committee.GetQuorumConfig(tt.sourceSelector)
			if !ok || quorumConfig == nil {
				t.Fatalf("no quorum config for source selector %d", tt.sourceSelector)
			}

			for i, step := range tt.steps {
				if step.waitBefore > 0 {
					time.Sleep(step.waitBefore)
				}
				record := makeRecord(t, step.signer, tt.sourceSelector, step.seq)
				err := limiter.TryAcquire(ctx, record, quorumConfig)

				if step.wantSuccess {
					require.NoError(t, err, "step %d: signer %s seq %d", i+1, step.signer, step.seq)
				} else {
					require.Error(t, err, "step %d: signer %s seq %d", i+1, step.signer, step.seq)
					if step.wantErrorContains != "" {
						require.Contains(t, err.Error(), step.wantErrorContains, "step %d", i+1)
					}
				}

				if step.assertStats {
					median, mad, statsErr := getStats(ctx, limiter, committee, tt.sourceSelector)
					require.NoError(t, statsErr, "step %d: getStats", i+1)
					require.Equal(t, step.wantMedian, median, "step %d: median", i+1)
					require.Equal(t, step.wantMAD, mad, "step %d: MAD", i+1)
				}
			}
		})
	}
}
