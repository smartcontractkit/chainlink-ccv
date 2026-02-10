package rate_limiting

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

type VerificationRateLimiter struct {
	redisClient                   *redis.Client
	k                             float64
	minCommitteeSize              uint64
	minRateBeforeComparingWithMAD float64
	rateWindow                    time.Duration
}

/*
VerificationRateLimiter is a rate limiter for commit verification records.
It uses Redis sorted sets to store the verification records and remove old ones.
The count of verifications record is compared with other verifier in the committee.
We use a MAD score to compare the count of verifications record with other verifier in the committee.
If the rate median rate is higher than 5 we enable the rate limiting and compare it's rate with the MAD score.
*/
func NewVerificationRateLimiter(config model.VerificationRateLimiterConfig) (*VerificationRateLimiter, error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     config.Redis.Address,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis at %s: %w", config.Redis.Address, err)
	}

	return &VerificationRateLimiter{
		redisClient:                   redisClient,
		k:                             config.K,
		minCommitteeSize:              config.MinCommitteeSize,
		minRateBeforeComparingWithMAD: config.MinRateBeforeComparingWithMAD,
		rateWindow:                    config.RateWindow,
	}, nil
}

func (v *VerificationRateLimiter) TryAcquire(ctx context.Context, verificationRecord *model.CommitVerificationRecord, quorumConfig *model.QuorumConfig) error {
	if quorumConfig == nil {
		return fmt.Errorf("quorum config is nil")
	}
	keys, err := v.computeAllKeysForCommitteePerSourceSelector(uint64(verificationRecord.Message.SourceChainSelector), quorumConfig)
	if err != nil {
		return fmt.Errorf("failed to compute all keys for committee per source selector: %w", err)
	}

	if uint64(len(keys)) < v.minCommitteeSize {
		return nil // we don't need to rate limit if the committee size is less than the minimum committee size
	}

	if err := v.removeOldKeys(ctx, keys); err != nil {
		return fmt.Errorf("failed to remove old keys from rate limiter: %w", err)
	}

	if err := v.add(ctx, verificationRecord); err != nil {
		return fmt.Errorf("failed to add verification record to rate limiter: %w", err)
	}

	rates, err := v.getAllRates(ctx, keys)
	if err != nil {
		return fmt.Errorf("failed to get all rates from rate limiter: %w", err)
	}
	rate := rates[v.computeKeyForSignerPerSourceSelector(verificationRecord.SignerIdentifier.Identifier.String(), uint64(verificationRecord.Message.SourceChainSelector))]
	if rate < v.minRateBeforeComparingWithMAD {
		return nil // we don't need to rate limit if the rate is less than the minimum rate
	}

	median := v.computeMedian(rates)
	mad := v.computeMAD(rates, median)

	if !v.isWithinBounds(mad, median, v.k, rate) {
		return fmt.Errorf("verification rate is not within bounds. rate: %f, median: %f, mad: %f, k: %f", rate, median, mad, v.k)
	}

	return nil
}

func (v *VerificationRateLimiter) computeAllKeysForCommitteePerSourceSelector(sourceSelector uint64, quorumConfig *model.QuorumConfig) ([]string, error) {
	keys := make([]string, 0, len(quorumConfig.Signers))
	for _, signer := range quorumConfig.Signers {
		keys = append(keys, v.computeKeyForSignerPerSourceSelector(signer.Address, sourceSelector))
	}
	return keys, nil
}

func (v *VerificationRateLimiter) computeKeyForSignerPerSourceSelector(signer string, sourceSelector uint64) string {
	return fmt.Sprintf("cvr:rate:%s:%d", signer, sourceSelector)
}

func (v *VerificationRateLimiter) add(ctx context.Context, verificationRecord *model.CommitVerificationRecord) error {
	signer := verificationRecord.SignerIdentifier.Identifier
	sourceSelector := verificationRecord.Message.SourceChainSelector

	key := v.computeKeyForSignerPerSourceSelector(signer.String(), uint64(sourceSelector))
	zAddCmd := v.redisClient.ZAdd(ctx, key, redis.Z{
		Score:  float64(time.Now().Unix()),
		Member: verificationRecord.MessageID,
	})
	if err := zAddCmd.Err(); err != nil {
		return fmt.Errorf("failed to add verification record to rate limiter: %w", err)
	}
	return nil
}

func (v *VerificationRateLimiter) removeOldKeys(ctx context.Context, keys []string) error {
	earliestTimestamp := time.Now().Add(-1 * v.rateWindow).Unix()
	for _, key := range keys {
		zRemCmd := v.redisClient.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", earliestTimestamp-1))
		if err := zRemCmd.Err(); err != nil {
			return fmt.Errorf("failed to remove old keys from rate limiter: %w", err)
		}
	}
	return nil
}

func (v *VerificationRateLimiter) getAllRates(ctx context.Context, keys []string) (map[string]float64, error) {
	rates := make(map[string]float64)
	for _, key := range keys {
		rate, err := v.redisClient.ZCard(ctx, key).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to get rate for key: %w", err)
		}
		rates[key] = float64(rate)
	}
	return rates, nil
}

func (v *VerificationRateLimiter) isWithinBounds(mad, median, k, rate float64) bool {
	upperBound := median + k*mad
	return rate <= upperBound
}

// computeMAD computes the MAD score for a given rates by comparing it to the median.
func (v *VerificationRateLimiter) computeMAD(rates map[string]float64, median float64) float64 {
	deviations := make([]float64, 0, len(rates))
	for _, rate := range rates {
		deviations = append(deviations, math.Abs(rate-median))
	}
	sort.Float64s(deviations)
	mad := deviations[len(deviations)/2]
	return mad
}

func (v *VerificationRateLimiter) computeMedian(rates map[string]float64) float64 {
	ratesList := make([]float64, 0, len(rates))
	for _, rate := range rates {
		ratesList = append(ratesList, rate)
	}
	sort.Float64s(ratesList)
	return ratesList[len(ratesList)/2]
}

func (v *VerificationRateLimiter) Ready() error {
	if v.redisClient == nil {
		// rate limiter not initialized"
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := v.redisClient.Ping(ctx).Err()
	if err != nil {
		return fmt.Errorf("rate limiter redis client unavailable: %v", err)
	}

	return nil
}

func (v *VerificationRateLimiter) HealthReport() map[string]error {
	return map[string]error{
		v.Name(): v.Ready(),
	}
}

func (v *VerificationRateLimiter) Name() string {
	return "verification_rate_limiter"
}
