package rate_limiting

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	tryAcquireTimeout = 5 * time.Second
	redisPingTimeout  = 3 * time.Second
)

type VerificationRateLimiter struct {
	redisClient                   *redis.Client
	k                             float64
	minCommitteeSize              uint64
	minRateBeforeComparingWithMAD float64
	rateWindow                    time.Duration
	logger                        logger.SugaredLogger
}

/*
VerificationRateLimiter is a rate limiter for commit verification records.
It uses Redis sorted sets to store the verification records and remove old ones.
The count of verifications record is compared with other verifier in the committee.
We use a MAD score to compare the count of verifications record with other verifier in the committee.
If the rate median rate is higher than 5 we enable the rate limiting and compare it's rate with the MAD score.
*/
func NewVerificationRateLimiter(config model.VerificationRateLimiterConfig, logger logger.SugaredLogger) (*VerificationRateLimiter, error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     config.Redis.Address,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), redisPingTimeout)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis at %s: %w", config.Redis.Address, err)
	}

	return &VerificationRateLimiter{
		redisClient:                   redisClient,
		k:                             config.K,
		minCommitteeSize:              config.MinCommitteeSize,
		minRateBeforeComparingWithMAD: config.MinRateBeforeComparingWithMAD,
		rateWindow:                    config.RateWindow,
		logger:                        logger,
	}, nil
}

func (v *VerificationRateLimiter) TryAcquire(ctx context.Context, verificationRecord *model.CommitVerificationRecord, quorumConfig *model.QuorumConfig) (model.TryAcquireResult, error) {
	ctx, cancel := context.WithTimeout(ctx, tryAcquireTimeout)
	defer cancel()
	if quorumConfig == nil {
		return model.TryAcquireResult{}, fmt.Errorf("quorum config is nil")
	}
	keys := v.computeAllKeysForCommitteePerSourceSelector(uint64(verificationRecord.Message.SourceChainSelector), quorumConfig)
	v.logger.Debugf("computed all keys for committee per source selector: %v", keys)

	if uint64(len(keys)) < v.minCommitteeSize {
		v.logger.Debugf("committee size is less than min committee size: %d < %d on source selector: %d, rate limiting is disabled", len(keys), v.minCommitteeSize, verificationRecord.Message.SourceChainSelector)
		return model.TryAcquireResult{IsReached: false, IsEnabled: false}, nil
	}

	pipe := v.redisClient.Pipeline()

	if err := v.removeOldKeys(ctx, keys, pipe); err != nil {
		return model.TryAcquireResult{}, fmt.Errorf("failed to remove old keys from rate limiter: %w", err)
	}

	if err := v.add(ctx, verificationRecord, pipe); err != nil {
		return model.TryAcquireResult{}, fmt.Errorf("failed to add verification record to rate limiter: %w", err)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return model.TryAcquireResult{}, fmt.Errorf("failed to execute pipeline: %w", err)
	}

	rates, err := v.getAllRates(ctx, keys)
	if err != nil {
		return model.TryAcquireResult{}, fmt.Errorf("failed to get all rates from rate limiter: %w", err)
	}

	currentRateKey := v.computeKeyForSignerPerSourceSelector(verificationRecord.SignerIdentifier.Identifier.String(), uint64(verificationRecord.Message.SourceChainSelector))
	v.logger.Debugf("current rate key: %s", currentRateKey)

	rate, rateFoundInCommittee := rates[currentRateKey]

	median := v.computeMedian(rates)
	mad := v.computeMAD(rates, median)
	upperBound := median + v.k*mad

	if rate < v.minRateBeforeComparingWithMAD {
		v.logger.Debugf("rate is less than min rate: %f < %f, allowing verification", rate, v.minRateBeforeComparingWithMAD)
		return model.TryAcquireResult{
			Median: median, MAD: mad, K: v.k, UpperBound: upperBound, CurrentRate: rate,
			IsReached: false, IsEnabled: false,
		}, nil
	}

	result := model.TryAcquireResult{
		Median: median, MAD: mad, K: v.k, UpperBound: upperBound, CurrentRate: rate,
		IsEnabled: true,
	}

	if !rateFoundInCommittee {
		v.logger.Errorf("rate key %s not found in committee keys: %v, rate limiting the request", currentRateKey, keys)
		result.IsReached = true
	}

	if !v.isWithinBounds(mad, median, v.k, rate) {
		result.IsReached = true
	}
	return result, nil
}

func (v *VerificationRateLimiter) computeAllKeysForCommitteePerSourceSelector(sourceSelector uint64, quorumConfig *model.QuorumConfig) map[string]struct{} {
	keys := make(map[string]struct{}, len(quorumConfig.Signers))
	for _, signer := range quorumConfig.Signers {
		keys[v.computeKeyForSignerPerSourceSelector(signer.Address, sourceSelector)] = struct{}{}
	}
	return keys
}

func (v *VerificationRateLimiter) computeKeyForSignerPerSourceSelector(signer string, sourceSelector uint64) string {
	return fmt.Sprintf("cvr:rate:%s:%d", signer, sourceSelector)
}

func (v *VerificationRateLimiter) add(ctx context.Context, verificationRecord *model.CommitVerificationRecord, pipe redis.Pipeliner) error {
	signer := verificationRecord.SignerIdentifier.Identifier
	sourceSelector := verificationRecord.Message.SourceChainSelector

	key := v.computeKeyForSignerPerSourceSelector(signer.String(), uint64(sourceSelector))
	zAddCmd := pipe.ZAdd(ctx, key, redis.Z{
		Score:  float64(time.Now().Unix()),
		Member: verificationRecord.MessageID,
	})
	if err := zAddCmd.Err(); err != nil {
		return fmt.Errorf("failed to add verification record to rate limiter: %w", err)
	}

	return nil
}

func (v *VerificationRateLimiter) removeOldKeys(ctx context.Context, keys map[string]struct{}, pipe redis.Pipeliner) error {
	earliestTimestamp := time.Now().Add(-1 * v.rateWindow).Unix()
	for key := range keys {
		zRemCmd := pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", earliestTimestamp-1))
		if err := zRemCmd.Err(); err != nil {
			return fmt.Errorf("failed to remove old keys from rate limiter: %w", err)
		}
	}
	return nil
}

func (v *VerificationRateLimiter) getAllRates(ctx context.Context, keys map[string]struct{}) (map[string]float64, error) {
	pipe := v.redisClient.Pipeline()
	rates := make(map[string]float64)
	cmds := make(map[string]*redis.IntCmd)
	for key := range keys {
		cmds[key] = pipe.ZCard(ctx, key)
	}
	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to execute pipeline: %w", err)
	}

	for key, cmd := range cmds {
		rate, err := cmd.Result()
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

	ctx, cancel := context.WithTimeout(context.Background(), redisPingTimeout)
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
