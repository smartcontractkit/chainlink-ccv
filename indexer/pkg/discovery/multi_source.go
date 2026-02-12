package discovery

import (
	"context"
	"errors"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	// seenMessageIDTTL is how long we remember a messageID for deduplication.
	seenMessageIDTTL = 24 * time.Hour
	// seenCacheMaxSize is the maximum number of messageIDs to keep in the seen cache (LRU eviction when full).
	seenCacheMaxSize = 1_000_000
)

var _ common.MessageDiscovery = (*MultiSourceMessageDiscovery)(nil)

// MultiSourceMessageDiscovery merges multiple MessageDiscovery sources and deduplicates
// by messageID (first discovery wins). It implements common.MessageDiscovery.
type MultiSourceMessageDiscovery struct {
	logger    logger.Logger
	sources   []common.MessageDiscovery
	messageCh chan common.VerifierResultWithMetadata
	seen      *lru.LRU[protocol.Bytes32, struct{}]
	wg        sync.WaitGroup
	cancel    context.CancelFunc
}

// MultiSourceOption configures MultiSourceMessageDiscovery.
type MultiSourceOption func(*MultiSourceMessageDiscovery)

// NewMultiSourceMessageDiscovery builds a MultiSourceMessageDiscovery from the given options.
func NewMultiSourceMessageDiscovery(lggr logger.Logger, sources []common.MessageDiscovery) (common.MessageDiscovery, error) {
	m := &MultiSourceMessageDiscovery{
		logger:    lggr,
		sources:   sources,
		messageCh: make(chan common.VerifierResultWithMetadata),
		seen:      lru.NewLRU[protocol.Bytes32, struct{}](seenCacheMaxSize, nil, seenMessageIDTTL),
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *MultiSourceMessageDiscovery) validate() error {
	if len(m.sources) < 1 {
		return errors.New("at least one discovery source is required")
	}
	if m.logger == nil {
		return errors.New("logger is required")
	}
	return nil
}

// Start starts all source discoveries and returns a single channel that emits deduplicated
// VerifierResultWithMetadata (first discovery per messageID wins).
func (m *MultiSourceMessageDiscovery) Start(ctx context.Context) chan common.VerifierResultWithMetadata {
	childCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	chans := make([]<-chan common.VerifierResultWithMetadata, 0, len(m.sources))
	for _, src := range m.sources {
		chans = append(chans, src.Start(childCtx))
	}

	m.wg.Add(1)
	go m.merge(childCtx, chans)
	m.logger.Info("MultiSourceMessageDiscovery started")
	return m.messageCh
}

// merge reads from all source channels and forwards to m.messageCh, deduplicating by messageID.
func (m *MultiSourceMessageDiscovery) merge(ctx context.Context, chans []<-chan common.VerifierResultWithMetadata) {
	defer m.wg.Done()
	defer func() {
		// Do not close messageCh to match AggregatorMessageDiscovery behavior (channel stays open).
	}()

	// Build select cases dynamically: we need to receive from N channels and ctx.Done().
	// Use a single select with reflect.Select or run N goroutines that forward to a single channel.
	// Simpler: spawn one goroutine per source that forwards to a shared channel, then one goroutine
	// that reads from that shared channel and dedupes. That way we have one place that checks "seen".
	type recv struct {
		msg common.VerifierResultWithMetadata
	}
	recvCh := make(chan recv, len(chans)*2)
	for _, ch := range chans {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case msg, ok := <-ch:
					if !ok {
						m.logger.Warnw("one source message discovery channel closed", "source", ch)
						return
					}
					select {
					case <-ctx.Done():
						return
					case recvCh <- recv{msg: msg}:
					}
				}
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("MultiSourceMessageDiscovery merge stopped due to context cancellation")
			return
		case r := <-recvCh:
			if _, found := m.seen.Get(r.msg.VerifierResult.MessageID); found {
				m.logger.Infow("messageID already discovered from different source, skipping", "messageID", r.msg.VerifierResult.MessageID)
				continue
			}
			m.seen.Add(r.msg.VerifierResult.MessageID, struct{}{})
			select {
			case <-ctx.Done():
				return
			case m.messageCh <- r.msg:
			}
		}
	}
}

// Close stops all source discoveries and the merge goroutine.
func (m *MultiSourceMessageDiscovery) Close() error {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	for _, src := range m.sources {
		_ = src.Close()
	}
	m.logger.Info("MultiSourceMessageDiscovery stopped")
	return nil
}

// Replay is a no-op for multi-source discovery (each source could implement Replay separately if needed).
func (m *MultiSourceMessageDiscovery) Replay(ctx context.Context, start, end uint64) error {
	return nil
}
