package storageaccess

import (
	lru "github.com/hashicorp/golang-lru/v2"
)

// DefaultAckCacheSize bounds how many (aggregator, message) acks the fan-out writer tracks in
// memory. Acks are normally forgotten as soon as every aggregator confirms a message, so in the
// all-up steady state this stays near empty. The bound matters when one aggregator is down for a
// long time: those messages are acked by the healthy aggregators but never fully confirmed, so
// their entries would otherwise accumulate unbounded until the outage ends.
const DefaultAckCacheSize = 1_000

// ackKey identifies one aggregator's confirmation of one message.
type ackKey struct {
	label string
	msg   string
}

// ackCache is a bounded LRU (least-recently-acked) set of acks backed by
// github.com/hashicorp/golang-lru/v2, which is internally mutex-guarded and evicts the
// least-recently-used entry once it reaches its capacity.
//
// Eviction is safe because aggregator writes are idempotent: dropping an ack merely causes that
// already-acked aggregator to be re-sent the message on its next retry (a no-op on the
// aggregator side) and then re-learn the ack. It trades a little extra re-fanout for a hard
// upper bound on memory.
type ackCache struct {
	lru *lru.Cache[ackKey, struct{}]
}

func newAckCache(capacity int) (*ackCache, error) {
	if capacity <= 0 {
		capacity = DefaultAckCacheSize
	}
	// capacity is positive here, so New cannot fail.
	c, err := lru.New[ackKey, struct{}](capacity)
	if err != nil {
		return nil, err
	}
	return &ackCache{lru: c}, nil
}

// has reports whether the (label, msg) ack is present without touching recency. A nil cache
// (e.g. an uninitialized FanOutWriter) reports no acks, so every item is still attempted.
func (c *ackCache) has(label, msg string) bool {
	if c == nil || c.lru == nil {
		return false
	}
	return c.lru.Contains(ackKey{label: label, msg: msg})
}

// add records an ack for (label, msg), bumping it to the most-recently-used position, evicting
// the least-recently-used entry first if at capacity. A nil cache is a no-op.
func (c *ackCache) add(label, msg string) {
	if c == nil || c.lru == nil {
		return
	}
	c.lru.Add(ackKey{label: label, msg: msg}, struct{}{})
}

// remove drops an ack. A nil cache is a no-op.
func (c *ackCache) remove(label, msg string) {
	if c == nil || c.lru == nil {
		return
	}
	c.lru.Remove(ackKey{label: label, msg: msg})
}

// len returns the number of tracked acks, for introspection and tests.
func (c *ackCache) len() int {
	if c == nil || c.lru == nil {
		return 0
	}
	return c.lru.Len()
}
