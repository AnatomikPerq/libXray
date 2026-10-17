package core

import (
	"sync"
	"time"
)

// tokenBucket is a simple thread-safe token bucket rate limiter. Tokens
// represent bytes. Mirrors the server's implementation so that in
// "realistic" mode the tunnel is throttled symmetrically in both
// directions - an unthrottled upload next to a throttled download would
// itself be an oddity for anyone watching traffic shape.
type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	refillRate float64 // bytes per second
	lastRefill time.Time
}

func newTokenBucket(refillRatePerSec, capacityBytes float64) *tokenBucket {
	if capacityBytes < refillRatePerSec {
		capacityBytes = refillRatePerSec
	}
	return &tokenBucket{
		tokens:     capacityBytes,
		capacity:   capacityBytes,
		refillRate: refillRatePerSec,
		lastRefill: time.Now(),
	}
}

// newThrottleBucket builds a tokenBucket sized according to cfg, or returns
// nil in fast mode (no throttling - matches previous behavior).
func newThrottleBucket(cfg Config) *tokenBucket {
	if cfg.Mode != ModeRealistic {
		return nil
	}
	rate := float64(cfg.RealisticBandwidthKB) * 1024
	burst := float64(cfg.RealisticBurstKB) * 1024
	return newTokenBucket(rate, burst)
}

// WaitN blocks until n bytes worth of tokens are available, then consumes
// them. Safe to call on a nil bucket (fast mode) - it's then a no-op.
func (tb *tokenBucket) WaitN(n int) {
	if tb == nil || n <= 0 {
		return
	}
	need := float64(n)
	for {
		tb.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(tb.lastRefill).Seconds()
		tb.lastRefill = now

		tb.tokens += elapsed * tb.refillRate
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}

		if tb.tokens >= need {
			tb.tokens -= need
			tb.mu.Unlock()
			return
		}

		deficit := need - tb.tokens
		waitSec := deficit / tb.refillRate
		tb.mu.Unlock()

		time.Sleep(time.Duration(waitSec * float64(time.Second)))
	}
}
