package probe

import (
	"sync"
	"time"
)

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64
	burst   float64
	lastGC  time.Time
	ttl     time.Duration
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewLimiter(ratePerMinute, burst float64) *Limiter {
	return &Limiter{
		buckets: make(map[string]*bucket),
		rate:    ratePerMinute / 60.0,
		burst:   burst,
		ttl:     10 * time.Minute,
	}
}

func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastGC) > time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.last) > l.ttl {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}

	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}

	elapsed := now.Sub(b.last).Seconds()
	b.tokens = minFloat(l.burst, b.tokens+elapsed*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
