// Package ratelimit provides per-client-IP request throttling: a token-bucket
// rate cap plus a concurrent-in-flight-requests cap. Together these are the
// HTTP-layer flood mitigation described in docs/NETWORK_HARDENING.md; they do
// not replace OS-level SYN-flood protection.
package ratelimit

import (
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type entry struct {
	limiter    *rate.Limiter
	inFlight   int
	lastSeenAt time.Time
}

type Limiter struct {
	mu                 sync.Mutex
	entries            map[string]*entry
	requestsPerSecond  rate.Limit
	burst              int
	maxConcurrentPerIP int
	idleTimeout        time.Duration
	stopCleanup        chan struct{}
}

// New creates a Limiter. maxConcurrentPerIP <= 0 disables the concurrency cap.
func New(requestsPerSecond float64, burst int, maxConcurrentPerIP int, idleTimeout time.Duration) *Limiter {
	if idleTimeout <= 0 {
		idleTimeout = 10 * time.Minute
	}
	l := &Limiter{
		entries:            make(map[string]*entry),
		requestsPerSecond:  rate.Limit(requestsPerSecond),
		burst:              burst,
		maxConcurrentPerIP: maxConcurrentPerIP,
		idleTimeout:        idleTimeout,
		stopCleanup:        make(chan struct{}),
	}
	go l.cleanupLoop()
	return l
}

func (l *Limiter) get(ip string) *entry {
	e, ok := l.entries[ip]
	if !ok {
		e = &entry{limiter: rate.NewLimiter(l.requestsPerSecond, l.burst)}
		l.entries[ip] = e
	}
	e.lastSeenAt = time.Now()
	return e
}

// Allow reports whether a request from ip may proceed under the rate cap.
// It does not account for concurrency; call Begin/End around the request body
// for that.
func (l *Limiter) Allow(ip net.IP) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.get(ip.String())
	return e.limiter.Allow()
}

// Begin reserves an in-flight slot for ip, returning false if the
// concurrency cap is already reached (in which case no slot is held; the
// caller must not call End).
func (l *Limiter) Begin(ip net.IP) bool {
	if l.maxConcurrentPerIP <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.get(ip.String())
	if e.inFlight >= l.maxConcurrentPerIP {
		return false
	}
	e.inFlight++
	return true
}

// End releases the in-flight slot reserved by a successful Begin.
func (l *Limiter) End(ip net.IP) {
	if l.maxConcurrentPerIP <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.entries[ip.String()]; ok && e.inFlight > 0 {
		e.inFlight--
	}
}

func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(l.idleTimeout)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			cutoff := time.Now().Add(-l.idleTimeout)
			for ip, e := range l.entries {
				if e.inFlight == 0 && e.lastSeenAt.Before(cutoff) {
					delete(l.entries, ip)
				}
			}
			l.mu.Unlock()
		case <-l.stopCleanup:
			return
		}
	}
}

func (l *Limiter) Close() {
	close(l.stopCleanup)
}
